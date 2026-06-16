'''
消融实验
'''

import torch
import numpy as np
import os
import gc
from datasets import load_dataset, DatasetDict
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments, EvalPrediction
from transformers import DataCollatorWithPadding
import tqdm
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score
from skmultilearn.model_selection import iterative_train_test_split
from functools import partial
import json
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score, classification_report
from transformers import TrainingArguments, Trainer
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from node2vec import Node2Vec
import sys
import networkx as nx
import csv
from transformers import AutoTokenizer, RobertaTokenizer
torch.cuda.empty_cache()
REMOVED_IDS = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 16, 17, 20, 32, 40, 53, 54, 57, 60, 63, 64, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 86}
TEMPERATURE = 0.05
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PRETRAINED_MODEL_PATH = '/workspace/models/cpp-chinese-roberta-wwm-ext-transfer/checkpoint-1395'
SAVE_PATH = '/workspace/models/roberta-multilabel-classifier-d2n-82-9575-05-30-g-ablation-h'

class TeeLogger:

    def __init__(self, log_file, mode='a'):
        self.terminal = sys.stdout
        self.log = open(log_file, mode)

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()

    def isatty(self):
        return hasattr(self.terminal, 'isatty') and self.terminal.isatty()

def build_label_relation_matrix_node2vec(child_to_parent_map: dict, num_labels: int, dimensions=32, walk_length=10, num_walks=100, p=1.0, q=0.5) -> np.ndarray:
    print('正在使用 Node2Vec 构建标签关系矩阵 H...')
    G = nx.Graph()
    G.add_nodes_from([str(i) for i in range(num_labels)])
    for child, parent in child_to_parent_map.items():
        if 0 <= child < num_labels and 0 <= parent < num_labels:
            G.add_edge(str(parent), str(child))
    node2vec = Node2Vec(G, dimensions=dimensions, walk_length=walk_length, num_walks=num_walks, p=p, q=q, workers=4, quiet=True)
    model = node2vec.fit(window=5, min_count=1, batch_words=4)
    embeddings = np.array([model.wv[str(i)] for i in range(num_labels)])
    embeddings_normalized = embeddings / (np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-08)
    H = np.dot(embeddings_normalized, embeddings_normalized.T)
    H = (H + 1) / 2
    print('基于 Node2Vec 的标签关系矩阵 H 构建完成。')
    return H

def find_best_thresholds_per_label_optimized(y_prob: np.ndarray, y_true: np.ndarray) -> np.ndarray:
    num_samples, num_labels = y_true.shape
    thresholds = np.arange(0.1, 0.9, 0.05)
    y_true_bool = y_true.astype(bool)
    y_prob_expanded = np.expand_dims(y_prob, axis=2)
    thresholds_expanded = np.expand_dims(thresholds, axis=(0, 1))
    predictions_tensor = y_prob_expanded >= thresholds_expanded
    y_true_expanded = np.expand_dims(y_true_bool, axis=2)
    true_positives = np.sum(predictions_tensor & y_true_expanded, axis=0)
    false_positives = np.sum(predictions_tensor & ~y_true_expanded, axis=0)
    total_positives_per_label = np.sum(y_true_bool, axis=0)
    total_positives_expanded = np.expand_dims(total_positives_per_label, axis=1)
    false_negatives = total_positives_expanded - true_positives
    denominator = 2 * true_positives + false_positives + false_negatives
    f1_scores = 2 * true_positives / (denominator + 1e-08)
    best_threshold_indices = np.argmax(f1_scores, axis=1)
    best_thresholds = thresholds[best_threshold_indices]
    best_thresholds[total_positives_per_label == 0] = 0.5
    del y_prob_expanded, thresholds_expanded, predictions_tensor, y_true_expanded
    gc.collect()
    return best_thresholds

def apply_per_label_thresholds(probs, thresholds):
    return (probs >= thresholds).astype(int)

def compute_metrics_for_trainer(p: EvalPrediction):
    preds = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
    labels = p.label_ids
    preds_tensor_cpu = torch.from_numpy(preds).cpu()
    sigmoid = torch.nn.Sigmoid()
    probs_tensor_cpu = sigmoid(preds_tensor_cpu)
    probs = probs_tensor_cpu.numpy()
    best_thresholds_vector = find_best_thresholds_per_label_optimized(probs, labels)
    y_pred_final = apply_per_label_thresholds(probs, best_thresholds_vector)
    y_true_final = labels
    f1_micro = f1_score(y_true_final, y_pred_final, average='micro', zero_division=0)
    f1_macro = f1_score(y_true_final, y_pred_final, average='macro', zero_division=0)
    f1_weighted = f1_score(y_true_final, y_pred_final, average='weighted', zero_division=0)
    accuracy = accuracy_score(y_true_final, y_pred_final)
    metrics = {'accuracy': accuracy, 'f1_micro': f1_micro, 'f1_macro': f1_macro, 'f1_weighted': f1_weighted, 'threshold_mean': np.mean(best_thresholds_vector), 'threshold_std': np.std(best_thresholds_vector)}
    return metrics

class MultiLabelSupervisedContrastiveLoss(nn.Module):

    def __init__(self, temperature=0.07, label_relation_matrix=None, negative_weight=0.1):
        super().__init__()
        self.temperature = temperature
        self.H = label_relation_matrix
        self.negative_weight = negative_weight

    def forward(self, embeddings, labels):
        embeddings = F.normalize(embeddings, p=2, dim=1)
        similarity_matrix = torch.matmul(embeddings, embeddings.T)
        similarity_matrix = torch.clamp(similarity_matrix, min=-15.0, max=15.0)
        if self.H is not None:
            if self.H.device != labels.device:
                self.H = self.H.to(labels.device)
            hierarchical_similarity = torch.matmul(torch.matmul(labels.float(), self.H), labels.float().T)
            positive_weights = torch.log1p(hierarchical_similarity)
        else:
            shared_labels_count = torch.matmul(labels.float(), labels.float().T)
            positive_weights = torch.log1p(shared_labels_count)
        mask_no_self = torch.eye(labels.shape[0], device=labels.device).bool()
        positive_weights.masked_fill_(mask_no_self, 0)
        shared_labels_count = torch.matmul(labels.float(), labels.float().T)
        negative_mask = shared_labels_count == 0
        negative_similarities = similarity_matrix.masked_select(negative_mask)
        loss_neg = negative_similarities.mean() if negative_similarities.numel() > 0 else 0.0
        similarity_matrix_no_self = similarity_matrix.masked_fill(mask_no_self, -9000000000000000.0)
        logits = similarity_matrix_no_self / self.temperature
        log_prob = logits - torch.logsumexp(logits, dim=1, keepdim=True)
        mean_log_prob_pos = (positive_weights * log_prob).sum(1) / (positive_weights.sum(1) + 1e-08)
        loss_pos = -mean_log_prob_pos.mean()
        final_scl_loss = loss_pos + self.negative_weight * loss_neg
        return final_scl_loss
from transformers import Trainer
from torch.nn import BCEWithLogitsLoss

def build_ancestor_map(child_to_parent_map):
    ancestor_map = {}
    if not child_to_parent_map:
        return ancestor_map
    for child_id, parent_id in child_to_parent_map.items():
        ancestors = []
        current = parent_id
        while current is not None:
            ancestors.append(current)
            current = child_to_parent_map.get(current)
        if ancestors:
            ancestor_map[child_id] = ancestors
    return ancestor_map

class HybridLossTrainer(Trainer):

    def __init__(self, *args, pos_weight=None, label_relation_matrix=None, temperature=0.05, alpha_large_class=0.95, alpha_small_class=0.75, class_size_threshold=30, y_train_counts=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.pos_weight = pos_weight
        self.scl_loss_fn = MultiLabelSupervisedContrastiveLoss(temperature=temperature, label_relation_matrix=label_relation_matrix)
        if y_train_counts is None:
            raise ValueError('HybridLossTrainer 需要 y_train_counts 参数来进行类别感知加权！')
        print('\n--- HybridLossTrainer: 正在构建类别感知的 alpha 权重张量 ---')
        alpha_tensor = torch.full((self.model.config.num_labels,), alpha_small_class, device=self.args.device)
        large_class_mask = torch.from_numpy(y_train_counts > class_size_threshold).to(self.args.device)
        alpha_tensor[large_class_mask] = alpha_large_class
        self.alpha_tensor = alpha_tensor.view(1, -1)
        num_large_classes = large_class_mask.sum().item()
        print(f'Alpha 张量构建完成。大类阈值: >{class_size_threshold}个样本。')
        print(f'大类数量: {num_large_classes}, 使用 alpha = {alpha_large_class}')
        print(f'小类数量: {self.model.config.num_labels - num_large_classes}, 使用 alpha = {alpha_small_class}')

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop('labels')
        if self.model.training:
            outputs = model(**inputs, output_hidden_states=True)
            logits = outputs.get('logits')
            cls_loss_fct = BCEWithLogitsLoss(pos_weight=self.pos_weight, reduction='none')
            per_item_loss_cls = cls_loss_fct(logits.view(-1, self.model.config.num_labels), labels.float().view(-1, self.model.config.num_labels))
            weighted_per_item_loss_cls = self.alpha_tensor * per_item_loss_cls
            loss_cls = weighted_per_item_loss_cls.mean()
            last_hidden_state = outputs.hidden_states[-1]
            attention_mask = inputs['attention_mask']
            mask_expanded = attention_mask.unsqueeze(-1).expand(last_hidden_state.size()).float()
            sum_embeddings = torch.sum(last_hidden_state * mask_expanded, 1)
            sum_mask = torch.clamp(mask_expanded.sum(1), min=1e-09)
            embeddings = sum_embeddings / sum_mask
            loss_scl = self.scl_loss_fn(embeddings, labels)
            batch_label_presence = (labels.sum(dim=0) > 0).float()
            alpha_vec = self.alpha_tensor.squeeze(0)
            den = batch_label_presence.sum().clamp(min=1.0)
            beta_scl = ((1.0 - alpha_vec) * batch_label_presence).sum() / den
            loss = loss_cls + beta_scl * loss_scl
        else:
            outputs = model(**inputs, output_hidden_states=False)
            logits = outputs.get('logits')
            loss_fct = BCEWithLogitsLoss(pos_weight=self.pos_weight)
            loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.float().view(-1, self.model.config.num_labels))
        return (loss, outputs) if return_outputs else loss

class LabelManager:

    def __init__(self, csv_path):
        self.csv_path = csv_path
        self._load_all_labels()
        self.reset()
        self.y_train_counts = None

    def _load_all_labels(self):
        self.all_labels_info = []
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)
            for i, row in enumerate(reader):
                full_id_str = row[0].strip()
                parts = full_id_str.split('.')
                parent_id = '.'.join(parts[:-1]) if len(parts) > 1 else None
                self.all_labels_info.append({'original_index': i, 'id_str': full_id_str, 'name': row[1].strip(), 'parent_id_str': parent_id})
        self.original_num_labels = len(self.all_labels_info)

    def reset(self):
        self.setup_with_removed_ids(removed_ids=set())

    def setup_with_removed_ids(self, removed_ids: set):
        print(f'\n--- LabelManager: 正在使用移除ID列表 {removed_ids} 重新设置 ---')
        self.removed_ids = removed_ids
        self.retained_labels_info = [info for info in self.all_labels_info if info['original_index'] not in self.removed_ids]
        self.label_remapping = {info['original_index']: new_id for new_id, info in enumerate(self.retained_labels_info)}
        self.id2label = {new_id: info['name'] for new_id, info in enumerate(self.retained_labels_info)}
        self.label2id = {v: k for k, v in self.id2label.items()}
        self.num_labels = len(self.retained_labels_info)
        print(f'标签重映射完成: 原始标签数: {self.original_num_labels}, 新标签数: {self.num_labels}')
        retained_id_strs = {info['id_str'] for info in self.retained_labels_info}
        self.child_to_parent_map = {}
        for info in self.retained_labels_info:
            if info['parent_id_str'] in retained_id_strs:
                parent_info = next((p for p in self.all_labels_info if p['id_str'] == info['parent_id_str']))
                new_child_id = self.label_remapping[info['original_index']]
                new_parent_id = self.label_remapping[parent_info['original_index']]
                self.child_to_parent_map[new_child_id] = new_parent_id
        self.ancestor_map = build_ancestor_map(self.child_to_parent_map)
        print('层次关系祖先图构建完成。')

    def calculate_ic_and_counts_from_dataset(self, tokenized_train_dataset):
        print('--- LabelManager: 正在计算标签计数、概率和信息内容 (IC) ---')
        y_train = np.array([item['labels'] for item in tokenized_train_dataset])
        num_samples, num_labels_in_data = y_train.shape
        if num_labels_in_data != self.num_labels:
            raise ValueError(f'数据集中的标签数量({num_labels_in_data})与LabelManager中的数量({self.num_labels})不匹配！')
        self.y_train_counts = y_train.sum(axis=0)
        self.label_probabilities = (self.y_train_counts + 1) / (num_samples + 2)
        self.ic_values = -np.log(self.label_probabilities)
        self.ic_map = {i: self.ic_values[i] for i in range(self.num_labels)}
        print('标签计数和信息内容 (IC) 计算完成。')

def build_label_relation_matrix(child_to_parent_map: dict, num_labels: int) -> np.ndarray:
    print('正在构建标签层级关系图...')
    G = nx.Graph()
    all_nodes = set(range(num_labels))
    G.add_nodes_from(all_nodes)
    for child, parent in child_to_parent_map.items():
        if child in all_nodes and parent in all_nodes:
            G.add_edge(parent, child)
    print('正在计算所有标签对之间的最短路径距离...')
    path_lengths = dict(nx.all_pairs_shortest_path_length(G))
    H = np.zeros((num_labels, num_labels))
    print('正在根据距离计算相似度矩阵 H...')
    for i in range(num_labels):
        for j in range(i, num_labels):
            if i in path_lengths and j in path_lengths[i]:
                distance = path_lengths[i][j]
                similarity = 1.0 / (1.0 + distance)
                H[i, j] = similarity
                H[j, i] = similarity
    print('标签关系矩阵 H 构建完成。')
    return H
DEVICE = 'cuda:0' if torch.cuda.is_available() else 'cpu'

def main():
    print('--- Step 1: Loading data and setting up LabelManager ---')
    DATA_PATH = os.path.join(PROJECT_DIR, 'data')
    label_manager = LabelManager(csv_path=os.path.join(DATA_PATH, 'idlable.csv'))
    label_manager.setup_with_removed_ids(removed_ids=REMOVED_IDS)
    num_labels = label_manager.num_labels
    label_remapping = label_manager.label_remapping
    ancestor_map = label_manager.ancestor_map
    id2label = label_manager.id2label
    label2id = {v: k for k, v in id2label.items()}
    final_datasets = DatasetDict({'train': load_dataset('json', data_files=os.path.join(DATA_PATH, 'train_da_deduplicated.jsonl'))['train'], 'validation': load_dataset('json', data_files=os.path.join(DATA_PATH, 'validation_deduplicated.jsonl'))['train'], 'test': load_dataset('json', data_files=os.path.join(DATA_PATH, 'test_deduplicated.jsonl'))['train']})
    print('\n--- Step 2: Preprocessing data ---')
    tokenizer = AutoTokenizer.from_pretrained(PRETRAINED_MODEL_PATH)

    def preprocess_data(examples):
        text = examples['text']
        encoding = tokenizer(text, truncation=True, max_length=256)
        labels_matrix = np.zeros((len(text), num_labels))
        for i, labels_list in enumerate(examples['label']):
            remapped_labels = [label_remapping[old_id] for old_id in labels_list if old_id in label_remapping]
            for new_label_id in remapped_labels:
                labels_matrix[i, new_label_id] = 1.0
        encoding['labels'] = labels_matrix.tolist()
        return encoding
    tokenized_datasets = final_datasets.map(preprocess_data, batched=True, remove_columns=final_datasets['train'].column_names, load_from_cache_file=False)
    tokenized_datasets.set_format('torch')
    print('\n--- Step 3: Calculating label statistics ---')
    label_manager.calculate_ic_and_counts_from_dataset(tokenized_datasets['train'])
    ic_map = label_manager.ic_map
    y_train_counts = label_manager.y_train_counts
    print('\n--- Step 4: Calculating class weights ---')
    y_train_mlb = np.array(tokenized_datasets['train']['labels'])
    pos_counts = y_train_mlb.sum(axis=0)
    neg_counts = len(y_train_mlb) - pos_counts
    pos_weight = neg_counts / (pos_counts + 1e-08)
    pos_weight_tensor = torch.tensor(pos_weight, dtype=torch.float).to(DEVICE)
    print('类别权重计算完成。')
    print('\n--- Step 5: Setting up Model and Trainer ---')
    model = AutoModelForSequenceClassification.from_pretrained(PRETRAINED_MODEL_PATH, problem_type='multi_label_classification', num_labels=num_labels, id2label=id2label, label2id=label2id, ignore_mismatched_sizes=True)
    args = TrainingArguments(output_dir=SAVE_PATH, eval_strategy='epoch', save_strategy='epoch', learning_rate=1e-05, per_device_train_batch_size=32, per_device_eval_batch_size=32, num_train_epochs=60, weight_decay=0.01, load_best_model_at_end=True, metric_for_best_model='f1_micro', save_total_limit=3, logging_steps=30, fp16=True, gradient_checkpointing=True, report_to='tensorboard')
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    ALPHA_LARGE_CLASS = 0.95
    ALPHA_SMALL_CLASS = 0.75
    CLASS_SIZE_THRESHOLD = 50
    trainer = HybridLossTrainer(model=model, args=args, train_dataset=tokenized_datasets['train'], eval_dataset=tokenized_datasets['validation'], tokenizer=tokenizer, compute_metrics=compute_metrics_for_trainer, data_collator=data_collator, pos_weight=pos_weight_tensor, label_relation_matrix=None, temperature=TEMPERATURE, alpha_large_class=ALPHA_LARGE_CLASS, alpha_small_class=ALPHA_SMALL_CLASS, class_size_threshold=CLASS_SIZE_THRESHOLD, y_train_counts=y_train_counts)
    print('\n--- Step 6: Starting model fine-tuning ---')
    trainer.train()
    print('\n--- Step 7: Final evaluation on test set ---')
    test_results = trainer.predict(tokenized_datasets['test'])
    final_metrics = compute_metrics_for_trainer(test_results)
    print('Final metrics on the test set:')
    print(final_metrics)
    with open(os.path.join(SAVE_PATH, 'final_test_results.json'), 'w') as f:
        json.dump(final_metrics, f, indent=4)
    print(f'\nTraining complete. Best model saved in {SAVE_PATH} checkpoints. Final metrics saved.')
if __name__ == '__main__':
    log_filename = '/workspace/ablation_g.txt'
    sys.stdout = TeeLogger(log_filename, mode='a')
    try:
        main()
    finally:
        sys.stdout.close()
        sys.stdout = sys.__stdout__
