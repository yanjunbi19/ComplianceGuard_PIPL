'''
消融实验
'''

import torch
import numpy as np
import os
import gc 
from datasets import load_dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    EvalPrediction
)
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
torch.cuda.empty_cache()

    # --- 【核心修改】实例化新的 Trainer，并传入新参数 ---
    # 定义新的超参数
ALPHA_LARGE_CLASS = 0.95  # 对大类的BCE损失权重，让它更相信分类器
ALPHA_SMALL_CLASS = 0.75 # 对小类的BCE损失权重，让它更依赖SCL
CLASS_SIZE_THRESHOLD = 50 # 定义多大的类算“大类”

REMOVED_IDS = {3,4,5,6, 7, 8, 9, 10, 11,13,15,16,17,20,32,40,53,54,57,60,63,64,67,68,69,70,71,72,73,74,75,76,77,86}


# ALPHA = 0.8
TEMPERATURE = 0.05
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PRETRAINED_MODEL_PATH = "/workspace/models/cpp-chinese-roberta-wwm-ext-transfer/checkpoint-1395" # [建议] 使用上次训练保存的最终最佳模型
SAVE_PATH = "./models/roberta-multilabel-classifier-d1-82-9575-05-50-g-ablation-scl"
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
        # --- 【核心修复】在这里添加 isatty 方法 ---
    def isatty(self):
        """
        实现 isatty 方法，以兼容需要检查终端类型的库。
        我们将这个请求直接转发给原始的终端。
        """
        return hasattr(self.terminal, 'isatty') and self.terminal.isatty()
    # --- 【修复结束】 ---

def build_label_relation_matrix_node2vec(
    child_to_parent_map: dict, 
    num_labels: int,
    dimensions=32,  # 嵌入向量的维度
    walk_length=10, # 随机游走的长度
    num_walks=100,  # 每个节点的游走次数
    p=1.0,          # 返回参数
    q=0.5           # 进出参数 (q<1偏向BFS，q>1偏向DFS)
) -> np.ndarray:
    """
    【新函数】使用 Node2Vec 来为标签学习嵌入，并构建 H 矩阵。
    """
    print("正在使用 Node2Vec 构建标签关系矩阵 H...")
    
    # 1. 构建 NetworkX 图
    G = nx.Graph()
    G.add_nodes_from(range(num_labels))
    for child, parent in child_to_parent_map.items():
        if child in range(num_labels) and parent in range(num_labels):
            G.add_edge(str(parent), str(child)) # Node2Vec 需要节点是字符串

    # 2. 配置并训练 Node2Vec 模型
    # p=1, q=0.5 会让游走更倾向于探索一个节点的局部邻域（像BFS）
    # 这对于层次结构来说，可能能更好地捕捉兄弟节点的关系
    node2vec = Node2Vec(G, dimensions=dimensions, walk_length=walk_length, 
                        num_walks=num_walks, p=p, q=q, workers=4, quiet=True)
    model = node2vec.fit(window=5, min_count=1, batch_words=4)

    # 3. 从训练好的模型中获取所有节点的嵌入向量
    embeddings = np.array([model.wv[str(i)] for i in range(num_labels)])
    
    # 4. 计算嵌入向量之间的余弦相似度来构建 H 矩阵
    #    首先对嵌入进行归一化
    embeddings_normalized = embeddings / (np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-8)
    #    然后计算点积，即为余弦相似度
    H = np.dot(embeddings_normalized, embeddings_normalized.T)
    
    # 将相似度范围从 [-1, 1] 映射到 [0, 1] (可选，但推荐)
    H = (H + 1) / 2
    
    print("基于 Node2Vec 的标签关系矩阵 H 构建完成。")
    return H
def find_best_thresholds_per_label_optimized(y_prob: np.ndarray, y_true: np.ndarray) -> np.ndarray:
    """
    【V2.1 - 类型修复版】使用向量化操作为每个标签高效地寻找最佳阈值。
    """
    num_samples, num_labels = y_true.shape
    
    # 1. 定义要搜索的阈值范围
    thresholds = np.arange(0.1, 0.9, 0.05)

    # 2. 【核心修复】在进行任何操作前，将 y_true 转换为布尔类型
    y_true_bool = y_true.astype(bool)

    # 3. 扩展维度以进行广播
    y_prob_expanded = np.expand_dims(y_prob, axis=2)
    thresholds_expanded = np.expand_dims(thresholds, axis=(0, 1))
    
    # a) 得到布尔预测矩阵
    predictions_tensor = (y_prob_expanded >= thresholds_expanded)

    # b) 扩展布尔类型的真实标签
    y_true_expanded = np.expand_dims(y_true_bool, axis=2)

    # 4. 一次性计算所有阈值下的 TP, FP, FN (现在类型匹配了)
    true_positives = np.sum(predictions_tensor & y_true_expanded, axis=0)
    false_positives = np.sum(predictions_tensor & ~y_true_expanded, axis=0)
    
    # 为了正确计算FN，我们需要每类的正样本总数
    total_positives_per_label = np.sum(y_true_bool, axis=0) # 形状 [num_labels]
    # 扩展维度以便广播
    total_positives_expanded = np.expand_dims(total_positives_per_label, axis=1) # 形状 [num_labels, 1]
    false_negatives = total_positives_expanded - true_positives

    # 5. 一次性计算所有 F1 分数
    denominator = (2 * true_positives + false_positives + false_negatives)
    f1_scores = (2 * true_positives) / (denominator + 1e-8)

    # 6. 为每个标签找到最大 F1 分数对应的阈值索引
    best_threshold_indices = np.argmax(f1_scores, axis=1)
    best_thresholds = thresholds[best_threshold_indices]
    
    # 7. 重置没有正样本的标签的阈值
    best_thresholds[total_positives_per_label == 0] = 0.5

    # 8. 手动清理大的中间变量，防止内存泄漏
    del y_prob_expanded, thresholds_expanded, predictions_tensor, y_true_expanded
    gc.collect()

    return best_thresholds

def apply_per_label_thresholds(probs, thresholds):
    """
    【新辅助函数】使用每类不同的阈值向量来生成最终的二进制预测。
    """
    # NumPy的广播机制会自动按列比较，非常高效
    return (probs >= thresholds).astype(int)

def compute_metrics_for_trainer(p: EvalPrediction):
    """
    【终极版】在每次评估时，为每个类别动态寻找最优阈值，并计算指标。
    """
def compute_metrics_for_trainer(p: EvalPrediction):
    """
    【V2 - OOM修复版】
    """
    preds = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
    labels = p.label_ids

    # 【核心修复】确保所有操作都在 CPU 上进行
    # 1. 将 numpy array 转换为 CPU 上的 torch tensor
    preds_tensor_cpu = torch.from_numpy(preds).cpu() 
    
    # 2. 在 CPU 上计算 sigmoid
    sigmoid = torch.nn.Sigmoid()
    probs_tensor_cpu = sigmoid(preds_tensor_cpu)
    
    # 3. 转回 numpy array 以进行后续计算
    probs = probs_tensor_cpu.numpy()

    # 【重要】调用优化后的阈值查找函数
    best_thresholds_vector = find_best_thresholds_per_label_optimized(probs, labels)
    
    y_pred_final = apply_per_label_thresholds(probs, best_thresholds_vector)
    y_true_final = labels

    # 5. 计算各项指标
    f1_micro = f1_score(y_true_final, y_pred_final, average='micro', zero_division=0)
    f1_macro = f1_score(y_true_final, y_pred_final, average='macro', zero_division=0)
    f1_weighted = f1_score(y_true_final, y_pred_final, average='weighted', zero_division=0)
    accuracy = accuracy_score(y_true_final, y_pred_final) # 注意：accuracy在多标签中意义有限

    # 6. 准备返回的指标字典
    metrics = {
        'accuracy': accuracy,
        'f1_micro': f1_micro,
        'f1_macro': f1_macro,
        'f1_weighted': f1_weighted,
        # 【重要】在日志中记录阈值向量的平均值和标准差，以观察其变化
        'threshold_mean': np.mean(best_thresholds_vector),
        'threshold_std': np.std(best_thresholds_vector),
    }
    
    return metrics


class MultiLabelSupervisedContrastiveLoss(nn.Module):
    def __init__(self, temperature=0.07, label_relation_matrix=None, negative_weight=0.1): # 增加一个超参
        super().__init__()
        self.temperature = temperature
        self.H = label_relation_matrix
        self.negative_weight = negative_weight # 负权重

    def forward(self, embeddings, labels):
        embeddings = F.normalize(embeddings, p=2, dim=1)
        similarity_matrix = torch.matmul(embeddings, embeddings.T)
        similarity_matrix = torch.clamp(similarity_matrix, min=-15.0, max=15.0)

        # --- 第一部分：正样本对的吸引力 (保持不变) ---
        if self.H is not None:
            if self.H.device != labels.device: self.H = self.H.to(labels.device)
            hierarchical_similarity = torch.matmul(torch.matmul(labels.float(), self.H), labels.float().T)
            positive_weights = torch.log1p(hierarchical_similarity)
        else:
            shared_labels_count = torch.matmul(labels.float(), labels.float().T)
            positive_weights = torch.log1p(shared_labels_count)

        mask_no_self = torch.eye(labels.shape[0], device=labels.device).bool()
        positive_weights.masked_fill_(mask_no_self, 0)
        
        # --- 第二部分：【新增】困难负样本对的排斥力 ---
        # 1. 找到完全没有共享标签的样本对 (hard negatives)
        shared_labels_count = torch.matmul(labels.float(), labels.float().T)
        negative_mask = (shared_labels_count == 0)
        
        # 2. 我们只关心那些虽然标签不同，但表示空间很接近的样本对
        #    这些是导致 Precision 低的“罪魁祸首”
        #    我们想让它们的 similarity_matrix 值变小（即增加它们的损失）
        #    一个简单的实现是，对它们的 cosine similarity 施加一个惩罚
        #    我们希望 similarity_matrix[negative_mask] -> 0
        #    所以损失项可以是 similarity_matrix[negative_mask].mean()
        
        # 筛选出负样本对的相似度
        negative_similarities = similarity_matrix.masked_select(negative_mask)
        # 计算负样本对的损失，我们希望这些相似度越小越好，所以直接取其均值作为损失项
        loss_neg = negative_similarities.mean() if negative_similarities.numel() > 0 else 0.0

        # --- 第三部分：计算原始SCL损失 (保持不变) ---
        similarity_matrix_no_self = similarity_matrix.masked_fill(mask_no_self, -9e15)
        logits = similarity_matrix_no_self / self.temperature
        log_prob = logits - torch.logsumexp(logits, dim=1, keepdim=True)
        mean_log_prob_pos = (positive_weights * log_prob).sum(1) / (positive_weights.sum(1) + 1e-8)
        loss_pos = -mean_log_prob_pos.mean()

        # --- 第四部分：【新增】组合损失 ---
        # 最终的SCL损失 = 正样本损失 + beta * 负样本损失
        final_scl_loss = loss_pos + self.negative_weight * loss_neg
        
        return final_scl_loss

from transformers import Trainer
from torch.nn import BCEWithLogitsLoss

def build_ancestor_map(child_to_parent_map):
    """
    根据子->父的映射，构建一个 子->[所有祖先] 的映射。
    """
    ancestor_map = {}
    
    # 检查输入是否有效
    if not child_to_parent_map:
        return ancestor_map # 如果输入为空，返回空字典

    for child_id, parent_id in child_to_parent_map.items():
        ancestors = []
        current = parent_id
        while current is not None:
            ancestors.append(current)
            current = child_to_parent_map.get(current) # 递归查找上级父节点
        
        if ancestors:
            # 【修复1】将找到的祖先列表赋值给对应的子ID
            ancestor_map[child_id] = ancestors
            
    # 【修复2】在函数末尾返回构建好的字典
    return ancestor_map

class HybridLossTrainer(Trainer):
    def __init__(self, *args, 
                 pos_weight=None, 
                 label_relation_matrix=None,
                 temperature=0.07,
                 # --- 【新增】类别感知加权的超参数 ---
                 alpha_large_class=0.95, 
                 alpha_small_class=0.7, 
                 class_size_threshold=50, 
                 y_train_counts=None,
                 # ---
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.pos_weight = pos_weight
        self.scl_loss_fn = MultiLabelSupervisedContrastiveLoss(
            temperature=temperature,
            label_relation_matrix=label_relation_matrix
        )

        # --- 【核心实现】构建类别感知的 alpha 张量 ---
        if y_train_counts is None:
            raise ValueError("HybridLossTrainer 需要 y_train_counts 参数来进行类别感知加权！")
            
        print("\n--- HybridLossTrainer: 正在构建类别感知的 alpha 权重张量 ---")
        
        # 1. 创建一个张量，默认所有 alpha 都是小类的 alpha
        alpha_tensor = torch.full((self.model.config.num_labels,), alpha_small_class, device=self.args.device)
        
        # 2. 找到大类的索引
        large_class_mask = torch.from_numpy(y_train_counts > class_size_threshold).to(self.args.device)
        
        # 3. 将大类的 alpha 值设置为较大的那个
        alpha_tensor[large_class_mask] = alpha_large_class
        
        # 4. 保存为类的属性，并调整形状以便广播
        self.alpha_tensor = alpha_tensor.view(1, -1) # 形状变为 [1, num_labels]
        
        num_large_classes = large_class_mask.sum().item()
        print(f"Alpha 张量构建完成。大类阈值: >{class_size_threshold}个样本。")
        print(f"大类数量: {num_large_classes}, 使用 alpha = {alpha_large_class}")
        print(f"小类数量: {self.model.config.num_labels - num_large_classes}, 使用 alpha = {alpha_small_class}")
        # ---

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop("labels")
        
        # --- 区分训练和评估模式 (保持不变) ---
        if self.model.training:
            outputs = model(**inputs, output_hidden_states=True)
            logits = outputs.get("logits")
            
            # 1. 计算【类别感知加权】的分类损失
            #    使用 'none' reduction 来获取每个元素独立的损失
            cls_loss_fct = BCEWithLogitsLoss(pos_weight=self.pos_weight, reduction='none')
            per_item_loss_cls = cls_loss_fct(logits.view(-1, self.model.config.num_labels), 
                                             labels.float().view(-1, self.model.config.num_labels))
            
            # 使用 alpha_tensor 对每个类别的损失进行加权
            # (batch_size, num_labels) * (1, num_labels) -> (batch_size, num_labels)
            weighted_per_item_loss_cls = self.alpha_tensor * per_item_loss_cls
            
            # 最后取平均得到最终的分类损失
            loss_cls = weighted_per_item_loss_cls.mean()

            # 2. 计算对比损失 (SCL)
            last_hidden_state = outputs.hidden_states[-1]
            attention_mask = inputs['attention_mask']
            mask_expanded = attention_mask.unsqueeze(-1).expand(last_hidden_state.size()).float()
            sum_embeddings = torch.sum(last_hidden_state * mask_expanded, 1)
            sum_mask = torch.clamp(mask_expanded.sum(1), min=1e-9)
            embeddings = sum_embeddings / sum_mask
            loss_scl = self.scl_loss_fn(embeddings, labels)
            
            # 3. 【核心修改】混合损失
            #    我们不能再用一个全局的 alpha。我们需要一个全局的 (1-alpha) 权重
            #    一个合理的近似是使用 (1 - alpha_tensor) 的平均值
            global_scl_weight = (1.0 - self.alpha_tensor).mean()
            
            loss = loss_cls + global_scl_weight * loss_scl

        else:
            # 评估模式下，只计算标准的分类损失用于日志记录
            outputs = model(**inputs, output_hidden_states=False)
            logits = outputs.get("logits")
            loss_fct = BCEWithLogitsLoss(pos_weight=self.pos_weight)
            loss = loss_fct(logits.view(-1, self.model.config.num_labels), 
                            labels.float().view(-1, self.model.config.num_labels))

        return (loss, outputs) if return_outputs else loss

class LabelManager:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self._load_all_labels()
        self.reset()
        self.y_train_counts = None # 【新增】用于存储类别计数的属性

    def _load_all_labels(self):
        """从CSV加载所有标签及其层级关系，作为原始数据。"""
        self.all_labels_info = []
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader) # Skip header
            for i, row in enumerate(reader):
                full_id_str = row[0].strip()
                parts = full_id_str.split('.')
                parent_id = '.'.join(parts[:-1]) if len(parts) > 1 else None
                self.all_labels_info.append({
                    "original_index": i,
                    "id_str": full_id_str,
                    "name": row[1].strip(),
                    "parent_id_str": parent_id
                })
        self.original_num_labels = len(self.all_labels_info)

    def reset(self):
        """重置状态，恢复到使用所有标签。"""
        self.setup_with_removed_ids(removed_ids=set())

    def setup_with_removed_ids(self, removed_ids: set):
        """
        【核心方法】根据一组要移除的原始索引，重新计算所有映射和层级关系。
        """
        print(f"\n--- LabelManager: 正在使用移除ID列表 {removed_ids} 重新设置 ---")
        self.removed_ids = removed_ids
        
        self.retained_labels_info = [
            info for info in self.all_labels_info if info["original_index"] not in self.removed_ids
        ]
        
        self.label_remapping = {
            info["original_index"]: new_id for new_id, info in enumerate(self.retained_labels_info)
        }
        
        self.id2label = {new_id: info["name"] for new_id, info in enumerate(self.retained_labels_info)}
        self.label2id = {v: k for k, v in self.id2label.items()}
        
        self.num_labels = len(self.retained_labels_info)
        print(f"标签重映射完成: 原始标签数: {self.original_num_labels}, 新标签数: {self.num_labels}")

        retained_id_strs = {info["id_str"] for info in self.retained_labels_info}
        self.child_to_parent_map = {}
        for info in self.retained_labels_info:
            if info["parent_id_str"] in retained_id_strs:
                parent_info = next(p for p in self.all_labels_info if p["id_str"] == info["parent_id_str"])
                new_child_id = self.label_remapping[info["original_index"]]
                new_parent_id = self.label_remapping[parent_info["original_index"]]
                self.child_to_parent_map[new_child_id] = new_parent_id
        
        self.ancestor_map = build_ancestor_map(self.child_to_parent_map)
        print("层次关系祖先图构建完成。")

    def calculate_ic_and_counts_from_dataset(self, tokenized_train_dataset): # 【修改】方法名，功能合并
        """
        【新版本】根据训练集计算每个标签的计数、概率和信息内容 (IC)。
        """
        print("--- LabelManager: 正在计算标签计数、概率和信息内容 (IC) ---")
        
        y_train = np.array([item['labels'] for item in tokenized_train_dataset])
        num_samples, num_labels_in_data = y_train.shape
        
        if num_labels_in_data != self.num_labels:
            raise ValueError(f"数据集中的标签数量({num_labels_in_data})与LabelManager中的数量({self.num_labels})不匹配！")

        # 1. 【新增】计算并存储每个标签的样本数
        self.y_train_counts = y_train.sum(axis=0)
        
        # 2. 计算概率 P(c)
        self.label_probabilities = (self.y_train_counts + 1) / (num_samples + 2)
        
        # 3. 计算信息内容 IC(c) = -log(P(c))
        self.ic_values = -np.log(self.label_probabilities)
        self.ic_map = {i: self.ic_values[i] for i in range(self.num_labels)}
        
        print("标签计数和信息内容 (IC) 计算完成。")


def build_label_relation_matrix_ic(
    num_labels: int, 
    ancestor_map: dict, 
    ic_map: dict
) -> np.ndarray:
    """
    【新函数】使用信息论方法 (Lin Similarity) 构建标签关系矩阵 H。

    Args:
        num_labels (int): 总的标签数量。
        ancestor_map (dict): {子ID: [所有祖先ID列表]} 的映射。
        ic_map (dict): {标签ID: IC值} 的映射。

    Returns:
        np.ndarray: 一个 [num_labels, num_labels] 的相似度矩阵 H。
    """
    print("正在使用信息论方法构建标签关系矩阵 H...")
    H = np.zeros((num_labels, num_labels))

    for i in range(num_labels):
        for j in range(i, num_labels):
            if i == j:
                H[i, j] = 1.0 # 自身与自身的相似度为1
                continue

            # 1. 获取两个标签各自的IC值
            ic_i = ic_map.get(i, 0)
            ic_j = ic_map.get(j, 0)
            
            # 如果任一IC值为0（例如，标签从未出现），则相似度为0
            if ic_i == 0 or ic_j == 0:
                similarity = 0.0
            else:
                # 2. 找到最深共同祖先 (LCA)
                # 一个标签的所有祖先包括它自己
                ancestors_i = set(ancestor_map.get(i, [])) | {i}
                ancestors_j = set(ancestor_map.get(j, [])) | {j}
                
                common_ancestors = ancestors_i.intersection(ancestors_j)
                
                if not common_ancestors:
                    # 如果没有共同祖先（理论上在你的树中不会发生，除非是多个根）
                    lca_ic = 0.0
                else:
                    # 从共同祖先中，找到IC值最大的那个，即最深的共同祖先
                    lca_ic = max(ic_map.get(ca, 0) for ca in common_ancestors)
                
                # 3. 计算 Lin 相似度
                # 加上一个小的 epsilon 防止分母为0
                denominator = ic_i + ic_j + 1e-8
                similarity = (2 * lca_ic) / denominator
            
            H[i, j] = similarity
            H[j, i] = similarity # 对称赋值
            
    print("基于信息内容的标签关系矩阵 H 构建完成。")
    return H

def build_label_relation_matrix(child_to_parent_map: dict, num_labels: int) -> np.ndarray:
    """
    构建一个量化标签间层级关系的相似度矩阵 H。

    Args:
        child_to_parent_map (dict): {子ID: 父ID} 的映射。
        num_labels (int): 总的标签数量。

    Returns:
        np.ndarray: 一个 [num_labels, num_labels] 的相似度矩阵 H。
    """
    print("正在构建标签层级关系图...")
    # 1. 使用 networkx 构建一个无向图
    G = nx.Graph()
    all_nodes = set(range(num_labels))
    
    # 添加所有节点
    G.add_nodes_from(all_nodes)
    
    # 添加边（父子关系）
    for child, parent in child_to_parent_map.items():
        if child in all_nodes and parent in all_nodes:
            G.add_edge(parent, child)

    # 2. 计算所有节点对之间的最短路径长度
    print("正在计算所有标签对之间的最短路径距离...")
    # all_pairs_shortest_path_length 返回一个迭代器，我们需要将其转换为字典
    path_lengths = dict(nx.all_pairs_shortest_path_length(G))

    # 3. 创建相似度矩阵 H
    # 矩阵初始化为0
    H = np.zeros((num_labels, num_labels))
    
    print("正在根据距离计算相似度矩阵 H...")
    for i in range(num_labels):
        for j in range(i, num_labels): # 对称矩阵，只计算一半
            if i in path_lengths and j in path_lengths[i]:
                distance = path_lengths[i][j]
                # 将距离转换为相似度，这里使用 1 / (1 + distance)
                # 距离为0（同一个节点），相似度为1
                # 距离为1（父子），相似度为0.5
                # 距离为2（兄弟），相似度为0.33
                similarity = 1.0 / (1.0 + distance)
                H[i, j] = similarity
                H[j, i] = similarity # 对称赋值
            # 如果两个节点不在同一个连通分量中，则它们之间没有路径，相似度保持为0

    print("标签关系矩阵 H 构建完成。")
    return H


# =========================================================================
# 统一的全局配置
# =========================================================================


DEVICE = "cuda:0" if torch.cuda.is_available() else "cpu"
def main():
    """主函数，整合所有流程"""

    # =========================================================================
    # Step 1: 加载数据和配置 LabelManager
    # =========================================================================
    print("--- Step 1: Loading data and setting up LabelManager ---")
    DATA_PATH = os.path.join(PROJECT_DIR, "data")


    label_manager = LabelManager(csv_path=os.path.join(DATA_PATH, "idlable.csv"))
    label_manager.setup_with_removed_ids(removed_ids=REMOVED_IDS)
    
    # 从 LabelManager 获取所有计算好的、权威的变量
    num_labels = label_manager.num_labels
    label_remapping = label_manager.label_remapping
    ancestor_map = label_manager.ancestor_map # 获取祖先图，为 IC 方法做准备
    id2label = label_manager.id2label
    label2id = {v: k for k, v in id2label.items()}
    
    # 加载原始数据集
    final_datasets = DatasetDict({
        'train': load_dataset("json", data_files=os.path.join(DATA_PATH, "train_da_deduplicated.jsonl"))['train'],
        'validation': load_dataset("json", data_files=os.path.join(DATA_PATH, "validation_deduplicated.jsonl"))['train'],
        'test': load_dataset("json", data_files=os.path.join(DATA_PATH, "test_deduplicated.jsonl"))['train']
    })

    # =========================================================================
    # Step 2: 数据预处理
    # =========================================================================
    print("\n--- Step 2: Preprocessing data ---")
    tokenizer = AutoTokenizer.from_pretrained(PRETRAINED_MODEL_PATH)

    # preprocess_data 函数保持不变
    def preprocess_data(examples):
        text = examples["text"]
        encoding = tokenizer(text, truncation=True, max_length=256)
        labels_matrix = np.zeros((len(text), num_labels))
        for i, labels_list in enumerate(examples["label"]):
            remapped_labels = [label_remapping[old_id] for old_id in labels_list if old_id in label_remapping]
            for new_label_id in remapped_labels:
                labels_matrix[i, new_label_id] = 1.0
        encoding["labels"] = labels_matrix.tolist()
        return encoding

    tokenized_datasets = final_datasets.map(preprocess_data, batched=True, remove_columns=final_datasets['train'].column_names, load_from_cache_file=False)
    tokenized_datasets.set_format("torch")

    # =========================================================================
    # Step 3: 构建基于信息论的层次化关系矩阵 H
    # =========================================================================
    print("\n--- Step 3: Building Hierarchical Relation Matrix H (IC-based) ---")

    
    # 3.1. 【修改】调用新的合并功能函数
    label_manager.calculate_ic_and_counts_from_dataset(tokenized_datasets['train'])
    ic_map = label_manager.ic_map
    y_train_counts = label_manager.y_train_counts # 【获取】类别计数

    # 3.2. 构建 H 矩阵 (不变)
    child_to_parent_map = label_manager.child_to_parent_map # 确保这个可用
    label_relation_matrix_np = build_label_relation_matrix_node2vec(
        child_to_parent_map=child_to_parent_map,
        num_labels=num_labels
    )
    label_relation_matrix_tensor = torch.tensor(label_relation_matrix_np, dtype=torch.float).to(DEVICE)

    # =========================================================================
    # Step 4: 计算类别权重 (用于 BCE 损失)
    # =========================================================================
    print("\n--- Step 4: Calculating class weights ---")
    y_train_mlb = np.array(tokenized_datasets['train']['labels'])
    pos_counts = y_train_mlb.sum(axis=0)
    neg_counts = len(y_train_mlb) - pos_counts
    pos_weight = neg_counts / (pos_counts + 1e-8)
    pos_weight_tensor = torch.tensor(pos_weight, dtype=torch.float).to(DEVICE)
    print("类别权重计算完成。")

    # =========================================================================
    # Step 5: 模型与训练器配置
    # =========================================================================
    print("\n--- Step 5: Setting up Model and Trainer ---")
    model = AutoModelForSequenceClassification.from_pretrained(
        PRETRAINED_MODEL_PATH, 
        problem_type="multi_label_classification", 
        num_labels=num_labels,
        id2label=id2label,
        label2id=label2id,
        ignore_mismatched_sizes=True
    )

    args = TrainingArguments(
        # --- 【重要】为这个实验设置一个新的输出目录 ---
        output_dir=SAVE_PATH, 
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=1e-5,
        per_device_train_batch_size=32,
        per_device_eval_batch_size=32,
        num_train_epochs=60,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="f1_micro",
        save_total_limit=3,
        logging_steps=50,
        fp16=True,
        gradient_checkpointing=True,
        report_to="tensorboard"
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    class SimpleTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs): # <--- 核心修改在这里
            """
            修正了方法签名，通过 **kwargs 接受任何额外的参数。
            """
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.get("logits")
            
            # 确保 pos_weight 在正确的设备上
            # 我们假设 pos_weight 已经被附加到 model 对象上
            if hasattr(self.model, 'pos_weight'):
                pos_weight_tensor = self.model.pos_weight.to(logits.device)
            else:
                pos_weight_tensor = None
                
            loss_fct = BCEWithLogitsLoss(pos_weight=pos_weight_tensor)
            
            loss = loss_fct(logits.view(-1, self.model.config.num_labels), 
                            labels.float().view(-1, self.model.config.num_labels))
                            
            return (loss, outputs) if return_outputs else loss


    # 在模型上附加 pos_weight
    model.pos_weight = pos_weight_tensor

    trainer = SimpleTrainer( # 或者直接用 transformers.Trainer 如果不考虑 pos_weight
        model=model,
        args=args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["validation"],
        tokenizer=tokenizer,
        compute_metrics=compute_metrics_for_trainer,
        data_collator=data_collator,
        # 不需要传入 label_relation_matrix 等参数
    )
    # =========================================================================
    # Step 6: 训练和评估
    # =========================================================================
    print("\n--- Step 6: Starting model fine-tuning ---")
    trainer.train()
    
    print("\n--- Step 7: Final evaluation on test set ---")
    # 注意：这里的 compute_metrics_for_trainer 内部没有使用层次化指标
    # 如果要在最终评估中也看到层次化指标，需要修改 compute_metrics_for_trainer
    test_results = trainer.predict(tokenized_datasets['test'])
    final_metrics = compute_metrics_for_trainer(test_results)
    
    print("Final metrics on the test set:")
    print(final_metrics)
    
    with open(os.path.join(SAVE_PATH, "final_test_results.json"), "w") as f:
        json.dump(final_metrics, f, indent=4)
        
    print(f"\nTraining complete. Best model saved in {SAVE_PATH} checkpoints. Final metrics saved.")


if __name__ == '__main__':
    log_filename = "/workspace/ablation_scl.txt"

    # 如果是续写日志，可以使用 mode='a'；如果是每次新建日志，使用 mode='w'
    sys.stdout = TeeLogger(log_filename, mode='a')  # 改为 'w' 可覆盖日志
    try:   
        main()
        # evaluate_model()
    finally:
        sys.stdout.close()  # 关闭文件写入
        sys.stdout = sys.__stdout__  # 恢复标准输出
