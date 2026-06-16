'''
分类实验的对比模型。
'''
import os
import gc
import sys
import csv
import json
import random
import numpy as np
import torch

from datasets import load_dataset, DatasetDict
from sklearn.metrics import f1_score, accuracy_score
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    EvalPrediction,
    DataCollatorWithPadding,
    EarlyStoppingCallback,
    set_seed
)
from torch.nn import BCEWithLogitsLoss


# =========================================================
# 基础配置
# =========================================================
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# -------------------------
# 数据与标签路径
# -------------------------
DATA_PATH = os.path.join(PROJECT_DIR, "data")
LABEL_CSV_PATH = os.path.join(DATA_PATH, "idlable.csv")

MODEL_TAG = "ernie_3_base"
MODEL_NAME_OR_PATH = "nghuyong/ernie-3.0-base-zh"
OUTPUT_DIR = f"/workspace/model_compare_outputs/{MODEL_TAG}"
LOG_FILE = f"/workspace/model_compare_outputs/{MODEL_TAG}.log"

# 示例：
# MODEL_TAG = "roberta_wwm_ext"
# MODEL_NAME_OR_PATH = "hfl/chinese-roberta-wwm-ext"
# OUTPUT_DIR = f"/workspace/model_compare_outputs/{MODEL_TAG}"
# LOG_FILE = f"/workspace/model_compare_outputs/{MODEL_TAG}.log"

# -------------------------
# 训练超参数
# -------------------------
MAX_LENGTH = 256
LEARNING_RATE = 1e-5
TRAIN_BATCH_SIZE = 32
EVAL_BATCH_SIZE = 32
NUM_EPOCHS = 30
WEIGHT_DECAY = 0.01
SEED = 42

USE_FP16 = torch.cuda.is_available()
USE_GRADIENT_CHECKPOINTING = True

# -------------------------
# EarlyStopping 参数
# 如果连续 patience 次评估没有提升，就提前停止
# -------------------------
EARLY_STOPPING_PATIENCE = 3
EARLY_STOPPING_THRESHOLD = 0.0

# -------------------------
# 只保留两个 checkpoint
# 注意：HF 通常会保留“最佳checkpoint + 最近checkpoint”
# -------------------------
SAVE_TOTAL_LIMIT = 2

# 你原来的标签移除列表
REMOVED_IDS = {3,4,5,6, 7, 8, 9, 10, 11,13,15,16,17,20,32,40,53,54,57,60,63,64,67,68,69,70,71,72,73,74,75,76,77,86}

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


# =========================================================
# 日志输出
# =========================================================
class TeeLogger:
    def __init__(self, log_file, mode='a'):
        self.terminal = sys.stdout
        self.log = open(log_file, mode, encoding="utf-8")

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


# =========================================================
# 标签管理器
# =========================================================
class LabelManager:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self._load_all_labels()
        self.reset()

    def _load_all_labels(self):
        self.all_labels_info = []
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # 跳过表头
            for i, row in enumerate(reader):
                full_id_str = row[0].strip()
                self.all_labels_info.append({
                    "original_index": i,
                    "id_str": full_id_str,
                    "name": row[1].strip()
                })
        self.original_num_labels = len(self.all_labels_info)

    def reset(self):
        self.setup_with_removed_ids(set())

    def setup_with_removed_ids(self, removed_ids: set):
        print("\n--- LabelManager: 正在重新设置标签映射 ---")
        self.removed_ids = removed_ids

        self.retained_labels_info = [
            info for info in self.all_labels_info
            if info["original_index"] not in self.removed_ids
        ]

        self.label_remapping = {
            info["original_index"]: new_id
            for new_id, info in enumerate(self.retained_labels_info)
        }

        self.id2label = {
            new_id: info["name"]
            for new_id, info in enumerate(self.retained_labels_info)
        }
        self.label2id = {v: k for k, v in self.id2label.items()}

        self.num_labels = len(self.retained_labels_info)

        print(f"原始标签数: {self.original_num_labels}")
        print(f"保留后标签数: {self.num_labels}")


# =========================================================
# 阈值搜索与评估
# =========================================================
def logits_to_probs(logits: np.ndarray) -> np.ndarray:
    logits_tensor = torch.from_numpy(logits).float().cpu()
    probs = torch.sigmoid(logits_tensor).numpy()
    return probs


def find_best_thresholds_per_label_optimized(y_prob: np.ndarray, y_true: np.ndarray) -> np.ndarray:
    """
    在验证集上为每个标签搜索最佳阈值
    """
    _, num_labels = y_true.shape
    thresholds = np.arange(0.1, 0.9, 0.05)
    y_true_bool = y_true.astype(bool)

    y_prob_expanded = np.expand_dims(y_prob, axis=2)              # [N, L, 1]
    thresholds_expanded = np.expand_dims(thresholds, axis=(0, 1)) # [1, 1, T]

    predictions_tensor = (y_prob_expanded >= thresholds_expanded) # [N, L, T]
    y_true_expanded = np.expand_dims(y_true_bool, axis=2)         # [N, L, 1]

    true_positives = np.sum(predictions_tensor & y_true_expanded, axis=0)   # [L, T]
    false_positives = np.sum(predictions_tensor & ~y_true_expanded, axis=0) # [L, T]

    total_positives_per_label = np.sum(y_true_bool, axis=0)                 # [L]
    total_positives_expanded = np.expand_dims(total_positives_per_label, axis=1)
    false_negatives = total_positives_expanded - true_positives

    denominator = 2 * true_positives + false_positives + false_negatives
    f1_scores = (2 * true_positives) / (denominator + 1e-8)

    best_threshold_indices = np.argmax(f1_scores, axis=1)
    best_thresholds = thresholds[best_threshold_indices]

    # 没有正样本的类别，默认阈值 0.5
    best_thresholds[total_positives_per_label == 0] = 0.5

    del y_prob_expanded, thresholds_expanded, predictions_tensor, y_true_expanded
    gc.collect()

    return best_thresholds


def apply_per_label_thresholds(probs: np.ndarray, thresholds: np.ndarray) -> np.ndarray:
    return (probs >= thresholds).astype(int)


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    f1_micro = f1_score(y_true, y_pred, average='micro', zero_division=0)
    f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)

    return {
        "accuracy": float(accuracy),
        "f1_micro": float(f1_micro),
        "f1_macro": float(f1_macro),
        "f1_weighted": float(f1_weighted)
    }


def compute_metrics_for_trainer(p: EvalPrediction):
    """
    用于 Trainer 在验证集评估时动态搜索阈值
    """
    preds = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
    labels = p.label_ids

    probs = logits_to_probs(preds)
    best_thresholds = find_best_thresholds_per_label_optimized(probs, labels)
    y_pred = apply_per_label_thresholds(probs, best_thresholds)

    metrics = calculate_metrics(labels, y_pred)
    metrics["threshold_mean"] = float(np.mean(best_thresholds))
    metrics["threshold_std"] = float(np.std(best_thresholds))
    return metrics


def evaluate_with_fixed_thresholds(pred_output, thresholds: np.ndarray) -> dict:
    """
    测试集评估：使用验证集上得到的固定阈值
    """
    preds = pred_output.predictions[0] if isinstance(pred_output.predictions, tuple) else pred_output.predictions
    labels = pred_output.label_ids

    probs = logits_to_probs(preds)
    y_pred = apply_per_label_thresholds(probs, thresholds)

    metrics = calculate_metrics(labels, y_pred)
    metrics["threshold_mean"] = float(np.mean(thresholds))
    metrics["threshold_std"] = float(np.std(thresholds))
    return metrics


# =========================================================
# 自定义 Trainer：仅 BCE 多标签分类损失
# =========================================================
class WeightedTrainer(Trainer):
    def __init__(self, *args, pos_weight=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.pos_weight = pos_weight

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")

        if self.pos_weight is not None:
            loss_fct = BCEWithLogitsLoss(pos_weight=self.pos_weight.to(logits.device))
        else:
            loss_fct = BCEWithLogitsLoss()

        loss = loss_fct(
            logits.view(-1, model.config.num_labels),
            labels.float().view(-1, model.config.num_labels)
        )

        return (loss, outputs) if return_outputs else loss


# =========================================================
# 数据加载与预处理
# =========================================================
def load_raw_datasets(data_path: str) -> DatasetDict:
    print("\n--- 开始加载数据集 ---")
    datasets = DatasetDict({
        'train': load_dataset("json", data_files=os.path.join(data_path, "train_da_deduplicated.jsonl"))['train'],
        'validation': load_dataset("json", data_files=os.path.join(data_path, "validation_deduplicated.jsonl"))['train'],
        'test': load_dataset("json", data_files=os.path.join(data_path, "test_deduplicated.jsonl"))['train']
    })
    print("数据集加载完成。")
    print(f"train size: {len(datasets['train'])}")
    print(f"validation size: {len(datasets['validation'])}")
    print(f"test size: {len(datasets['test'])}")
    return datasets


def tokenize_datasets(raw_datasets, tokenizer, num_labels, label_remapping):
    def preprocess_data(examples):
        texts = examples["text"]
        encoding = tokenizer(
            texts,
            truncation=True,
            max_length=MAX_LENGTH
        )

        labels_matrix = np.zeros((len(texts), num_labels), dtype=np.float32)

        for i, labels_list in enumerate(examples["label"]):
            remapped_labels = [
                label_remapping[old_id]
                for old_id in labels_list
                if old_id in label_remapping
            ]
            for new_label_id in remapped_labels:
                labels_matrix[i, new_label_id] = 1.0

        encoding["labels"] = labels_matrix.tolist()
        return encoding

    print("\n--- 开始分词与标签编码 ---")
    tokenized = raw_datasets.map(
        preprocess_data,
        batched=True,
        remove_columns=raw_datasets["train"].column_names,
        load_from_cache_file=False
    )
    print("分词与标签编码完成。")
    return tokenized


def compute_pos_weight(train_labels: np.ndarray) -> torch.Tensor:
    pos_counts = train_labels.sum(axis=0)
    neg_counts = len(train_labels) - pos_counts
    pos_weight = neg_counts / (pos_counts + 1e-8)
    return torch.tensor(pos_weight, dtype=torch.float32)


# =========================================================
# 主训练流程
# =========================================================
def main():
    print("=" * 100)
    print("开始单模型多标签分类训练")
    print(f"DEVICE: {DEVICE}")
    print(f"MODEL_TAG: {MODEL_TAG}")
    print(f"MODEL_NAME_OR_PATH: {MODEL_NAME_OR_PATH}")
    print(f"OUTPUT_DIR: {OUTPUT_DIR}")
    print("=" * 100)

    # 固定随机种子
    set_seed(SEED)
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)

    # 1. 加载数据
    raw_datasets = load_raw_datasets(DATA_PATH)

    # 2. 标签管理
    label_manager = LabelManager(csv_path=LABEL_CSV_PATH)
    label_manager.setup_with_removed_ids(removed_ids=REMOVED_IDS)

    num_labels = label_manager.num_labels
    label_remapping = label_manager.label_remapping
    id2label = label_manager.id2label
    label2id = {v: k for k, v in id2label.items()}

    # 3. tokenizer
    print("\n--- 加载 tokenizer ---")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME_OR_PATH)

    # 4. tokenize
    tokenized_datasets = tokenize_datasets(
        raw_datasets=raw_datasets,
        tokenizer=tokenizer,
        num_labels=num_labels,
        label_remapping=label_remapping
    )

    # 5. 计算类别不平衡权重
    print("\n--- 计算 pos_weight ---")
    y_train = np.array(tokenized_datasets["train"]["labels"], dtype=np.float32)
    pos_weight_tensor = compute_pos_weight(y_train)
    print("pos_weight 计算完成。")

    # 6. 设置为 torch 格式
    tokenized_datasets.set_format("torch")

    # 7. 加载模型
    print("\n--- 加载模型 ---")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME_OR_PATH,
        problem_type="multi_label_classification",
        num_labels=num_labels,
        id2label=id2label,
        label2id=label2id,
        ignore_mismatched_sizes=True
    )

    if USE_GRADIENT_CHECKPOINTING:
        model.gradient_checkpointing_enable()
        print("已启用 gradient checkpointing。")

    # 8. 训练参数
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,

        eval_strategy="epoch",
        save_strategy="epoch",

        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=TRAIN_BATCH_SIZE,
        per_device_eval_batch_size=EVAL_BATCH_SIZE,
        num_train_epochs=NUM_EPOCHS,
        weight_decay=WEIGHT_DECAY,

        logging_steps=30,
        load_best_model_at_end=True,
        metric_for_best_model="f1_micro",
        greater_is_better=True,

        save_total_limit=SAVE_TOTAL_LIMIT,
        fp16=USE_FP16,
        seed=SEED,
        data_seed=SEED,

        report_to="none"
        # 如果需要 tensorboard，可改成：
        # report_to="tensorboard"
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    # 9. Trainer
    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["validation"],
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics_for_trainer,
        pos_weight=pos_weight_tensor,
        callbacks=[
            EarlyStoppingCallback(
                early_stopping_patience=EARLY_STOPPING_PATIENCE,
                early_stopping_threshold=EARLY_STOPPING_THRESHOLD
            )
        ]
    )

    # 10. 训练
    print("\n--- 开始训练 ---")
    trainer.train()

    # 11. 在验证集上搜索最佳阈值
    print("\n--- 在验证集上搜索每个标签的最佳阈值 ---")
    val_output = trainer.predict(tokenized_datasets["validation"])
    val_logits = val_output.predictions[0] if isinstance(val_output.predictions, tuple) else val_output.predictions
    val_labels = val_output.label_ids
    val_probs = logits_to_probs(val_logits)
    best_thresholds = find_best_thresholds_per_label_optimized(val_probs, val_labels)

    thresholds_path = os.path.join(OUTPUT_DIR, "best_thresholds.npy")
    np.save(thresholds_path, best_thresholds)
    print(f"最佳阈值已保存到: {thresholds_path}")

    # 12. 测试集评估
    print("\n--- 在测试集上使用验证集阈值进行最终评估 ---")
    test_output = trainer.predict(tokenized_datasets["test"])
    final_test_metrics = evaluate_with_fixed_thresholds(test_output, best_thresholds)

    print("\n最终测试集结果：")
    print(json.dumps(final_test_metrics, ensure_ascii=False, indent=4))

    # 13. 保存测试结果
    result_path = os.path.join(OUTPUT_DIR, "final_test_results.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(final_test_metrics, f, ensure_ascii=False, indent=4)
    print(f"测试结果已保存到: {result_path}")

    # 14. 保存最佳 checkpoint 路径信息
    trainer_state_path = os.path.join(OUTPUT_DIR, "best_checkpoint_info.json")
    best_checkpoint = trainer.state.best_model_checkpoint
    best_score = trainer.state.best_metric

    with open(trainer_state_path, "w", encoding="utf-8") as f:
        json.dump({
            "best_model_checkpoint": best_checkpoint,
            "best_metric": best_score,
            "metric_for_best_model": training_args.metric_for_best_model
        }, f, ensure_ascii=False, indent=4)

    print("\n最佳模型信息：")
    print(json.dumps({
        "best_model_checkpoint": best_checkpoint,
        "best_metric": best_score,
        "metric_for_best_model": training_args.metric_for_best_model
    }, ensure_ascii=False, indent=4))

    # 15. 清理显存
    del trainer
    del model
    del tokenizer
    del tokenized_datasets
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    print("\n训练与评估全部完成。")


if __name__ == '__main__':
    sys.stdout = TeeLogger(LOG_FILE, mode='a')
    try:
        main()
    finally:
        sys.stdout.close()
        sys.stdout = sys.__stdout__
