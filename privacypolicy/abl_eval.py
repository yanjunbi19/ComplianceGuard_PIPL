"""
NER评估脚本
"""

import re
from collections import defaultdict
import os
from typing import List, Dict, Tuple, Set
import json


class PostProcessor:
    """
    一个独立的类，专门用于实现针对实体列表的后处理规则。
    """
    def __init__(self):
        self.REDUNDANT_PREFIXES = re.compile(
            r"^(您的|你的|您|的|部分|必要的|相关的|一些|某种)\s*"
        )

    def _normalize_text(self, text: str) -> str:
        return self.REDUNDANT_PREFIXES.sub('', text).strip()

    def _split_parallel_phrases(self, entity_tuple: Tuple[str, str]) -> List[Tuple[str, str]]:
        text, label = entity_tuple
        parts = re.split(r'[、，,;和\s]+', text)
        split_tuples = [
            (part.strip(), label) 
            for part in parts if part.strip()
        ]
        return split_tuples

    def process(self, entity_set: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
        normalized_set = {
            (self._normalize_text(text), label)
            for text, label in entity_set
            if self._normalize_text(text)
        }
        final_set = set()
        for entity_tuple in normalized_set:
            final_set.update(self._split_parallel_phrases(entity_tuple))
        return final_set


class DataLoader:
    """
    数据加载器：支持多种输入格式
    """
    
    @staticmethod
    def detect_format(data) -> str:
        """
        自动检测数据格式
        返回: 'paragraph_format' 或 'flat_format'
        """
        if not data:
            return 'unknown'
        
        first_item = data[0]
        
        # 格式1: 段落格式 [{"sentences": [...], ...}, ...]
        if 'sentences' in first_item:
            return 'paragraph_format'
        
        # 格式2: 扁平格式 [{"sentence_text": ..., "ground_truth_entities": ..., "predicted_entities": ...}, ...]
        if 'sentence_text' in first_item and 'predicted_entities' in first_item:
            return 'flat_format'
        
        return 'unknown'
    
    @staticmethod
    def load_paragraph_format(data: List[Dict]) -> List[Dict]:
        """
        加载段落格式数据，直接返回（已经是正确格式）
        """
        return data
    
    @staticmethod
    def load_flat_format(data: List[Dict]) -> List[Dict]:
        """
        将扁平格式转换为段落格式，以便统一处理
        
        输入格式:
        [
            {
                "doc_id": "...",
                "sentence_text": "...",
                "classification_labels": [...],
                "ground_truth_entities": [...],
                "predicted_entities": [...],
                "raw_llm_output": "..."
            },
            ...
        ]
        
        输出格式:
        [
            {
                "sentences": [
                    {
                        "sentence_text": "...",
                        "entities": [...],           # ground truth
                        "predicted_entities": [...]  # predictions
                    }
                ]
            }
        ]
        """
        # 按 doc_id 分组
        doc_groups = defaultdict(list)
        for item in data:
            doc_id = item.get('doc_id', 'default')
            doc_groups[doc_id].append(item)
        
        # 转换为段落格式
        converted_data = []
        for doc_id, items in doc_groups.items():
            paragraph = {
                'doc_id': doc_id,
                'sentences': []
            }
            for item in items:
                sentence = {
                    'sentence_text': item.get('sentence_text', ''),
                    'entities': item.get('ground_truth_entities', []),
                    'predicted_entities': item.get('predicted_entities', []),
                    'classification_labels': item.get('classification_labels', [])
                }
                paragraph['sentences'].append(sentence)
            converted_data.append(paragraph)
        
        return converted_data
    
    @staticmethod
    def load_and_convert(filepath: str) -> List[Dict]:
        """
        加载文件并自动转换为统一的段落格式
        """
        # 检测文件类型 (JSON 或 JSONL)
        with open(filepath, 'r', encoding='utf-8') as f:
            first_char = f.read(1)
            f.seek(0)
            
            if first_char == '[':
                # JSON 数组格式
                data = json.load(f)
            else:
                # JSONL 格式
                data = [json.loads(line) for line in f if line.strip()]
        
        # 检测数据格式并转换
        format_type = DataLoader.detect_format(data)
        print(f"[信息] 检测到数据格式: {format_type}")
        
        if format_type == 'paragraph_format':
            return DataLoader.load_paragraph_format(data)
        elif format_type == 'flat_format':
            return DataLoader.load_flat_format(data)
        else:
            print(f"[警告] 未知数据格式，尝试按段落格式处理")
            return data


def extract_entities_from_list(entity_list: List[Dict]) -> List[tuple[str, str]]:
    """
    从 entities/predicted_entities 的列表中提取实体，返回 (text, label) 元组列表
    """
    extracted = []
    for entity in entity_list:
        text = entity.get("text", "")
        label = entity.get("label", "")
        extracted.append((text, label.lower()))
    return extracted


def find_perfect_matches(data: List[Dict]) -> List[Dict]:
    """
    筛选出 predicted_entities 和 entities 集合完全一致的句子
    """
    perfect_matches = []
    
    for paragraph in data:
        for sentence in paragraph.get("sentences", []):
            gold_entities = extract_entities_from_list(sentence.get("entities", []))
            pred_entities = extract_entities_from_list(sentence.get("predicted_entities", []))
            
            if gold_entities == pred_entities:
                perfect_matches.append({
                    "sentence_text": sentence.get("sentence_text", ""),
                    "original_entities": sentence.get("entities", []),
                    "original_predicted_entities": sentence.get("predicted_entities", []),
                    "matching_entities_count": len(gold_entities)
                })
    
    return perfect_matches


def compute_metrics_new(data: List[Dict], use_postprocessing: bool = True):
    """
    计算评估指标
    """
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    
    if use_postprocessing:
        post_processor = PostProcessor()
    for item in data:
        for sent in item.get('sentences', []):
            golds = sent.get('entities', [])
            preds = sent.get('predicted_entities', [])
            if not golds:
                continue
                
            gold_set = {(g['text'], g['label'].lower()) for g in golds}
            pred_set = {(p['text'], p['label'].lower()) for p in preds}

            if use_postprocessing:
                gold_set = post_processor.process(gold_set)
                pred_set = post_processor.process(pred_set)

            all_labels_in_sent = {label for _, label in gold_set} | {label for _, label in pred_set}

            for t in all_labels_in_sent:
                golds_of_t = {(text, lbl) for text, lbl in gold_set if lbl == t}
                preds_of_t = {(text, lbl) for text, lbl in pred_set if lbl == t}
                tp[t] += len(golds_of_t.intersection(preds_of_t))
                fp[t] += len(preds_of_t - golds_of_t)
                fn[t] += len(golds_of_t - preds_of_t)
    
    # 打印报告
    print(f"\n{'Label':<12} {'Prec':<8} {'Recall':<8} {'F1':<8} {'Support':<8}")
    print("-" * 50)

    total_tp = 0
    total_fp = 0
    total_fn = 0
    macro_ps_list = []
    macro_rs_list = []
    macro_f1s_list = []
    
    all_gold_labels_in_dataset = set()
    for item in data:
        for sent in item.get('sentences', []):
            for entity in sent.get('entities', []):
                all_gold_labels_in_dataset.add(entity['label'].lower())

    sorted_gold_labels = sorted(list(all_gold_labels_in_dataset))
    
    for t in sorted_gold_labels:
        P = tp[t] / (tp[t] + fp[t]) if (tp[t] + fp[t]) > 0 else 0
        R = tp[t] / (tp[t] + fn[t]) if (tp[t] + fn[t]) > 0 else 0
        F1 = 2 * P * R / (P + R) if (P + R) > 0 else 0
        support = tp[t] + fn[t]

        print(f"{t:<12} {P:.4f}   {R:.4f}   {F1:.4f}   {support}")

        macro_ps_list.append(P)
        macro_rs_list.append(R)
        macro_f1s_list.append(F1)
    
    for t in sorted_gold_labels:
        total_tp += tp[t]
        total_fn += fn[t]
    
    total_fp = sum(fp.values())

    micro_P = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    micro_R = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    micro_F1 = 2 * micro_P * micro_R / (micro_P + micro_R) if (micro_P + micro_R) > 0 else 0
    total_support = total_tp + total_fn

    print("-" * 50)
    print(f"{'Micro Avg':<12} {micro_P:.4f}   {micro_R:.4f}   {micro_F1:.4f}   {total_support}")
    
    num_macro_classes = len(sorted_gold_labels)
    macro_avg_p = sum(macro_ps_list) / num_macro_classes if num_macro_classes > 0 else 0
    macro_avg_r = sum(macro_rs_list) / num_macro_classes if num_macro_classes > 0 else 0
    macro_avg_f1 = sum(macro_f1s_list) / num_macro_classes if num_macro_classes > 0 else 0

    print(f"{'Macro Avg':<12} {macro_avg_p:.4f}   {macro_avg_r:.4f}   {macro_avg_f1:.4f}")
    
    return {
        'micro_p': micro_P,
        'micro_r': micro_R,
        'micro_f1': micro_F1,
        'macro_p': macro_avg_p,
        'macro_r': macro_avg_r,
        'macro_f1': macro_avg_f1
    }


def evaluate_single_file(filepath: str, use_postprocessing: bool = True):
    """
    评估单个预测文件
    """
    print(f"\n{'='*60}")
    print(f"评估文件: {filepath}")
    print(f"{'='*60}")
    
    try:
        data = DataLoader.load_and_convert(filepath)
        print(f"[信息] 加载完成，共 {len(data)} 个段落")
        
        # 统计句子数
        total_sentences = sum(len(item.get('sentences', [])) for item in data)
        print(f"[信息] 共 {total_sentences} 个句子")
        
        return compute_metrics_new(data, use_postprocessing=use_postprocessing)
        
    except FileNotFoundError:
        print(f"[错误] 文件未找到: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"[错误] JSON解析失败: {e}")
        return None
    except Exception as e:
        print(f"[错误] 处理失败: {e}")
        return None

def evaluate_all_ablation_files(results_dir: str, use_postprocessing: bool = True):
    """
    评估目录下所有消融实验文件并生成汇总对比
    
    文件命名约定: label{0,1}_rag{0,1}_filter{0,1}.json
    """
    import glob
    
    # 查找所有结果文件
    pattern = os.path.join(results_dir, "label*_rag*_filter*.json")
    files = glob.glob(pattern)
    
    if not files:
        print(f"[错误] 在 {results_dir} 中未找到匹配的文件")
        return
    
    print("\n" + "#" * 70)
    print("# 消融实验完整评估")
    print(f"# 目录: {results_dir}")
    print(f"# 后处理: {'启用' if use_postprocessing else '禁用'}")
    print("#" * 70)
    
    # 存储所有结果
    all_results = {}
    
    # 逐个评估
    for filepath in sorted(files):
        filename = os.path.basename(filepath)
        # 解析配置
        # 格式: label0_rag1_filter0.json
        parts = filename.replace(".json", "").split("_")
        config = {}
        for part in parts:
            if part.startswith("label"):
                config["label"] = int(part[5:])
            elif part.startswith("rag"):
                config["rag"] = int(part[3:])
            elif part.startswith("filter"):
                config["filter"] = int(part[6:])
        
        config_str = f"label={config.get('label', '?')}, rag={config.get('rag', '?')}, filter={config.get('filter', '?')}"
        
        print("\n" + "=" * 70)
        print(f"评估文件: {filepath}")
        print(f"配置: {config_str}")
        print("=" * 70)
        
        metrics = evaluate_single_file(filepath, use_postprocessing)
        
        if metrics:
            all_results[filename] = {
                "config": config,
                "metrics": metrics
            }
    
    # 打印汇总对比表
    if all_results:
        print("\n" + "#" * 70)
        print("# 汇总对比表")
        print("#" * 70)
        
        # 表头
        header = f"{'配置':<35} {'Micro P':<10} {'Micro R':<10} {'Micro F1':<10} {'Macro F1':<10}"
        print("\n" + header)
        print("-" * 75)
        
        # 按 Micro F1 排序
        sorted_results = sorted(
            all_results.items(),
            key=lambda x: x[1]["metrics"].get("micro_f1", 0),
            reverse=True
        )
        
        best_f1 = sorted_results[0][1]["metrics"]["micro_f1"] if sorted_results else 0
        
        for filename, data in sorted_results:
            config = data["config"]
            metrics = data["metrics"]
            
            # 构建配置描述
            label_str = "标签" if config.get("label") == 1 else "无标签"
            rag_str = "RAG" if config.get("rag") == 1 else "无RAG"
            filter_str = "过滤" if config.get("filter") == 1 else "无过滤"
            config_desc = f"{label_str}+{rag_str}+{filter_str}"
            
            micro_f1 = metrics.get("micro_f1", 0)
            diff = micro_f1 - best_f1
            diff_str = f"({diff:+.2%})" if diff != 0 else "(最优)"
            
            row = f"{config_desc:<25} {diff_str:<10} {metrics.get('micro_p', 0):<10.4f} {metrics.get('micro_r', 0):<10.4f} {micro_f1:<10.4f} {metrics.get('macro_f1', 0):<10.4f}"
            print(row)
        
        # 分析各因素影响
        print("\n" + "=" * 70)
        print("因素影响分析")
        print("=" * 70)
        
        analyze_factor_impact(all_results, "label", "标签引导")
        analyze_factor_impact(all_results, "rag", "RAG示例")
        analyze_factor_impact(all_results, "filter", "句子过滤")


def analyze_factor_impact(all_results: dict, factor: str, factor_name: str):
    """分析单个因素的影响"""
    
    # 收集启用和禁用该因素的所有结果
    enabled = []
    disabled = []
    
    for filename, data in all_results.items():
        config = data["config"]
        f1 = data["metrics"].get("micro_f1", 0)
        
        if config.get(factor) == 1:
            enabled.append(f1)
        elif config.get(factor) == 0:
            disabled.append(f1)
    
    if enabled and disabled:
        avg_enabled = sum(enabled) / len(enabled)
        avg_disabled = sum(disabled) / len(disabled)
        diff = avg_enabled - avg_disabled
        
        effect = "正向" if diff > 0.005 else ("负向" if diff < -0.005 else "无显著")
        print(f"\n{factor_name}:")
        print(f"  启用时平均 F1: {avg_enabled:.4f} (n={len(enabled)})")
        print(f"  禁用时平均 F1: {avg_disabled:.4f} (n={len(disabled)})")
        print(f"  差异: {diff:+.4f} ({diff*100:+.2f}%)")
        print(f"  效果: {effect}")


def evaluate_ablation_experiment(file_a: str, file_b: str, use_postprocessing: bool = True):
    """
    评估消融实验：对比两个文件
    """
    print("\n" + "=" * 60)
    print(f"====== 评估文件 A - {'应用后处理' if use_postprocessing else '无后处理'} ======")
    print("=" * 60)
    
    metrics_a = evaluate_single_file(file_a, use_postprocessing)
    
    print("\n" + "=" * 60)
    print(f"====== 评估文件 B - {'应用后处理' if use_postprocessing else '无后处理'} ======")
    print("=" * 60)
    
    metrics_b = evaluate_single_file(file_b, use_postprocessing)
    
    # 打印对比总结
    if metrics_a and metrics_b:
        print("\n" + "=" * 60)
        print("====== 对比总结 ======")
        print("=" * 60)
        
        print(f"\n{'指标':<18} {'文件A':<12} {'文件B':<12} {'差异':<12}")
        print("-" * 54)
        
        for metric_name, display_name in [
            ('micro_p', 'Micro Precision'),
            ('micro_r', 'Micro Recall'),
            ('micro_f1', 'Micro F1'),
            ('macro_p', 'Macro Precision'),
            ('macro_r', 'Macro Recall'),
            ('macro_f1', 'Macro F1')
        ]:
            val_a = metrics_a.get(metric_name, 0)
            val_b = metrics_b.get(metric_name, 0)
            diff = val_a - val_b
            diff_str = f"{diff:+.4f}"
            print(f"{display_name:<18} {val_a:<12.4f} {val_b:<12.4f} {diff_str:<12}")


if __name__ == "__main__":
    import sys
    
    # 默认目录
    RESULTS_DIR = "/workspace/ablation_results_v4"
    filepath="./ner/predictions_deepseek_structured_rag_2_yes.json"
    evaluate_single_file(filepath, use_postprocessing=True)
    
    
    #evaluate_all_ablation_files(RESULTS_DIR, use_postprocessing=True)

    print("  python eval_ner.py <results_dir>           # 评估目录下所有文件")
    print("  python eval_ner.py <file_a> <file_b>       # 对比两个文件")
    print("  python eval_ner.py <single_file>           # 评估单个文件")
