import re
from collections import defaultdict
import os
from typing import List, Dict, Tuple, Set
import json
class PostProcessor:

    def __init__(self):
        # 规则1 & 2: 定义需要移除的冗余前缀 (人称代词和修饰词)
        self.REDUNDANT_PREFIXES = re.compile(
            r"^(您的|你的|您|的|部分|必要的|相关的|一些|某种)\s*"
        )

    def _normalize_text(self, text: str) -> str:

        return self.REDUNDANT_PREFIXES.sub('', text).strip()

    def _split_parallel_phrases(self, entity_tuple: Tuple[str, str]) -> List[Tuple[str, str]]:

        text, label = entity_tuple
        # 按中文顿号、中英文逗号、分号或“和”进行拆分
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


def extract_entities_from_list(entity_list: List[Dict]) -> List[tuple[str, str]]:

    extracted = []
    for entity in entity_list:
        text = entity.get("text", "")
        label = entity.get("label", "")
        # 仅对预测实体的label做小写转换
        extracted.append((text, label.lower()))
    return extracted


def find_perfect_matches(data: List[Dict]) -> List[Dict]:

    perfect_matches = []
    
    for paragraph in data:
        for sentence in paragraph.get("sentences", []):
            # 提取真实实体和预测实体，转换为集合
            gold_entities = extract_entities_from_list(sentence.get("entities", []))
            pred_entities = extract_entities_from_list(sentence.get("predicted_entities", []))
            
            # 集合比较（忽略顺序）
            if gold_entities == pred_entities:
                perfect_matches.append({
                    "sentence_text": sentence.get("sentence_text", ""),
                    "original_entities": sentence.get("entities", []),
                    "original_predicted_entities": sentence.get("predicted_entities", []),
                    "matching_entities_count": len(gold_entities)  # 匹配的实体数量
                })
    
    return perfect_matches


def getall_perfect_matches(json_file_path: str, output_file_path: str) -> None:

    try:
        # 从JSON文件读取数据
        with open(json_file_path, 'r', encoding='utf-8') as f:
            sample_data = json.load(f)
        print(f"成功从 {json_file_path} 加载数据，共 {len(sample_data)} 个段落")
        
        # 筛选完全匹配的句子
        perfect_matches = find_perfect_matches(sample_data)
        print(f"共找到 {len(perfect_matches)} 个完全匹配的句子")
        
        # 保存结果到指定输出文件
        with open(output_file_path, "w", encoding="utf-8") as f:
            json.dump(perfect_matches, f, ensure_ascii=False, indent=2)
        print(f"结果已保存至 {output_file_path}")
    
    except FileNotFoundError:
        print(f"错误：未找到文件 {json_file_path}，请检查路径是否正确")
    except json.JSONDecodeError:
        print(f"错误：文件 {json_file_path} 不是有效的JSON格式")
    except Exception as e:
        print(f"处理过程中发生未知错误：{str(e)}")

def get_ner_predict_new():
    """
    加载数据并运行评估，可以轻松对比有无后处理的效果。
    """
    try:
        with open("./ner/predictions_deepseek_structured_rag_2_yes.json", "r", encoding="utf-8") as f:
        #with open("./ner/predictions_glm_structured_rag_2_yes.json", "r", encoding="utf-8") as f:
        #with open("./ner/predictions_qwenplus_structured_rag_2_yes.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("错误：预测文件未找到。")
        return
    except json.JSONDecodeError:
        print("错误：预测文件不是有效的JSON。")
        return

    print("--- 评估报告 ---")
    compute_metrics_new(data, use_postprocessing=True)


def compute_metrics_new(data, use_postprocessing: bool = True):

    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    
    if use_postprocessing:
        post_processor = PostProcessor()

    for item in data:
        for sent in item['sentences']:
            golds = sent.get('entities', [])
            preds = sent.get('predicted_entities', [])
            if not golds:
                continue
            gold_set = {(g['text'], g['label'].lower()) for g in golds} # 统一小写
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

    print(f"\n{'Label':<12} {'Prec':<8} {'Recall':<8} {'F1':<8} {'Support':<8}")
    print("-" * 50)

    total_tp = 0
    total_fp = 0
    total_fn = 0
    macro_f1s = []
    macro_ps_list = []
    macro_rs_list = []
    macro_f1s_list = []

    all_gold_labels_in_dataset = set()
    for item in data:
        for sent in item['sentences']:
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


   

def convert_predicted_to_output_format(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                print(f"成功从 {input_file} 读取数据")
            except json.JSONDecodeError:
                print(f"错误：{input_file} 不是有效的JSON文件")
                return  # JSON无效，直接终止，避免后续报错
    except FileNotFoundError:
        print(f"错误：找不到输入文件 {input_file}，请检查路径是否正确")
        return
    except PermissionError:
        print(f"错误：没有读取 {input_file} 的权限")
        return
    except Exception as e:
        print(f"读取文件时发生未知错误：{str(e)}")
        return
    for paragraph in data:
        for sentence in paragraph.get("sentences", []):
            predicted_entities = sentence.get("predicted_entities", [])
            formatted_entities = []
            
            for entity in predicted_entities:
                text = entity.get("text", "").strip()
                label = entity.get("label", "").strip().lower()
                if text and label:
                    formatted_entities.append(f"【{text}|{label}】")

            predicted_output = ", ".join(formatted_entities)
            sentence["predicted_entities"] = predicted_output

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)  # 修复：用data代替未定义的converted_data
        print(f"转换完成，结果已保存至 {output_file}")
    except PermissionError:
        print(f"错误：没有写入 {output_file} 的权限")
    except Exception as e:
        print(f"保存文件时发生未知错误：{str(e)}")


def filter_sentences_with_entities(input_file: str, output_file: str) -> None:
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                print(f"✅ 成功从 {input_file} 读取数据，共包含 {len(data)} 个段落")
            except json.JSONDecodeError:
                print(f"❌ 错误：{input_file} 不是有效的JSON格式，请检查文件内容")
                return
    except FileNotFoundError:
        print(f"❌ 错误：未找到输入文件 {input_file}，请确认路径正确")
        return
    except PermissionError:
        print(f"❌ 错误：没有读取 {input_file} 的权限，请检查文件权限")
        return
    except Exception as e:
        print(f"❌ 读取文件时发生未知错误：{str(e)}")
        return


    filtered_data = []
    total_original_sentences = 0
    total_filtered_sentences = 0

    for paragraph in data:

        filtered_paragraph = paragraph.copy()
        original_sentences = paragraph.get("sentences", [])
        total_original_sentences += len(original_sentences)

        filtered_sentences = []
        for sent in original_sentences:
            sent_output = sent.get("output", "").strip()
            if sent_output:  # 仅保留output非空的句子
                filtered_sentences.append(sent)
                total_filtered_sentences += 1

        filtered_paragraph["sentences"] = filtered_sentences
        filtered_data.append(filtered_paragraph)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=2)
        print(f"\n✅ 筛选完成！")
        print(f"📊 统计：原始句子总数 {total_original_sentences}，筛选后保留句子数 {total_filtered_sentences}")
        print(f"💾 结果已保存至 {output_file}")
    except PermissionError:
        print(f"❌ 错误：没有写入 {output_file} 的权限，请检查文件权限")
    except Exception as e:
        print(f"❌ 保存文件时发生未知错误：{str(e)}")



if __name__ == "__main__":

    get_ner_predict_new()
