"""
消融实验
- 并发API调用
- 保留原始完整Prompt
"""

import json
import os
import time
import asyncio
import aiohttp
from typing import List, Dict, Any, Tuple
from tqdm.asyncio import tqdm_asyncio
from tqdm import tqdm
import re
import numpy as np
import torch
from sentence_transformers import SentenceTransformer, util

# --- 配置 ---
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_DIR, "data")
NER_DIR = os.path.join(PROJECT_DIR, "ner")
DEEPSEEK_API_KEY = "sk-962515b077c14685b2fd469c823e980e"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1/chat/completions"

INPUT_FILE = os.path.join(NER_DIR, "cleaned_test_data_v2_yes.json")
KNOWLEDGE_BASE_FILE = os.path.join(NER_DIR, "cleaned_train_data_v3.json")
OUTPUT_DIR = "ablation_results_v4"

# 并发配置
MAX_CONCURRENT = 15
REQUEST_TIMEOUT = 60

# RAG配置
EMBEDDING_MODEL = 'BAAI/bge-large-zh-v1.5'
TOP_K_POSITIVE = 3
TOP_K_NEGATIVE = 1
THRESHOLD_HIGH = 0.91
THRESHOLD_LOW = 0.80

# 过滤配置
SKIP_LABELS = [
    "其他",
]


class NERRetriever:
    """RAG检索器"""
    
    def __init__(self, model_name: str = EMBEDDING_MODEL):
        print("加载句向量模型...")
        self.model = SentenceTransformer(model_name)
        self.kb_positive = []
        self.kb_positive_emb = None
        self.kb_negative = []
        self.kb_negative_emb = None

    def load_and_build(self, filepath: str):
        print(f"加载知识库: {filepath}")
        kb = []
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for para in data:
                for sent in para.get('sentences', []):
                    if 'output' in sent:
                        kb.append({
                            'text': sent['sentence_text'],
                            'output': sent['output'],
                            'entities': sent.get('entities', [])
                        })
        
        self.kb_positive = [s for s in kb if s.get('output')]
        self.kb_negative = [s for s in kb if not s.get('output')]
        
        print(f"正例: {len(self.kb_positive)}, 反例: {len(self.kb_negative)}")
        
        if self.kb_positive:
            texts = [s['text'] for s in self.kb_positive]
            self.kb_positive_emb = self.model.encode(texts, convert_to_tensor=True, 
                                                      show_progress_bar=True, batch_size=64)
        
        if self.kb_negative:
            texts = [s['text'] for s in self.kb_negative]
            self.kb_negative_emb = self.model.encode(texts, convert_to_tensor=True,
                                                      show_progress_bar=True, batch_size=64)

    def retrieve(self, query: str) -> List[Dict]:
        if self.kb_positive_emb is None:
            return []
        
        q_emb = self.model.encode(query, convert_to_tensor=True)
        scores = util.cos_sim(q_emb, self.kb_positive_emb)[0]
        max_score = torch.max(scores).item()
        
        if max_score > THRESHOLD_HIGH:
            k_pos, k_neg = TOP_K_POSITIVE, 0
        elif max_score > THRESHOLD_LOW:
            k_pos, k_neg = TOP_K_POSITIVE - 1, TOP_K_NEGATIVE
        else:
            k_pos, k_neg = 1, TOP_K_NEGATIVE
        
        results = []
        
        if k_pos > 0:
            k = min(k_pos, len(self.kb_positive))
            indices = np.argpartition(-scores.cpu().numpy(), range(k))[:k]
            results.extend([self.kb_positive[i] for i in indices])
        
        if k_neg > 0 and self.kb_negative_emb is not None:
            neg_scores = util.cos_sim(q_emb, self.kb_negative_emb)[0]
            k = min(k_neg, len(self.kb_negative))
            indices = np.argpartition(-neg_scores.cpu().numpy(), range(k))[:k]
            results.extend([self.kb_negative[i] for i in indices])
        
        return results
class AsyncLLMClient:
    """异步LLM客户端"""
    
    JSON_SCHEMA = """{
  "processing_acts": [
    {
      "action_verb": "执行操作的核心动词 (如: 收集, 共享)",
      "action_type": "从 [Collection, Sharing, Other] 中选择一个",
      "controller": "执行该操作的主体 (我们/公司名)",
      "data_collected_or_shared": ["原子化的数据项1", "原子化的数据项2"],
      "purpose": "完整的目的状语",
      "condition": "完整的条件状语",
      "receiver": "完整的接收方名称 (如果是Sharing)"
    }
  ]
}"""

    def __init__(self, api_key: str, max_concurrent: int = MAX_CONCURRENT):
        self.api_key = api_key
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def format_rag_examples(self, examples: List[Dict]) -> str:
        """格式化RAG检索到的示例"""
        if not examples:
            return ""
        
        formatted = ""
        for i, ex in enumerate(examples, 1):
            formatted += f"\n## 示例 {i}\n"
            formatted += f"**输入句子**: {ex['text']}\n"
            
            if ex.get('output'):
                formatted += f"**标准输出**: {ex['output']}\n"
            elif ex.get('entities'):
                entities_str = ", ".join([f"{e['label']}:{e['text']}" for e in ex['entities'][:5]])
                formatted += f"**提取的实体**: {entities_str}\n"
            else:
                formatted += f"**标准输出**: {{\"processing_acts\": []}}\n"
        
        return formatted

    def build_prompt(self, sentence: str, labels: List[str] = None, 
                     rag_examples: List[Dict] = None,
                     use_labels: bool = True, use_rag: bool = True) -> List[Dict]:
        """构建提示词 - 唯一的prompt构建方法"""
        
        # 标签部分
        label_section = ""
        if use_labels and labels and len(labels) > 0:
            labels_str = "、".join(labels)
            label_section = f"""
# 重要上下文信息
这个句子在隐私政策中的宏观主题是：【{labels_str}】。请基于这个主题理解并执行以下任务。
"""
        
        # RAG部分
        rag_section = ""
        if use_rag and rag_examples:
            rag_section = self.format_rag_examples(rag_examples)
        
        system_prompt = f"""你是一个隐私政策信息抽取AI。你的任务是从句子中提取数据处理行为，并严格按照JSON格式输出。
{label_section}
# JSON 输出模板
{self.JSON_SCHEMA}

# 关键规则
1. **行为分类 (action_type)**:
   - `Collection`: 从用户处获取数据 (收集, 获取, 读取)
   - `Sharing`: 将数据给第三方 (共享, 提供, 披露, 转让)
   - `Other`: 其他所有操作 (使用, 存储, 分析, 删除)

2. **数据原子化 (data_collected_or_shared)**:
   - 必须是JSON列表 []
   - 原文中的 "A、B和C" 必须拆分为 ["A", "B", "C"]
   - 每项都必须是去除修饰词的核心名词

3. **内容真实性**: 所有值必须是句子原文中的片段，严禁创造或总结

4. **空结果处理**: 如果句子不包含任何数据处理行为，输出: {{"processing_acts": []}}
{rag_section}"""
        
        user_prompt = f"""# 原始句子:
{sentence}

# 你的JSON输出:"""

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

    async def call_single(self, session: aiohttp.ClientSession, 
                          messages: List[Dict], idx: int) -> Tuple[int, str, float]:
        """单次异步调用"""
        async with self.semaphore:
            start = time.time()
            payload = {
                "model": "deepseek-chat",
                "messages": messages,
                "temperature": 0.0,
                "max_tokens": 1024
            }
            
            for attempt in range(3):
                try:
                    async with session.post(
                        DEEPSEEK_BASE_URL,
                        headers=self.headers,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            output = data['choices'][0]['message']['content']
                            return idx, output, time.time() - start
                        elif resp.status == 429:
                            wait_time = 2 ** attempt
                            print(f"[{idx}] 速率限制，等待 {wait_time}s")
                            await asyncio.sleep(wait_time)
                        else:
                            text = await resp.text()
                            print(f"[{idx}] HTTP {resp.status}: {text[:100]}")
                            return idx, "", time.time() - start
                except asyncio.TimeoutError:
                    print(f"[{idx}] 超时，重试 {attempt+1}/3")
                except Exception as e:
                    print(f"[{idx}] 错误: {e}")
                    if attempt < 2:
                        await asyncio.sleep(1)
            
            return idx, "", time.time() - start
    
    async def call_batch(self, tasks: List[Tuple[int, List[Dict]]]) -> Dict[int, Tuple[str, float]]:
        """批量异步调用"""
        async with aiohttp.ClientSession() as session:
            coroutines = [self.call_single(session, msgs, idx) for idx, msgs in tasks]
            results = {}
            
            for coro in tqdm_asyncio.as_completed(coroutines, total=len(coroutines), desc="LLM调用"):
                idx, output, elapsed = await coro
                results[idx] = (output, elapsed)
            
            return results

def parse_output(raw: str) -> List[Dict]:
    """解析LLM输出，提取实体"""
    entities = []
    try:
        # 提取JSON部分
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if not match:
            return []
        
        data = json.loads(match.group(0))
        
        for act in data.get("processing_acts", []):
            # controller
            if act.get("controller"):
                entities.append({"text": act["controller"], "label": "controller"})
            
            # action_verb + action_type
            if act.get("action_verb") and act.get("action_type"):
                action_type = act["action_type"].lower()
                if action_type == "collection":
                    entities.append({"text": act["action_verb"], "label": "collection"})
                elif action_type == "sharing":
                    entities.append({"text": act["action_verb"], "label": "sharing"})
                else:
                    entities.append({"text": act["action_verb"], "label": "other"})
            
            # purpose
            if act.get("purpose"):
                entities.append({"text": act["purpose"], "label": "purpose"})
            
            # condition
            if act.get("condition"):
                entities.append({"text": act["condition"], "label": "condition"})
            
            # receiver
            if act.get("receiver"):
                entities.append({"text": act["receiver"], "label": "receiver"})
            
            # data_collected_or_shared
            for item in act.get("data_collected_or_shared", []):
                if item:
                    entities.append({"text": item, "label": "data"})
    except json.JSONDecodeError:
        pass
    except Exception:
        pass
    
    return entities


def should_skip(labels: List[str]) -> bool:
    """判断是否跳过该句子"""
    for label in labels:
        for skip in SKIP_LABELS:
            if skip.lower() in label.lower():
                return True
    return False


def load_data(filepath: str) -> List[Dict]:
    """加载数据"""
    print(f"加载数据: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        if filepath.lower().endswith(".json"):
            data = json.load(f)
            print(f"共 {len(data)} 个段落")
            return data

        data = []
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    print(f"共 {len(data)} 个段落")
    return data


def flatten_sentences(data: List[Dict]) -> List[Dict]:
    """展平句子"""
    sentences = []
    for para in data:
        doc_id = para.get('doc_id', '')
        for sent in para.get('sentences', []):
            sentences.append({
                'doc_id': doc_id,
                'sentence_text': sent.get('sentence_text', ''),
                'classification_labels': sent.get('classification_labels', []),
                'ground_truth_entities': sent.get('entities', []),
            })
    return sentences


async def run_condition_async(sentences: List[Dict], retriever,
                               use_labels: bool, use_rag: bool, use_filter: bool,
                               output_file: str) -> Tuple[List[Dict], Dict]:
    """异步运行单个实验条件"""
    
    client = AsyncLLMClient(DEEPSEEK_API_KEY)
    
    # 准备任务
    tasks = []  # (idx, messages)
    results = [None] * len(sentences)
    
    stats = {
        'total_sentences': len(sentences),
        'filtered_count': 0,
        'llm_calls': 0,
        'total_time': 0.0
    }
    
    config_desc = f"标签={'是' if use_labels else '否'}, RAG={'是' if use_rag else '否'}, 过滤={'是' if use_filter else '否'}"
    print(f"\n{'='*60}")
    print(f"运行条件: {config_desc}")
    print(f"{'='*60}")
    
    for idx, sent in enumerate(tqdm(sentences, desc="准备Prompt")):
        text = sent['sentence_text']
        labels = sent['classification_labels']
        
        # 过滤检查
        if use_filter and should_skip(labels):
            stats['filtered_count'] += 1
            results[idx] = {
                'doc_id': sent.get('doc_id', ''),
                'sentence_text': text,
                'classification_labels': labels,
                'ground_truth_entities': sent['ground_truth_entities'],
                'predicted_entities': [],
                'raw_llm_output': '{"processing_acts": []}  // FILTERED'
            }
            continue
        
        # RAG检索
        rag_examples = []
        if use_rag and retriever:
            try:
                rag_examples = retriever.retrieve(text)
            except Exception as e:
                print(f"[警告] RAG检索失败: {e}")
        
        # 创建Prompt
        messages = client.build_prompt(text, labels, rag_examples, use_labels, use_rag)
        tasks.append((idx, messages))
    
    stats['llm_calls'] = len(tasks)
    print(f"需调用LLM: {len(tasks)}, 已过滤: {stats['filtered_count']}")
    
    # 批量调用
    if tasks:
        start_time = time.time()
        llm_results = await client.call_batch(tasks)
        stats['total_time'] = time.time() - start_time
        
        # 填充结果
        for idx, (output, elapsed) in llm_results.items():
            sent = sentences[idx]
            pred_entities = parse_output(output)
            
            results[idx] = {
                'doc_id': sent.get('doc_id', ''),
                'sentence_text': sent['sentence_text'],
                'classification_labels': sent['classification_labels'],
                'ground_truth_entities': sent['ground_truth_entities'],
                'predicted_entities': pred_entities,
                'raw_llm_output': output
            }
    
    # 保存结果（纯列表格式，参数在文件名中）
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"保存: {output_file}")
    print(f"耗时: {stats['total_time']:.1f}s, 平均: {stats['total_time']/max(1,stats['llm_calls']):.2f}s/句")
    
    return results, stats


def evaluate(results: List[Dict]) -> Dict:
    """评估结果"""
    label_stats = {}
    
    for r in results:
        if r is None:
            continue
            
        gt = {(e['text'], e['label'].lower()) for e in r.get('ground_truth_entities', [])}
        pred = {(e['text'], e['label'].lower()) for e in r.get('predicted_entities', [])}
        
        all_labels = set([e[1] for e in gt] + [e[1] for e in pred])
        
        for label in all_labels:
            if label not in label_stats:
                label_stats[label] = {'tp': 0, 'fp': 0, 'fn': 0}
            
            gt_l = {e for e in gt if e[1] == label}
            pred_l = {e for e in pred if e[1] == label}
            
            label_stats[label]['tp'] += len(gt_l & pred_l)
            label_stats[label]['fp'] += len(pred_l - gt_l)
            label_stats[label]['fn'] += len(gt_l - pred_l)
    
    total_tp = sum(s['tp'] for s in label_stats.values())
    total_fp = sum(s['fp'] for s in label_stats.values())
    total_fn = sum(s['fn'] for s in label_stats.values())
    
    micro_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    micro_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) > 0 else 0
    
    f1_list = []
    for s in label_stats.values():
        p = s['tp'] / (s['tp'] + s['fp']) if (s['tp'] + s['fp']) > 0 else 0
        r = s['tp'] / (s['tp'] + s['fn']) if (s['tp'] + s['fn']) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        f1_list.append(f1)
    
    macro_f1 = sum(f1_list) / len(f1_list) if f1_list else 0
    
    return {
        'micro_precision': micro_p,
        'micro_recall': micro_r,
        'micro_f1': micro_f1,
        'macro_f1': macro_f1,
    }


async def main_async():
    """主函数"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 加载数据
    data = load_data(INPUT_FILE)
    sentences = flatten_sentences(data)
    print(f"总句子数: {len(sentences)}")
    
    # 加载RAG检索器
    retriever = None
    if os.path.exists(KNOWLEDGE_BASE_FILE):
        retriever = NERRetriever()
        retriever.load_and_build(KNOWLEDGE_BASE_FILE)
    else:
        print(f"[警告] 知识库文件不存在: {KNOWLEDGE_BASE_FILE}")
        print("[警告] RAG功能将被禁用")
    
    # 实验条件: (文件名, use_labels, use_rag, use_filter)
    # 实验条件: (文件名, use_labels, use_rag, use_filter)
    conditions = [
        ("label0_rag0_filter0", False, False, False),  # 基线：无标签、无RAG、无过滤
        ("label1_rag0_filter0", True,  False, False),  # 仅标签
        ("label0_rag1_filter0", False, True,  False),  # 仅RAG
        ("label1_rag1_filter0", True,  True,  False),  # 标签+RAG
        ("label1_rag1_filter1", True,  True,  True),   # 完整方案：标签+RAG+过滤
    ]
    
    all_evals = {}
    all_stats = {}
    
    for name, use_labels, use_rag, use_filter in conditions:
        output_file = os.path.join(OUTPUT_DIR, f"{name}.json")
        
        results, stats = await run_condition_async(
            sentences=sentences,
            retriever=retriever,
            use_labels=use_labels,
            use_rag=use_rag,
            use_filter=use_filter,
            output_file=output_file
        )
        
        ev = evaluate(results)
        all_evals[name] = ev
        all_stats[name] = stats
        
        print(f"\n{name} 评估结果:")
        print(f"  Micro P: {ev['micro_precision']:.4f}")
        print(f"  Micro R: {ev['micro_recall']:.4f}")
        print(f"  Micro F1: {ev['micro_f1']:.4f}")
        print(f"  Macro F1: {ev['macro_f1']:.4f}")
    
    # 打印汇总表格
    print("\n" + "=" * 100)
    print("消融实验汇总")
    print("=" * 100)
    print(f"{'条件':<25} {'Micro P':<10} {'Micro R':<10} {'Micro F1':<10} {'Macro F1':<10} {'LLM调用':<10} {'过滤':<8} {'时间(s)':<10}")
    print("-" * 100)
    
    for name, _, _, _ in conditions:
        ev = all_evals[name]
        st = all_stats[name]
        print(f"{name:<25} {ev['micro_precision']:<10.4f} {ev['micro_recall']:<10.4f} "
              f"{ev['micro_f1']:<10.4f} {ev['macro_f1']:<10.4f} "
              f"{st['llm_calls']:<10} {st['filtered_count']:<8} {st['total_time']:<10.1f}")
    
    # 保存汇总结果
    summary = {
        "evaluations": all_evals, 
        "stats": all_stats,
        "conditions": {name: {"use_labels": ul, "use_rag": ur, "use_filter": uf} 
                       for name, ul, ur, uf in conditions}
    }
    summary_file = os.path.join(OUTPUT_DIR, "summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    
    print(f"\n汇总已保存: {summary_file}")
    
    # 打印消融分析
    print("\n" + "=" * 100)
    print("消融分析")
    print("=" * 100)
    
    baseline_f1 = all_evals["label0_rag0_filter0"]["micro_f1"]
    
    print(f"\n基线 (无标签、无RAG、无过滤): Micro F1 = {baseline_f1:.4f}")
    
    # 标签的增益
    label_only_f1 = all_evals["label1_rag0_filter0"]["micro_f1"]
    label_gain = label_only_f1 - baseline_f1
    print(f"\n+标签: Micro F1 = {label_only_f1:.4f} (增益: {label_gain:+.4f})")
    
    # RAG的增益
    rag_only_f1 = all_evals["label0_rag1_filter0"]["micro_f1"]
    rag_gain = rag_only_f1 - baseline_f1
    print(f"+RAG:  Micro F1 = {rag_only_f1:.4f} (增益: {rag_gain:+.4f})")
    
    # 标签+RAG的增益
    label_rag_f1 = all_evals["label1_rag1_filter0"]["micro_f1"]
    label_rag_gain = label_rag_f1 - baseline_f1
    print(f"+标签+RAG: Micro F1 = {label_rag_f1:.4f} (增益: {label_rag_gain:+.4f})")
    
    # 完整方案的增益
    full_f1 = all_evals["label1_rag1_filter1"]["micro_f1"]
    full_gain = full_f1 - baseline_f1
    print(f"+标签+RAG+过滤: Micro F1 = {full_f1:.4f} (增益: {full_gain:+.4f})")
    
    # 效率分析
    print("\n" + "-" * 50)
    print("效率分析")
    print("-" * 50)
    
    baseline_calls = all_stats["label0_rag0_filter0"]["llm_calls"]
    filtered_calls = all_stats["label1_rag1_filter1"]["llm_calls"]
    filtered_count = all_stats["label1_rag1_filter1"]["filtered_count"]
    
    if baseline_calls > 0:
        reduction = (baseline_calls - filtered_calls) / baseline_calls * 100
        print(f"过滤减少的LLM调用: {baseline_calls} -> {filtered_calls} (减少 {reduction:.1f}%)")
        print(f"被过滤的句子数: {filtered_count}")


def main():
    """同步入口"""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
