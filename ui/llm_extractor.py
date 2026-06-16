import json
import os
import re
import torch
import dashscope
from tqdm import tqdm
from typing import List, Dict, Any
from sentence_transformers import SentenceTransformer, util
import time
import requests
from zhipuai import ZhipuAI
class LLMEntityExtractor:
    def __init__(self, api_key: str, kb_path: str = None, use_dynamic_rag: bool = True, model_name: str = 'qwen-plus'):
        """
        :param use_dynamic_rag: 是否开启动态 RAG。如果为 False，则跳过加载 BGE 模型。
        """
        os.environ["DASHSCOPE_API_KEY"] = api_key
        dashscope.api_key = api_key
        self.use_dynamic_rag = use_dynamic_rag
        self.model_name = model_name

        # 1. 根据模式决定是否加载本地 Embedding 模型
        if self.use_dynamic_rag:
            if not kb_path:
                raise ValueError("开启动态 RAG 模式必须提供 kb_path (知识库路径)")

            self.embedding_model = 'BAAI/bge-large-zh-v1.5'
            print(f"模式：[动态 RAG] - 正在加载句向量模型 {self.embedding_model}...")

            kb_data = self._load_knowledge_base(kb_path)
            self.retriever = NERRetriever(model_name=self.embedding_model)
            self.retriever.build_index_from_kb(kb_data)
        else:
            print("模式：[静态 RAG] - 已跳过本地 Embedding 模型加载，节省资源。")
            self.retriever = None

        # 2. 初始化 Prompt 生成器
        self.prompter = PromptGenerator()

    def _load_knowledge_base(self, filepath: str) -> List[Dict[str, Any]]:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            kb = []
            for paragraph in data:
                for sentence in paragraph.get('sentences', []):
                    if 'output' in sentence:
                        kb.append({
                            'text': sentence['sentence_text'],
                            'output': sentence['output'],
                            'entities': sentence.get('entities', [])
                        })
        return kb

    def extract_entities_with_labels(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """主入口：处理 Transformer 预测后的数据列表"""
        indices_to_process = [i for i, item in enumerate(data_list) if 87 not in item.get('id', [])]
        if not indices_to_process: return []

        sentences_to_llm = [data_list[i]['text'] for i in indices_to_process]
        labels_to_llm = [",".join(data_list[i]['label']) for i in indices_to_process]

        # 调用批量提取
        llm_outputs = self.extract_entities_batch(sentences_to_llm, labels_to_llm)

        final_results = []
        for k, idx in enumerate(indices_to_process):
            item = data_list[idx]
            final_results.append({
                'text': item['text'],
                'label': item['label'],
                'entities': llm_outputs[k]
            })
        return final_results

    def extract_entities_batch(self, sentences: List[str], labels: List[str]) -> List[List[Dict[str, str]]]:
        if not sentences: return []

        # 1. 动态检索逻辑 (仅在开启动态 RAG 时执行)
        all_retrieved_examples = []
        if self.use_dynamic_rag and self.retriever:
            all_retrieved_examples = [self.retriever.retrieve(s) for s in sentences]
        else:
            # 静态模式下，传空列表给 prompter，它会自动使用内置静态示例
            all_retrieved_examples = [None] * len(sentences)

        # 2. 构建 Prompt
        prepared_prompts = [
            self.prompter.create_structured_prompt(sentences[i], labels[i], all_retrieved_examples[i])
            for i in range(len(sentences))
        ]

        # 3. 批量调用 API
        raw_outputs = []
        for messages in tqdm(prepared_prompts, desc="LLM 深度提取", leave=False):
            try:
                response = dashscope.Generation.call(
                    model=self.model_name,
                    messages=messages,
                    temperature=0.0,
                    result_format='message'
                )
                raw_outputs.append(
                    response.output.choices[0]['message']['content'] if response.status_code == 200 else "")
            except Exception as e:
                print(f"API Error: {e}")
                raw_outputs.append("")

        return [self._parse_structured_output(out) for out in raw_outputs]

    def _parse_structured_output(self, structured_json_str: str) -> List[Dict[str, str]]:
        final_entities = []
        try:
            json_match = re.search(r'\{.*\}', structured_json_str, re.DOTALL)
            if not json_match: return []
            data = json.loads(json_match.group(0))
            for act in data.get("processing_acts", []):
                if act.get("controller"): final_entities.append({"text": act["controller"], "label": "controller"})
                if act.get("action_verb") and act.get("action_type"):
                    label = act["action_type"].lower()
                    if label in ["collection", "sharing", "other"]:
                        final_entities.append({"text": act["action_verb"], "label": label})
                if act.get("purpose"): final_entities.append({"text": act["purpose"], "label": "purpose"})
                if act.get("condition"): final_entities.append({"text": act["condition"], "label": "condition"})
                if act.get("receiver"): final_entities.append({"text": act["receiver"], "label": "receiver"})
                for data_item in act.get("data_collected_or_shared", []):
                    if data_item: final_entities.append({"text": data_item, "label": "data"})
        except:
            pass
        return final_entities


class LLMEntityExtractor1:

    def __init__(self, config: Dict[str, Any], kb_path: str = None, use_dynamic_rag: bool = True,
                 model_name: str = 'qwen-plus'):
        """
        :param config: 包含 dashscope_api_key, glm_api_key, deepseek_api_key 等的字典。
        :param use_dynamic_rag: 是否开启动态 RAG。
        """
        self.api_keys = config
        self.use_dynamic_rag = use_dynamic_rag
        self.model_name = model_name.lower()  # 统一转为小写便于判断
        # ------------------ 1. API Key 配置 ------------------
        # Qwen/Dashscope 配置
        dashscope_key = config.get('dashscope_api_key')
        if dashscope_key:
            os.environ["DASHSCOPE_API_KEY"] = dashscope_key
            dashscope.api_key = dashscope_key

        # GLM/Zhipu 配置
        glm_key = config.get('glm_api_key')
        if glm_key:
            os.environ["GLM_API_KEY"] = glm_key
            self.glm_client = ZhipuAI(api_key=glm_key)
        else:
            self.glm_client = None
        # Deepseek 配置
        deepseek_key = config.get('deepseek_api_key')
        if deepseek_key:
            os.environ["DEEPSEEK_API_KEY"] = deepseek_key
        # ------------------ 2. RAG/Retriever 配置 ------------------
        if self.use_dynamic_rag:
            if not kb_path:
                raise ValueError("开启动态 RAG 模式必须提供 kb_path (知识库路径)")
            self.embedding_model = 'BAAI/bge-large-zh-v1.5'
            print(f"模式：[动态 RAG] - 正在加载句向量模型 {self.embedding_model}...")
            kb_data = self._load_knowledge_base(kb_path)
            self.retriever = NERRetriever(model_name=self.embedding_model)  # 使用模拟类
            self.retriever.build_index_from_kb(kb_data)
        else:
            print("模式：[静态 RAG] - 已跳过本地 Embedding 模型加载，节省资源。")
            self.retriever = None
        # ------------------ 3. Prompt 配置 ------------------
        self.prompter = PromptGenerator()

    def _load_knowledge_base(self, filepath: str) -> List[Dict[str, Any]]:
        # 这是一个模拟加载，你需要确保文件存在且格式正确
        if not os.path.exists(filepath):
            print(f"警告: 知识库文件 {filepath} 不存在，返回空知识库。")
            return []

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            kb = []
            for paragraph in data:
                for sentence in paragraph.get('sentences', []):
                    if 'output' in sentence:
                        kb.append({
                            'text': sentence['sentence_text'],
                            'output': sentence['output'],
                            'entities': sentence.get('entities', [])
                        })
        return kb

    # --------------------------------------------------------
    # Qwen 批量调用方法
    # --------------------------------------------------------
    def _call_llm_api_batch_qwen(self, prompts: List[List[Dict[str, str]]], stage_name: str) -> List[str]:
        max_retries = 2
        if not os.environ.get("DASHSCOPE_API_KEY"):
            raise ValueError("Qwen模型调用失败：DASHSCOPE_API_KEY 未设置。")
        predictions = []
        print(f"--- 开始执行【{stage_name}】阶段的批量API调用 (Qwen) ---")

        for messages in tqdm(prompts, desc=f"调用Qwen API ({stage_name})"):
            content = ""
            for attempt in range(max_retries):
                try:
                    response = dashscope.Generation.call(
                        model=self.model_name,
                        messages=messages,
                        temperature=0.0,
                        result_format='message'
                    )
                    if response.status_code == 200:
                        content = response.output.choices[0]['message']['content']
                        break
                    else:
                        print(f"\n[API错误] Qwen状态码: {response.status_code}, 错误信息: {response}")
                        if attempt + 1 < max_retries:
                            time.sleep(2 ** attempt)
                except Exception as e:
                    print(f"\n[Qwen API异常] 请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                    if attempt + 1 < max_retries:
                        time.sleep(2 ** attempt)
            predictions.append(content)
        return predictions

    # --------------------------------------------------------
    # Deepseek 批量调用方法
    # --------------------------------------------------------
    def _call_llm_api_batch_deepseek(self, prompts: List[List[Dict[str, str]]], stage_name: str) -> List[str]:
        max_retries = 2
        if not os.environ.get("DEEPSEEK_API_KEY"):
            raise ValueError("Deepseek模型调用失败：DEEPSEEK_API_KEY 未设置。")

        api_key = os.environ["DEEPSEEK_API_KEY"]
        api_url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        predictions = []
        print(f"--- 开始执行【{stage_name}】阶段的批量API调用 (Deepseek) ---")

        for messages in tqdm(prompts, desc=f"调用Deepseek API ({stage_name})"):
            content = ""
            for attempt in range(max_retries):
                try:
                    payload = {
                        "model": self.model_name,
                        "messages": messages,
                        "stream": False,
                        "top_p": 0.95,
                        "temperature": 0.0,
                        # Deepseek 支持 response_format={"type": "json_object"}，这里省略以简化
                    }
                    response = requests.post(api_url, headers=headers, json=payload, timeout=30)

                    if response.status_code == 200:
                        response_data = response.json()
                        content = response_data["choices"][0]["message"]["content"]
                        break
                    else:
                        print(f"\n[API错误] Deepseek状态码: {response.status_code}, 错误信息: {response.text}")
                        if attempt + 1 < max_retries:
                            time.sleep(2 ** attempt)
                except requests.exceptions.RequestException as e:
                    print(f"\n[网络异常] 请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                    if attempt + 1 < max_retries:
                        time.sleep(2 ** attempt)
                except Exception as e:
                    print(f"\n[其他异常] Deepseek请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                    if attempt + 1 < max_retries:
                        time.sleep(2 ** attempt)
            predictions.append(content)
        return predictions

    # --------------------------------------------------------
    # GLM 批量调用方法
    # --------------------------------------------------------
    def _call_llm_api_batch_glm(self, prompts: List[List[Dict[str, str]]], stage_name: str) -> List[str]:
        max_retries = 2
        if not self.glm_client:
            raise ValueError("GLM模型调用失败：GLM客户端未正确初始化。")

        predictions = []
        print(f"--- 开始执行【{stage_name}】阶段的批量API调用 (GLM) ---")
        for messages in tqdm(prompts, desc=f"调用GLM API ({stage_name})"):
            content = ""
            for attempt in range(max_retries):
                try:
                    response = self.glm_client.chat.completions.create(
                        model=self.model_name,
                        messages=messages,
                        temperature=0.0,
                        top_p=0.95,
                        stream=False
                    )

                    if hasattr(response, 'choices') and response.choices:
                        content = response.choices[0].message.content
                        break
                    else:
                        print(f"\n[API错误] GLM响应格式异常: {response}")
                        if attempt + 1 < max_retries:
                            time.sleep(2 ** attempt)
                except Exception as e:
                    print(f"\n[GLM API异常] 请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                    if attempt + 1 < max_retries:
                        time.sleep(2 ** attempt)
            predictions.append(content)
        return predictions

    # --------------------------------------------------------
    # 调度器方法
    # --------------------------------------------------------
    def _dispatch_llm_call(self, prepared_prompts: List[List[Dict[str, str]]]) -> List[str]:
        """根据 self.model_name 调度到对应的 LLM 批量调用函数"""

        if self.model_name.startswith('qwen'):
            return self._call_llm_api_batch_qwen(prepared_prompts, "Qwen")

        elif self.model_name.startswith('glm'):
            return self._call_llm_api_batch_glm(prepared_prompts, "GLM")

        elif self.model_name.startswith('deepseek'):
            return self._call_llm_api_batch_deepseek(prepared_prompts, "Deepseek")

        else:
            raise ValueError(f"不支持的模型名称: {self.model_name}")

    # --------------------------------------------------------
    # 主入口和批量调用函数
    # --------------------------------------------------------
    def extract_entities_with_labels(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """主入口：处理 Transformer 预测后的数据列表"""
        indices_to_process = [i for i, item in enumerate(data_list) if 87 not in item.get('id', [])]
        if not indices_to_process: return []
        sentences_to_llm = [data_list[i]['text'] for i in indices_to_process]
        labels_to_llm = [",".join(data_list[i]['label']) for i in indices_to_process]
        llm_outputs = self.extract_entities_batch(sentences_to_llm, labels_to_llm)
        final_results = []
        for k, idx in enumerate(indices_to_process):
            item = data_list[idx]
            final_results.append({
                'text': item['text'],
                'label': item['label'],
                'entities': llm_outputs[k]
            })
        return final_results

    def extract_entities_batch(self, sentences: List[str], labels: List[str]) -> List[List[Dict[str, str]]]:
        if not sentences: return []
        # 1. 动态检索逻辑
        all_retrieved_examples = []
        if self.use_dynamic_rag and self.retriever:
            all_retrieved_examples = [self.retriever.retrieve(s) for s in sentences]
        else:
            all_retrieved_examples = [None] * len(sentences)
        # 2. 构建 Prompt
        prepared_prompts = [
            self.prompter.create_structured_prompt(sentences[i], labels[i], all_retrieved_examples[i])
            for i in range(len(sentences))
        ]
        # 3. 批量调用 API：使用调度器
        raw_outputs = self._dispatch_llm_call(prepared_prompts)
        return [self._parse_structured_output(out) for out in raw_outputs]

    def _parse_structured_output(self, structured_json_str: str) -> List[Dict[str, str]]:
        final_entities = []
        try:
            # 兼容处理，只提取第一个 JSON 块
            json_match = re.search(r'\{.*\}', structured_json_str, re.DOTALL)
            if not json_match: return []
            data = json.loads(json_match.group(0))

            # 实体解析逻辑 (保持不变)
            for act in data.get("processing_acts", []):
                if act.get("controller"): final_entities.append({"text": act["controller"], "label": "controller"})
                if act.get("action_verb") and act.get("action_type"):
                    label = act["action_type"].lower()
                    if label in ["collection", "sharing", "other"]:
                        final_entities.append({"text": act["action_verb"], "label": label})
                if act.get("purpose"): final_entities.append({"text": act["purpose"], "label": "purpose"})
                if act.get("condition"): final_entities.append({"text": act["condition"], "label": "condition"})
                if act.get("receiver"): final_entities.append({"text": act["receiver"], "label": "receiver"})
                for data_item in act.get("data_collected_or_shared", []):
                    if data_item: final_entities.append({"text": data_item, "label": "data"})
        except Exception as e:
            # print(f"JSON 解析失败: {e}, 原始输出: {structured_json_str[:50]}...")
            pass
        return final_entities

# --- 检索类保持不变 ---
class NERRetriever:
    def __init__(self, model_name: str):
        self.model = SentenceTransformer(model_name)
        self.kb_pos = []
        self.kb_pos_embeddings = None

    def build_index_from_kb(self, kb: List[Dict[str, Any]]):
        self.kb_pos = [s for s in kb if s.get('output')]
        texts = [s['text'] for s in self.kb_pos]
        self.kb_pos_embeddings = self.model.encode(texts, convert_to_tensor=True)

    def retrieve(self, query: str, k: int = 2) -> List[Dict[str, Any]]:
        query_emb = self.model.encode(query, convert_to_tensor=True)
        cos_scores = util.cos_sim(query_emb, self.kb_pos_embeddings)[0]
        top_k = torch.topk(cos_scores, k=min(k, len(self.kb_pos)))
        return [self.kb_pos[i] for i in top_k.indices]


# --- Prompt 生成器支持双模式 ---
class PromptGenerator:
    def __init__(self):
        self.json_schema = """... (保持之前的 JSON 结构定义) ..."""

        # 内置静态金牌示例（当动态 RAG 关闭或检索失败时使用）
        self.static_examples = """
--- 案例 1 ---
句子: 我们会收集您的手机号码、位置信息以提供导航服务。
JSON输出:
{
  "processing_acts": [
    { "action_verb": "收集", "action_type": "Collection", "controller": "我们", "data_collected_or_shared": ["手机号码", "位置信息"], "purpose": "为了提供导航服务" }
  ]
}
--- 案例 2 ---
句子: 经过您的同意，我们会将设备ID共享给第三方SDK。
JSON输出:
{
  "processing_acts": [
    { "action_verb": "共享", "action_type": "Sharing", "controller": "我们", "data_collected_or_shared": ["设备ID"], "receiver": "第三方SDK", "condition": "经过您的同意" }
  ]
}
"""

    def create_structured_prompt(self, sentence: str, label_text: str,
                                 retrieved_examples: List[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        # 如果有检索到的动态示例，则使用动态的；否则使用静态的
        if retrieved_examples:
            examples_str = self._format_examples(retrieved_examples)
        else:
            examples_str = self.static_examples

        system_prompt = f"""
        你是一个信息抽取AI，任务是从句子中提取数据处理行为，并严格按照指定的JSON格式输出。

        # 业务语境 (重要)
        当前句子在隐私政策中的分类标签为: 【{label_text}】。请结合此标签理解句子的真实意图。

        # 核心任务
        1.  **识别行为**: 判断句子是否描述了由“我们”或公司执行的数据处理行为 (如: 收集, 共享, 使用, 存储, 删除)。
        2.  **过滤无关句**: 如果句子只是定义、标题或对第三方的要求，必须输出空JSON: {{"processing_acts": []}}。
        3.  **结构化输出**: 对包含有效行为的句子，填充下面的JSON模板。

        # JSON 输出模板
        {self.json_schema}

        # 关键规则 (必须遵守)
        1.  **行为分类 (`action_type`)**:
            - `Collection`: 从用户处获取数据 (收集, 获取)。
            - `Sharing`: 将数据给第三方 (共享, 提供, 披露)。
            - `Other`: 其他所有操作 (使用, 存储, 分析, 删除)。
        2.  **数据原子化 (`data_collected_or_shared`)**:
            - 必须是JSON列表 `[]`。
            - 原文中的 "A、B和C" 必须拆分为 `["A", "B", "C"]`。
            - 列表中的每项都必须是去除了修饰词（如“您的”）的核心名词。
        3.  **内容真实性**: JSON中所有值都必须是句子原文中一字不差的片段，严禁创造或总结。
        4.  **实体完整性**: `purpose` 和 `condition` 必须是完整的状语短语。

        下面是参考案例：{examples_str}
        """
        user_prompt = f"# 原始句子:\n{sentence}\n\n# 你的最终JSON输出:"
        return [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]

    def _format_examples(self, examples: List[Dict[str, Any]]) -> str:
        formatted = ""
        for i, ex in enumerate(examples):
            structured = self._convert_flat_to_structured(ex['entities'])
            formatted += f"--- 案例 {i + 1} ---\n句子: {ex['text']}\nJSON输出:\n{json.dumps(structured, ensure_ascii=False, indent=2)}\n\n"
        return formatted

    def _convert_flat_to_structured(self, entities: List[Dict[str, str]]) -> Dict:
        if not entities: return {"processing_acts": []}
        act = {"action_verb": None, "action_type": None, "controller": None, "data_collected_or_shared": [],
               "purpose": None, "condition": None, "receiver": None}
        for entity in entities:
            label = entity['label'].lower()
            text = entity['text']
            if label in ['collection', 'sharing', 'other'] and not act['action_verb']:
                act['action_verb'] = text
                act['action_type'] = entity['label'].capitalize()
            elif label == 'controller' and not act['controller']:
                act['controller'] = text
            elif label == 'data':
                act['data_collected_or_shared'].append(text)
            elif label == 'purpose' and not act['purpose']:
                act['purpose'] = text
            elif label == 'condition' and not act['condition']:
                act['condition'] = text
            elif label == 'receiver' and not act['receiver']:
                act['receiver'] = text
        act_cleaned = {k: v for k, v in act.items() if v}
        return {"processing_acts": [act_cleaned]}
if __name__ == "__main__":
    output_dir= "result"
    output_jsonl_path=os.path.join(output_dir, "output_predictions_test.jsonl")
    predicted_data = []
    with open(output_jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            predicted_data.append(json.loads(line.strip()))
    config = {
        'model_path': "G:\\downloads\\fromtencent\\7.27\\models\\roberta-multilabel-classifier-d1-82-9575-05-V1\\checkpoint-25685",
        'csv_label_path': "result/idlable.csv",
        'removed_ids': {6, 7, 8, 9, 10, 11},
        'thresholds_path': "result/optimal_thresholds.npy",
        'dashscope_api_key': os.getenv('DASHSCOPE_API_KEY'),
    }
    llm_extractor = LLMEntityExtractor(
        api_key=config.get('dashscope_api_key') or '',
        use_dynamic_rag=False  # 关闭
    )

    # 3. 执行 LLM 提取 (内部已包含 ID 87 过滤逻辑)
    print("正在利用 LLM 提取深度实体信息...")
    llm_results = llm_extractor.extract_entities_with_labels(predicted_data)

    # --- 新增：保存 LLM 结果到文件 ---
    if output_dir:
        llm_output_path = os.path.join(output_dir, "llm_extraction_results.jsonl")
        with open(llm_output_path, 'w', encoding='utf-8') as f:
            for item in llm_results:
                # 每个 item 包含 text, label 和 entities
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
        print(f"LLM 深度分析结果已保存至: {llm_output_path}")
