'''
实体抽取
'''

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set

import dashscope
import torch
from sentence_transformers import SentenceTransformer, util
from tqdm import tqdm

EMBEDDING_MODEL = "BAAI/bge-large-zh-v1.5"
os.environ["DASHSCOPE_API_KEY"] = "sk-xxxxxxxxxxxxxx"

class FileProcessor:
    def __init__(
        self,
        filepath: Path,
        root_dir: Path,
        output_dir: Path,
        excluded_ids: Set[int],
    ):
        self.filepath = filepath
        self.relative_path = filepath.relative_to(root_dir)
        self.output_filepath = output_dir / self.relative_path
        self.excluded_ids = excluded_ids

        self.all_sentences_data: List[Dict[str, Any]] = []
        self.sentences_to_predict: List[str] = []
        self.macro_categories_to_predict: List[str] = []
        self.indices_to_predict: List[int] = []

    def load_and_filter(self) -> None:
        print(f"  正在处理文件: {self.filepath}")

        with self.filepath.open("r", encoding="utf-8") as f:
            for line_number, line in enumerate(f):
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                try:
                    data = json.loads(stripped_line)
                except json.JSONDecodeError:
                    print(f"    [警告] 跳过无效 JSON 行: {stripped_line}")
                    continue

                self.all_sentences_data.append(data)
                local_index = len(self.all_sentences_data) - 1

                sentence_ids = data.get("id", [])
                sentence_labels = data.get("label", [])
                sentence_text = data.get("text", "")

                if not isinstance(sentence_ids, list):
                    print(
                        f"    [警告] 原文件行号 {line_number} 的 id 字段不是列表，将跳过预测。"
                    )
                    continue

                if not isinstance(sentence_labels, list):
                    print(
                        f"    [警告] 原文件行号 {line_number} 的 label 字段不是列表，将使用默认宏观主题。"
                    )
                    sentence_labels = []

                if not isinstance(sentence_text, str) or not sentence_text.strip():
                    print(
                        f"    [警告] 原文件行号 {line_number} 的 text 字段为空或不是字符串，将跳过预测。"
                    )
                    continue

                should_predict = not self.excluded_ids.intersection(sentence_ids)

                if should_predict:
                    macro_category = "、".join(str(label) for label in sentence_labels)
                    if not macro_category:
                        macro_category = "未标注"

                    self.sentences_to_predict.append(sentence_text)
                    self.macro_categories_to_predict.append(macro_category)
                    self.indices_to_predict.append(local_index)

    def save_with_predictions(
        self,
        predictions: List[List[Dict[str, str]]],
    ) -> None:
        self.output_filepath.parent.mkdir(parents=True, exist_ok=True)
        prediction_iter = iter(predictions)
        indices_to_predict_set = set(self.indices_to_predict)

        for local_index, sentence_data in enumerate(self.all_sentences_data):
            if local_index in indices_to_predict_set:
                try:
                    sentence_data["predicted_entities"] = next(prediction_iter)
                except StopIteration:
                    print(
                        f"[警告] 预测结果数量少于预期，文件 {self.filepath} 中索引 {local_index} 之后的待预测句子将写入空列表。"
                    )
                    sentence_data["predicted_entities"] = []
            else:
                sentence_data["predicted_entities"] = []

        try:
            next(prediction_iter)
            print(f"[警告] 文件 {self.filepath} 的预测结果数量多于待预测句子数量。")
        except StopIteration:
            pass

        with self.output_filepath.open("w", encoding="utf-8") as f:
            for sentence_data in self.all_sentences_data:
                f.write(json.dumps(sentence_data, ensure_ascii=False) + "\n")

        print(f"  结果已保存到: {self.output_filepath}")


def load_knowledge_base(filepath: str) -> List[Dict[str, Any]]:
    print(f"正在从 '{filepath}' 加载知识库...")
    knowledge_base: List[Dict[str, Any]] = []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    for paragraph in data:
        for sentence in paragraph.get("sentences", []):
            if "output" in sentence:
                knowledge_base.append(
                    {
                        "text": sentence["sentence_text"],
                        "output": sentence["output"],
                        "entities": sentence.get("entities", []),
                    }
                )

    print(f"知识库加载完成，共 {len(knowledge_base)} 条带标注的句子。")
    return knowledge_base


class NERRetriever:
    def __init__(self, model_name: str = EMBEDDING_MODEL):
        print("正在加载句向量模型...")
        self.model = SentenceTransformer(model_name)
        self.knowledge_base_positive: List[Dict[str, Any]] = []
        self.knowledge_base_positive_embeddings = None
        print("模型加载完成。")

    def build_index_from_kb(self, knowledge_base: List[Dict[str, Any]]) -> None:
        self.knowledge_base_positive = [item for item in knowledge_base if item.get("output")]

        if not self.knowledge_base_positive:
            raise ValueError("知识库中没有任何有实体的正例，无法构建索引。")

        positive_texts = [item["text"] for item in self.knowledge_base_positive]
        print(f"正在为 {len(positive_texts)} 个正例句子创建向量索引...")
        self.knowledge_base_positive_embeddings = self.model.encode(
            positive_texts,
            convert_to_tensor=True,
            show_progress_bar=True,
            batch_size=64,
        )
        print("索引构建完成（仅正例）。")

    def retrieve(self, query_sentence: str, k: int = 2) -> List[Dict[str, Any]]:
        if self.knowledge_base_positive_embeddings is None:
            raise ValueError("索引尚未构建，请先调用 build_index_from_kb() 方法。")

        query_embedding = self.model.encode(query_sentence, convert_to_tensor=True)
        cos_scores = util.cos_sim(
            query_embedding,
            self.knowledge_base_positive_embeddings,
        )[0]
        top_k_results = torch.topk(
            cos_scores,
            k=min(k, len(self.knowledge_base_positive)),
        )
        return [
            self.knowledge_base_positive[index]
            for index in top_k_results.indices.tolist()
        ]


class PromptGenerator:
    json_schema = """
{
  "processing_acts": [
    {
      "action_verb": "执行操作的核心动词 (如: 收集, 共享)",
      "action_type": "从 [Collection, Sharing, Other] 中选择一个",
      "controller": "执行该操作的主体 (我们/公司名)",
      "data_collected_or_shared": [
        "原子化的数据项1",
        "原子化的数据项2"
      ],
      "purpose": "完整的目的状语",
      "condition": "完整的条件状语",
      "receiver": "接收方 (仅 Sharing 提取)"
    }
  ]
}
"""

    def _format_examples_for_structured_prompt(
        self,
        examples: List[Dict[str, Any]],
    ) -> str:
        formatted_examples: List[str] = []

        for index, example in enumerate(examples, start=1):
            if not example.get("output"):
                continue

            structured_example = self._convert_flat_to_structured(
                example.get("entities", [])
            )
            formatted_examples.append(
                "\n".join(
                    [
                        f"--- 案例 {index} ---",
                        f"句子: {example['text']}",
                        "JSON 输出:",
                        json.dumps(
                            structured_example,
                            ensure_ascii=False,
                            indent=2,
                        ),
                    ]
                )
            )

        return "\n\n".join(formatted_examples)

    def _convert_flat_to_structured(
        self,
        entities: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        if not entities:
            return {"processing_acts": []}

        act: Dict[str, Any] = {
            "action_verb": None,
            "action_type": None,
            "controller": None,
            "data_collected_or_shared": [],
            "purpose": None,
            "condition": None,
            "receiver": None,
        }

        for entity in entities:
            label = entity["label"].lower()
            text = entity["text"]

            if label in ["collection", "sharing", "other"] and not act["action_verb"]:
                act["action_verb"] = text
                act["action_type"] = entity["label"].capitalize()
            elif label == "controller" and not act["controller"]:
                act["controller"] = text
            elif label == "data":
                act["data_collected_or_shared"].append(text)
            elif label == "purpose" and not act["purpose"]:
                act["purpose"] = text
            elif label == "condition" and not act["condition"]:
                act["condition"] = text
            elif label == "receiver" and not act["receiver"]:
                act["receiver"] = text

        cleaned_act = {key: value for key, value in act.items() if value}
        return {"processing_acts": [cleaned_act]}

    def create_structured_prompt(
        self,
        sentence: str,
        macro_category: str,
        retrieved_examples: List[Dict[str, Any]],
        context_paragraph: str = "",
    ) -> List[Dict[str, str]]:
        formatted_examples = self._format_examples_for_structured_prompt(
            retrieved_examples
        )

        system_prompt = f"""你是一个信息提取助手，任务是从句子中提取数据处理行为，并严格按照指定的 JSON 格式输出。这个句子在隐私政策中的宏观主题是：{macro_category}。请基于这个主题理解并执行以下任务。

核心任务
1. 识别行为：判断句子是否描述了由“我们”或公司执行的数据处理行为（如：收集、共享、使用、存储、删除）。
2. 输出模板如下：
{self.json_schema}

关键规则
1. 一句多行为：如果一个句子描述了多个独立的处理行为，请在 processing_acts 列表中为每一个行为创建一个独立的 JSON 对象。
2. 行为分类：Collection：从用户处获取数据（收集、获取）；Sharing：将数据给第三方（共享、提供、披露）；Other：其他所有操作（存储、使用、删除）。
3. 数据原子化：data_collected_or_shared 必须是 JSON 列表；列表中的每项都必须是去除了修饰词（如“您的”）的核心名词。
4. 内容真实性：JSON 中所有值都必须是待提取的目标句子原文中一字不差的片段，严禁从段落上下文中直接提取内容，也严禁创造或总结。
5. 实体完整性：purpose 和 condition 必须是完整的状语短语。"""

        user_prompt = f"""下面是参考案例：
{formatted_examples}

段落上下文：{context_paragraph}
待提取的目标句子：{sentence}
你的最终 JSON 输出："""

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]


class StructuredNerPipeline:
    def __init__(self, knowledge_base_path: str):
        print("--- 初始化结构化实体抽取管道 ---")
        knowledge_base = load_knowledge_base(knowledge_base_path)
        self.retriever = NERRetriever()
        self.retriever.build_index_from_kb(knowledge_base)
        self.prompter = PromptGenerator()

    def _call_llm_api_batch(
        self,
        prompts: List[List[Dict[str, str]]],
        stage_name: str,
    ) -> List[str]:
        api_key = os.environ.get("DASHSCOPE_API_KEY")
        if not api_key:
            raise ValueError("环境变量 DASHSCOPE_API_KEY 未设置。")

        dashscope.api_key = api_key
        predictions: List[str] = []

        print(f"--- 开始执行【{stage_name}】阶段的批量 API 调用 ---")
        for messages in tqdm(prompts, desc=f"调用 API ({stage_name})"):
            content = ""
            try:
                response = dashscope.Generation.call(
                    model="qwen-plus",
                    messages=messages,
                    stream=False,
                    temperature=0.0,
                    result_format="message",
                )
                if response.status_code == 200:
                    content = response.output.choices[0]["message"]["content"]
                else:
                    print(
                        f"\n[API 错误] 状态码: {response.status_code}, 错误信息: {response.message}"
                    )
            except Exception as exc:
                print(f"\n[网络异常] 请求失败: {exc}")

            predictions.append(content)

        return predictions

    def _parse_structured_output(
        self,
        structured_json_str: str,
    ) -> List[Dict[str, str]]:
        final_entities: List[Dict[str, str]] = []

        try:
            json_match = re.search(r"\{.*\}", structured_json_str, re.DOTALL)
            if not json_match:
                return []

            data = json.loads(json_match.group(0))

            for act in data.get("processing_acts", []):
                if act.get("controller"):
                    final_entities.append(
                        {"text": act["controller"], "label": "controller"}
                    )

                if act.get("action_verb") and act.get("action_type"):
                    label = act["action_type"].lower()
                    if label in ["collection", "sharing", "other"]:
                        final_entities.append(
                            {"text": act["action_verb"], "label": label}
                        )

                if act.get("purpose"):
                    final_entities.append(
                        {"text": act["purpose"], "label": "purpose"}
                    )

                if act.get("condition"):
                    final_entities.append(
                        {"text": act["condition"], "label": "condition"}
                    )

                if act.get("receiver"):
                    final_entities.append(
                        {"text": act["receiver"], "label": "receiver"}
                    )

                for data_item in act.get("data_collected_or_shared", []):
                    if data_item:
                        final_entities.append({"text": data_item, "label": "data"})

        except (json.JSONDecodeError, TypeError, AttributeError):
            return []

        return final_entities

    def predict_batch(
        self,
        sentences: List[str],
        macro_categories: List[str],
    ) -> List[List[Dict[str, str]]]:
        if not sentences:
            return []

        if len(sentences) != len(macro_categories):
            raise ValueError("句子数量与宏观主题数量不一致。")

        retrieved_examples = [
            self.retriever.retrieve(sentence)
            for sentence in tqdm(sentences, desc="RAG 检索", leave=False)
        ]

        prepared_prompts = [
            self.prompter.create_structured_prompt(
                sentence=sentences[index],
                macro_category=macro_categories[index],
                retrieved_examples=retrieved_examples[index],
                context_paragraph="",
            )
            for index in range(len(sentences))
        ]

        raw_predictions = self._call_llm_api_batch(
            prepared_prompts,
            stage_name="Normalizer",
        )

        return [
            self._parse_structured_output(prediction)
            for prediction in tqdm(raw_predictions, desc="解析结果", leave=False)
        ]


def main() -> None:
    project_dir = Path(__file__).resolve().parent
    train_file = str(project_dir / "ner" / "cleaned_train_data_v3.json")
    data_root_dir = "/workspace/predict/result"
    output_dir = "/workspace/predict/ner"
    excluded_ids = {87}

    pipeline = StructuredNerPipeline(knowledge_base_path=train_file)

    root_path = Path(data_root_dir)
    if not root_path.is_dir():
        raise FileNotFoundError(f"指定的根目录不存在: {data_root_dir}")

    all_jsonl_files = list(root_path.rglob("*.jsonl"))
    print(f"在 '{data_root_dir}' 中发现 {len(all_jsonl_files)} 个 .jsonl 文件待处理。")

    for filepath in tqdm(all_jsonl_files, desc="处理文件"):
        file_processor = FileProcessor(
            filepath=filepath,
            root_dir=root_path,
            output_dir=Path(output_dir),
            excluded_ids=excluded_ids,
        )
        file_processor.load_and_filter()

        if file_processor.sentences_to_predict:
            predictions = pipeline.predict_batch(
                sentences=file_processor.sentences_to_predict,
                macro_categories=file_processor.macro_categories_to_predict,
            )
        else:
            predictions = []
            print(f"  文件 {filepath.name} 中没有需要预测的句子，跳过 LLM 调用。")

        file_processor.save_with_predictions(predictions)

    print("\n所有文件处理完毕！")


if __name__ == "__main__":
    main()
