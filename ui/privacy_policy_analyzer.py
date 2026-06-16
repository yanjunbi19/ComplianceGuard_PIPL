import re
from bs4 import BeautifulSoup
from datetime import datetime
import os
import json
import csv
import json
import re
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from tqdm import tqdm
from llm_extractor import LLMEntityExtractor1



class PrivacyPolicyConverter:
    def __init__(self):
        self.special_chars = {
            '&nbsp;': ' ',
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#39;': "'",
            '\u00A0': ' ',
            '\u3000': ' ',
            '\t': ' ',
        }
        self.tables = []  # 用于存储所有表格数据，格式为列表的列表
        self.emphasized_texts = []  # 存储所有<b>/<strong>文本

    def clean_special_chars(self, text):
        for char, replacement in self.special_chars.items():
            text = text.replace(char, replacement)
        return text

    def extract_emphasized(self, soup):
        """提取所有<b>和<strong>标签内的文本"""
        emphasized = []
        for tag in soup.find_all(['b', 'strong']):
            text = tag.get_text(strip=True)
            if text:
                emphasized.append(text)
        return emphasized

    def process_table(self, table_tag):
        """提取表格数据为二维列表"""
        table_data = []
        # 表头
        headers = [th.get_text(strip=True) for th in table_tag.find_all('th')]
        if headers:
            table_data.append(headers)

        # 表体行
        for tr in table_tag.find_all('tr'):
            row = [td.get_text(strip=True) for td in tr.find_all(['td', 'th'])]
            if row:
                table_data.append(row)

        self.tables.append(table_data)

        # 返回文本，保留简单换行分隔，方便纯文本显示
        row_texts = []
        for row in table_data:
            row_texts.append('\t'.join(row))
        return '\n'.join(row_texts) + '\n\n'

    def extract_text(self, tag):
        if tag.name == 'table':
            return self.process_table(tag)

        ignore_tags = {'script', 'style', 'link', 'meta', 'title', 'head'}
        if tag.name in ignore_tags:
            return ''

        text_parts = []
        for child in tag.contents:
            if isinstance(child, str):
                cleaned = self.clean_special_chars(child)
                if cleaned.strip():
                    text_parts.append(cleaned)
            else:
                child_text = self.extract_text(child)
                if child_text.strip():
                    text_parts.append(child_text)
                    if child.name in {'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'tr'}:
                        text_parts.append('\n')
        return ''.join(text_parts).strip()

    def convert(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')

        # 提取强调文本
        self.emphasized_texts = self.extract_emphasized(soup)

        body = soup.body if soup.body else soup
        raw_text = self.extract_text(body)
        if not raw_text.strip():
            raw_text = self._fallback_extract_text(soup, html_content)

        # 清理多余空白和换行
        text = raw_text.strip()
        return text

    def _fallback_extract_text(self, soup, html_content):
        text = soup.get_text('\n', strip=True)
        if text.strip():
            return text

        candidates = []
        for match in re.finditer(r'["\']([^"\']{12,})["\']', html_content):
            value = match.group(1)
            if re.search(r'[\u4e00-\u9fff]', value):
                try:
                    value = bytes(value, 'utf-8').decode('unicode_escape')
                except Exception:
                    pass
                value = self.clean_special_chars(value)
                value = re.sub(r'\\[nrt]', '\n', value)
                value = re.sub(r'<[^>]+>', '', value)
                value = value.strip()
                if value and re.search(r'[\u4e00-\u9fff]', value):
                    candidates.append(value)
        return '\n'.join(candidates)

    def convert_file(self, input_path, output_txt_path, output_csv_dir, output_emphasized_path):
        # 读取文件
        with open(input_path, 'r', encoding='utf-8') as f:
            html_content = f.read()

        text = self.convert(html_content)

        # 写纯文本
        with open(output_txt_path, 'w', encoding='utf-8') as f:
            f.write(text)

        # 写表格CSV文件，按表格数分别保存
        for idx, table_data in enumerate(self.tables, 1):
            csv_path = os.path.join(output_csv_dir, f"{os.path.splitext(os.path.basename(input_path))[0]}_table_{idx}.csv")
            os.makedirs(output_csv_dir, exist_ok=True)
            with open(csv_path, 'w', encoding='utf-8', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(table_data)
            print(f"保存表格CSV: {csv_path}")

        # 写强调文本文件
        with open(output_emphasized_path, 'w', encoding='utf-8') as f:
            for line in self.emphasized_texts:
                f.write(line + '\n')
        print(f"保存强调内容: {output_emphasized_path}")

        return text

class TXTSentenceToJSONL:
    """简化版分句逻辑，只暴露分句功能"""

    def __init__(self):
        self.html_tag_regex = re.compile(r'<[^>]+>', re.UNICODE)
        self.format_mark_regex = re.compile(r'【[^】]+】')
        self.extra_space_regex = re.compile(r' +')

        self.hierarchy_num_regex = re.compile(r'^\d+(\.\d+)*$')
        self.hierarchy_num_with_dot_regex = re.compile(r'^\d+(\.\d+)*\.$')
        self.list_item_regex = re.compile(r'^(\(\d+\)|\d+\)|\([a-zA-Z]\)|[a-zA-Z]\)|^\d+、)$')
        self.max_char_len = 450

    def clean_single_line(self, line):
        no_tag = self.html_tag_regex.sub('', line)
        no_format = self.format_mark_regex.sub('', no_tag)
        no_extra_space = self.extra_space_regex.sub(' ', no_format)
        return no_extra_space.strip()

    def merge_number_with_content(self, lines):
        merged = []
        i = 0
        while i < len(lines):
            current = lines[i].strip()
            if not current:
                merged.append(current)
                i += 1
                continue

            # 当前行是否是编号行
            is_hierarchy_num = self.hierarchy_num_regex.match(current)
            is_hierarchy_num_with_dot = self.hierarchy_num_with_dot_regex.match(current)
            is_list_item = self.list_item_regex.match(current)
            is_single_num = current.replace('.', '').isdigit()

            if (is_hierarchy_num or is_hierarchy_num_with_dot or is_list_item or is_single_num) and i + 1 < len(lines):
                next_line = lines[i + 1].strip()

                # 下一行是否编号行
                next_is_hierarchy_num = self.hierarchy_num_regex.match(next_line)
                next_is_hierarchy_num_with_dot = self.hierarchy_num_with_dot_regex.match(next_line)
                next_is_list_item = self.list_item_regex.match(next_line)
                next_is_single_num = next_line.replace('.', '').isdigit()

                # 如果下一行不是编号，合并
                if next_line and not (
                        next_is_hierarchy_num or next_is_hierarchy_num_with_dot or next_is_list_item or next_is_single_num):
                    merged.append(f"{current} {next_line}")
                    i += 2
                    continue

            # 不合并，直接添加
            merged.append(current)
            i += 1

        return merged

    def truncate_long_sentences_no_tokenizer(self, sentences):
        processed_sents = []
        split_pattern = re.compile(r'([。；！？])')

        for sent in sentences:
            clean_sent = sent.strip()
            if not clean_sent:
                continue
            if len(clean_sent) <= self.max_char_len:
                processed_sents.append(clean_sent)
                continue

            split_parts = split_pattern.split(clean_sent)
            semantic_units = []
            for i in range(0, len(split_parts) - 1, 2):
                content = split_parts[i].strip()
                punct = split_parts[i + 1]
                if content:
                    semantic_units.append(f"{content}{punct}")
            if len(split_parts) % 2 != 0:
                last_content = split_parts[-1].strip()
                if last_content:
                    semantic_units.append(last_content)

            for unit in semantic_units:
                if len(unit) <= self.max_char_len:
                    processed_sents.append(unit)
                else:
                    truncated = unit[:self.max_char_len].rstrip()
                    processed_sents.append(truncated)

        return processed_sents

    def split_sentences(self, raw_text):
        raw_lines = raw_text.split('\n')
        cleaned_lines = [self.clean_single_line(line) for line in raw_lines]
        merged_lines = self.merge_number_with_content(cleaned_lines)
        final_sentences = self.truncate_long_sentences_no_tokenizer(merged_lines)
        return [line for line in final_sentences if line.strip()]


class LabelManager:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self._load_all_labels()
        self.reverse_label_remapping = None
        self.reset()

    def _load_all_labels(self):
        self.all_labels_info = []
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            for i, row in enumerate(reader):
                full_id_str = row[0].strip()
                name = row[1].strip()
                self.all_labels_info.append({
                    "original_index": i,
                    "id_str": full_id_str,
                    "name": name
                })
        self.original_num_labels = len(self.all_labels_info)

    def reset(self):
        self.setup_with_removed_ids(set())

    def setup_with_removed_ids(self, removed_ids: set):
        # 过滤被移除标签
        self.retained_labels_info = [
            info for info in self.all_labels_info if info["original_index"] not in removed_ids
        ]
        # 原始ID到新ID映射
        self.label_remapping = {
            info["original_index"]: new_id for new_id, info in enumerate(self.retained_labels_info)
        }
        # 新ID到标签名映射
        self.id2label = {new_id: info["name"] for new_id, info in enumerate(self.retained_labels_info)}
        self.num_labels = len(self.retained_labels_info)

        self.reverse_label_remapping = {v: k for k, v in self.label_remapping.items()}


def apply_per_label_thresholds(probs, thresholds):
    return (probs >= thresholds).astype(int)


class PrivacyPolicyClassification:
    def __init__(self,
                 model_path,
                 csv_label_path,
                 removed_label_ids,
                 thresholds_path=None,
                 device=None,
                 batch_size=64):
        """
        Args:
            model_path: 预训练模型路径
            csv_label_path: 标签CSV文件路径
            removed_label_ids: 训练中移除的标签索引集合
            thresholds_path: npy阈值文件路径，若传入则加载，否则默认0.5阈值
            device: 设备，默认自动选择
            batch_size: 预测批大小
        """
        self.device = device if device else ("cuda:0" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size

        # 标签管理器
        self.label_manager = LabelManager(csv_label_path)
        self.label_manager.setup_with_removed_ids(removed_label_ids)

        # 加载模型和分词器
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True).to(self.device)
        self.model.eval()

        # 加载阈值
        if thresholds_path:
            self.best_thresholds = np.load(thresholds_path)
            print(f"阈值加载自：{thresholds_path}")
            if len(self.best_thresholds) != self.label_manager.num_labels:
                raise ValueError("阈值维度与标签数不匹配！")
        else:
            self.best_thresholds = np.full(self.label_manager.num_labels, 0.5)
            print("未提供阈值文件，使用默认0.5阈值")

    def _filter_texts_from_jsonl(self, jsonl_path):
        filtered_texts = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                item = json.loads(line)
                text = item.get('text', '').strip()
                # 过滤单独序号行和含制表符行
                if re.fullmatch(r'(\d+(\.\d+)*\.?|\(\d+\)|[a-zA-Z]\))', text) and len(text) <= 5:
                    continue
                if '\t' in text:
                    continue
                if not text:
                    continue
                filtered_texts.append(text)
        return filtered_texts

    def predict(self, input_jsonl_path):
        texts = self._filter_texts_from_jsonl(input_jsonl_path)
        if not texts:
            raise ValueError(
                "未从隐私政策文件中提取到可分析文本。请确认选择的是包含正文的HTML文件；"
                "如果该页面依赖JavaScript动态渲染，请先在浏览器中另存为完整网页或导出为静态HTML。"
            )
        all_probs = []
        for i in tqdm(range(0, len(texts), self.batch_size), desc="推理中"):
            batch_texts = texts[i:i+self.batch_size]
            encodings = self.tokenizer(batch_texts, padding=True, truncation=True, max_length=512, return_tensors="pt")
            input_ids = encodings['input_ids'].to(self.device)
            attention_mask = encodings['attention_mask'].to(self.device)
            with torch.no_grad():
                logits = self.model(input_ids=input_ids, attention_mask=attention_mask).logits
                probs = torch.sigmoid(logits).cpu().numpy()
                all_probs.append(probs)
        all_probs = np.vstack(all_probs)
        preds = apply_per_label_thresholds(all_probs, self.best_thresholds)
        results = []
        for text, pred in zip(texts, preds):
            new_label_ids = [i for i, v in enumerate(pred) if v == 1]
            # 反查原始标签ID
            original_label_ids = [self.label_manager.reverse_label_remapping[i] for i in new_label_ids]
            labels = [self.label_manager.id2label[i] for i in new_label_ids]
            results.append({
                "text": text,
                "id": original_label_ids,
                "label": labels  # 标签名称
            })
        return results

    def predict_and_save(self, input_jsonl_path, output_jsonl_path):
        results = self.predict(input_jsonl_path)
        with open(output_jsonl_path, 'w', encoding='utf-8') as fout:
            for item in results:
                fout.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"预测结果已保存至 {output_jsonl_path}")


class PrivacyPolicyAnalyzer:
    def __init__(self, html_path, output_dir=None):
        self.html_path = html_path
        self.output_dir = output_dir  # 新增输出目录参数，默认可传None不保存
        self.content = ""
        self.sentences = []
        self.analysis_result = {}

        self.converter = PrivacyPolicyConverter()
        self.sentence_splitter = TXTSentenceToJSONL()

        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)

    @classmethod
    def default_config(cls):
        ui_dir = os.path.dirname(os.path.abspath(__file__))
        workspace_dir = os.path.dirname(ui_dir)
        return {
            'model_path': os.path.join(workspace_dir, 'Explorer', 'basemodel', 'checkpoint-25685'),
            'csv_label_path': os.path.join(ui_dir, 'res', 'idlable.csv'),
            'removed_ids': {6, 7, 8, 9, 10, 11},
            'thresholds_path': os.path.join(ui_dir, 'res', 'optimal_thresholds.npy'),
            'batch_size': 64,
            'device': None,
            'reuse_predictions': True,
            'llm': {
                'enabled': False,
                'model_name': 'glm-4-plus',
                'use_dynamic_rag': False,
                'kb_path': None,
                'reuse_cache': True,
                'api_keys': {
                    'dashscope': None,
                    'glm': None,
                    'deepseek': None,
                },
            },
            'dynamic_explorer': {
                'script_path': os.path.join(workspace_dir, 'Explorer', 'explore33.py'),
                'leak_analyzer_script': os.path.join(workspace_dir, 'Explorer', 'anal5.py'),
                'run_leak_analysis': True,
                'leak_analysis_timeout_sec': 300,
                'algo': 'sac',
                'iterations': 50,
                'episods': 1,
                'stage': 2,
                'platform_version': '12',
                'udid': 'a6a635a42b72c75b',
                'device_name': 'Pixel5',
                'apps_explored': os.path.join(workspace_dir, 'Explorer', 'apps', 'testapp_end'),
                'layout_model': None,
                'memory_capacity': 32,
                'num_actions': 200,
            },
            'ui': {
                'analysis_order': ['policy', 'static', 'dynamic'],
            },
        }

    @classmethod
    def load_config(cls, config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return cls._normalize_config(json.load(f))

    @classmethod
    def _normalize_config(cls, config):
        """Support both the original flat dict and a classifier/llm JSON config."""
        defaults = cls.default_config()
        if config is None:
            return defaults
        if isinstance(config, (str, os.PathLike)):
            return cls.load_config(config)

        classifier_section = config.get('classifier', config)
        for key in (
            'model_path', 'csv_label_path', 'removed_ids', 'thresholds_path',
            'batch_size', 'device', 'reuse_predictions'
        ):
            if key in classifier_section:
                defaults[key] = classifier_section[key]
        defaults['removed_ids'] = set(defaults.get('removed_ids', []))

        llm_config = dict(defaults['llm'])
        llm_config.update(config.get('llm', {}))
        default_api_keys = dict(defaults['llm'].get('api_keys', {}))
        configured_api_keys = llm_config.get('api_keys') or {}
        default_api_keys.update(configured_api_keys)

        # Support old keys placed directly under "llm".
        direct_key_aliases = {
            'dashscope_api_key': 'dashscope',
            'glm_api_key': 'glm',
            'deepseek_api_key': 'deepseek',
        }
        for old_key, new_key in direct_key_aliases.items():
            if llm_config.get(old_key):
                default_api_keys[new_key] = llm_config[old_key]
        llm_config['api_keys'] = default_api_keys

        # Backward compatibility for an old flat DashScope config.
        if config.get('dashscope_api_key'):
            llm_config['enabled'] = True
            llm_config['api_keys']['dashscope'] = config['dashscope_api_key']
        defaults['llm'] = llm_config

        dynamic_explorer = dict(defaults['dynamic_explorer'])
        dynamic_explorer.update(config.get('dynamic_explorer', {}))
        defaults['dynamic_explorer'] = dynamic_explorer

        ui_config = dict(defaults['ui'])
        ui_config.update(config.get('ui', {}))
        defaults['ui'] = ui_config
        return defaults

    @staticmethod
    def _read_jsonl(path):
        rows = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    @staticmethod
    def _write_jsonl(path, rows):
        with open(path, 'w', encoding='utf-8') as f:
            for item in rows:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')

    def _read_llm_cache(self, llm_output_path):
        if not os.path.exists(llm_output_path):
            return None
        if os.path.getsize(llm_output_path) == 0:
            print(f"检测到 LLM 实体提取缓存为空，将重新分析: {llm_output_path}")
            return None
        try:
            rows = self._read_jsonl(llm_output_path)
        except Exception as e:
            print(f"读取 LLM 实体提取缓存失败，将重新分析: {e}")
            return None
        print(f"检测到 LLM 实体提取缓存，从本地加载: {llm_output_path}")
        return rows

    def _extract_llm_entities(self, predicted_data, llm_output_path, classifier_config):
        llm_config = classifier_config.get('llm', {})
        if llm_config.get('reuse_cache', True):
            cached_rows = self._read_llm_cache(llm_output_path)
            if cached_rows is not None:
                return cached_rows
        if not llm_config.get('enabled', False):
            print("LLM 实体提取未启用；R7/R8 将仅使用已有行为证据或返回证据不足。")
            return []

        model_name = llm_config.get('model_name', 'qwen-plus')
        api_keys = llm_config.get('api_keys') or {}
        api_config = {
            'dashscope_api_key': (
                api_keys.get('dashscope')
                or llm_config.get('dashscope_api_key')
                or os.getenv('DASHSCOPE_API_KEY')
            ),
            'glm_api_key': (
                api_keys.get('glm')
                or llm_config.get('glm_api_key')
                or os.getenv('GLM_API_KEY')
            ),
            'deepseek_api_key': (
                api_keys.get('deepseek')
                or llm_config.get('deepseek_api_key')
                or os.getenv('DEEPSEEK_API_KEY')
            ),
        }
        required_key = (
            'glm_api_key' if model_name.lower().startswith('glm')
            else 'deepseek_api_key' if model_name.lower().startswith('deepseek')
            else 'dashscope_api_key'
        )
        if not api_config.get(required_key):
            raise ValueError(
                f"LLM 已启用但未提供 {required_key}；请在环境变量或配置文件 llm.api_keys 中设置 API Key。"
            )

        llm_extractor = LLMEntityExtractor1(
            config=api_config,
            kb_path=llm_config.get('kb_path'),
            use_dynamic_rag=llm_config.get('use_dynamic_rag', False),
            model_name=model_name,
        )
        print(f"正在利用 LLM ({model_name}) 提取深度实体信息...")
        llm_results = llm_extractor.extract_entities_with_labels(predicted_data)
        self._write_jsonl(llm_output_path, llm_results)
        print(f"LLM 深度分析结果已保存至: {llm_output_path}")
        return llm_results

    def _aggregate_model_results_from_cache(self, csv_label_path, output_jsonl_path, removed_ids):
        """专门用于从已存在的 JSONL 文件中加载标签并聚合"""
        lm = LabelManager(csv_label_path)
        lm.setup_with_removed_ids(removed_ids)
        all_labels_set = {name.strip() for name in lm.id2label.values()}
        found_labels_raw = set()
        if os.path.exists(output_jsonl_path):
            with open(output_jsonl_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        labels = data.get('label', [])
                        for l in labels:
                            found_labels_raw.add(l.strip())
                    except:
                        pass
        included_set = found_labels_raw.intersection(all_labels_set)
        missing_set = all_labels_set - included_set
        included = sorted(list(included_set))
        missing = sorted(list(missing_set))

        print(f"--- 缓存标签聚合: 已包含({len(included)}) + 缺失({len(missing)}) ---")
        return included, missing
    def analyze(self, classifier_config=None):
        """
        执行分析：HTML -> TXT -> JSONL -> Transformer预测 -> 可选LLM实体提取 -> 统计结果。
        classifier_config: 旧版平铺字典、新版 classifier/llm 字典或 JSON 配置文件路径。
        """
        classifier_config = self._normalize_config(classifier_config)
        # 必须有输出目录才能进行缓存
        if not self.output_dir:
            raise ValueError("必须提供 output_dir 才能执行缓存和分析。")
        base_filename = self._get_base_filename()

        # 缓存文件路径定义
        txt_output_path = os.path.join(self.output_dir, base_filename + ".txt")
        input_jsonl_path = os.path.join(self.output_dir, "privacy_policy.jsonl")  # 原始分句结果
        predicted_output_path = os.path.join(self.output_dir, "output_predictions.jsonl")  # Transformer分类结果
        llm_output_path = os.path.join(self.output_dir, "llm_extraction_results.jsonl")  # LLM提取结果
        # --------------------- 1. 检查分类预测缓存 ---------------------
        if classifier_config.get('reuse_predictions', True) and os.path.exists(predicted_output_path):
            print("检测到分类预测缓存，从本地加载分析结果。")

            # 确保其他文件也存在，用于获取长度
            self.content = self._read_html_file()
            txt_content = self._html_to_txt()

            # 加载 Transformer 预测结果
            predicted_data = self._read_jsonl(predicted_output_path)
            llm_results = self._extract_llm_entities(
                predicted_data, llm_output_path, classifier_config
            )

            # 重新聚合统计信息
            included_labels, missing_labels = self._aggregate_model_results_from_cache(
                classifier_config['csv_label_path'],
                predicted_output_path,
                classifier_config['removed_ids']
            )
            total_possible = len(included_labels) + len(missing_labels)
            score = round((len(included_labels) / total_possible) * 100, 1) if total_possible > 0 else 0

            self.analysis_result = {
                'score': score,
                'length': len(txt_content),
                'keywords_found': included_labels,
                'missing_clauses': missing_labels,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " (Cached)",
                'llm_entities': llm_results,
                'predicted_sentences': predicted_data
            }
            return self.analysis_result

        self.content = self._read_html_file()
        if not self.content:
            print("HTML内容为空，无法分析。")
            return {}

        # 1. HTML转TXT文本
        txt_content = self._html_to_txt()

        # 2. 保存TXT文件
        if self.output_dir:
            txt_output_path = os.path.join(self.output_dir, self._get_base_filename() + ".txt")
            with open(txt_output_path, 'w', encoding='utf-8') as f:
                f.write(txt_content)

        # 3. TXT分句
        self.sentences = self._txt_to_sentences(txt_content)

        # 4. 保存为模型需要的待预测 JSONL 文件
        input_jsonl_path = os.path.join(self.output_dir, "privacy_policy.jsonl")
        if self.output_dir:
            with open(input_jsonl_path, 'w', encoding='utf-8') as f:
                for sent in self.sentences:
                    json.dump({"text": sent}, f, ensure_ascii=False)
                    f.write('\n')

        # 5. 调用 Transformer 模型进行分类预测
        # 假设预测结果保存为 output_predictions.jsonl
        output_jsonl_path = os.path.join(self.output_dir, "output_predictions.jsonl")
        print("隐私政策文件预处理完成\n")

        classifier = PrivacyPolicyClassification(
            model_path=classifier_config['model_path'],
            csv_label_path=classifier_config['csv_label_path'],
            removed_label_ids=classifier_config['removed_ids'],
            thresholds_path=classifier_config['thresholds_path'],
            device=classifier_config.get('device'),
            batch_size=classifier_config.get('batch_size', 64)
        )

        classifier.predict_and_save(input_jsonl_path, output_jsonl_path)

        output_jsonl_path = os.path.join(self.output_dir, "output_predictions.jsonl")
        predicted_data = self._read_jsonl(output_jsonl_path)
        llm_results = self._extract_llm_entities(
            predicted_data, llm_output_path, classifier_config
        )



        included_labels, missing_labels = self._aggregate_model_results(
            classifier_config['csv_label_path'],
            output_jsonl_path,
            classifier_config['removed_ids']
        )

        # 7. 计算评分、生成警告
        # 评分逻辑：(预测到的标签数 / 总标签数) * 100
        total_possible = len(included_labels) + len(missing_labels)
        score = round((len(included_labels) / total_possible) * 100, 1) if total_possible > 0 else 0

        self.analysis_result = {
            'score': score,
            'length': len(txt_content),
            'keywords_found': included_labels,
            'missing_clauses': missing_labels,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            # 新增：将 LLM 提取的结果存入，供 UI 使用
            'llm_entities': llm_results,
            # 同时也保存原始预测数据，方便 UI 对应文本显示
            'predicted_sentences': predicted_data
        }
        return self.analysis_result

    def _aggregate_model_results(self, csv_label_path, output_jsonl_path, removed_ids):

        lm = LabelManager(csv_label_path)
        lm.setup_with_removed_ids(removed_ids)

        # 获取标准标签全集（建议加上 strip() 防止不可见空格影响匹配）
        all_labels_set = {name.strip() for name in lm.id2label.values()}
        print(f"--- 标签全集加载完成，共 {len(all_labels_set)} 个唯一标签名 ---")

        found_labels_raw = set()
        if os.path.exists(output_jsonl_path):
            with open(output_jsonl_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        # 【关键修复】：将 'predicted_labels' 改为 'label'
                        labels = data.get('label', [])
                        # 确保提取出的标签也去掉空格
                        for l in labels:
                            found_labels_raw.add(l.strip())
                    except Exception as e:
                        pass

        print(f"--- 模型实际预测到的去重标签数: {len(found_labels_raw)} ---")

        # 计算交集和差集
        included_set = found_labels_raw.intersection(all_labels_set)
        missing_set = all_labels_set - included_set

        included = sorted(list(included_set))
        missing = sorted(list(missing_set))

        print(f"验证：已包含({len(included)}) + 缺失({len(missing)}) = {len(included) + len(missing)}")
        return included, missing

    def _get_base_filename(self):
        # 方便生成输出文件名，去掉路径和扩展名
        base = os.path.basename(self.html_path)
        return os.path.splitext(base)[0]

    # 其他方法同之前代码，如：
    def _read_html_file(self):
        # 读取html文件，支持utf-8和gbk编码
        try:
            with open(self.html_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            try:
                with open(self.html_path, 'r', encoding='gbk') as f:
                    return f.read()
            except Exception as e:
                print(f"读取HTML文件失败: {e}")
                return ""

    def _html_to_txt(self):
        return self.converter.convert(self.content)

    def _txt_to_sentences(self, txt_content):
        return self.sentence_splitter.split_sentences(txt_content)


def test_analyzer():
    test_html_path = r"G:\downloads\安吉星.html"
    output_dir = "result"
    resource_dir="../../../lab8/ui/res"
    analyzer = PrivacyPolicyAnalyzer(test_html_path,output_dir)
    config = PrivacyPolicyAnalyzer.default_config()
    result = analyzer.analyze(config)

def test_llm():
    output_dir = "result"
    predicted_data = []
    output_jsonl_path = os.path.join(output_dir, "output_predictions1.jsonl")
    with open(output_jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            predicted_data.append(json.loads(line.strip()))
    classifier_config = {
        'dashscope_api_key': os.getenv('DASHSCOPE_API_KEY'),
        'glm_api_key': os.getenv('GLM_API_KEY'),
        'deepseek_api_key': os.getenv('DEEPSEEK_API_KEY'),
    }
    # llm_extractor = LLMEntityExtractor1(
    #     config=classifier_config,
    #     use_dynamic_rag=False,
    #     model_name='deepseek-chat'  # 或者 deepseek-coder
    # )
    # llm_extractor = LLMEntityExtractor1(
    #     config=classifier_config,
    #     use_dynamic_rag=False,
    #     model_name='qwen-plus'  # 或者 deepseek-coder
    # )
    llm_extractor = LLMEntityExtractor1(
        config=classifier_config,
        use_dynamic_rag=False,
        model_name='glm-4-plus'  # 或者 deepseek-coder
    )
    print("正在利用 LLM 提取深度实体信息...")
    llm_results = llm_extractor.extract_entities_with_labels(predicted_data)

    llm_output_path = os.path.join(output_dir, "llm_extraction_results1.jsonl")
    with open(llm_output_path, 'w', encoding='utf-8') as f:
        for item in llm_results:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    print(f"LLM 深度分析结果已保存至: {llm_output_path}")
# 测试示例
if __name__ == "__main__":
    # 请替换为你的HTML文件路径
    print("55555555555555555")
    ## 测试单个文件
    #test_analyzer()


    ## 测试不同的大模型
    # test_llm()
