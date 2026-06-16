#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
隐私泄露检测脚本 v2.0
对比隐私政策声明与APP实际行为，检测违规收集和模糊声明

使用方法:
    python privacy_violation_detector.py \
        --declaration result/llm_extraction_results.jsonl \
        --behavior leak.json \
        --it-info analysis/it_info.json \
        --device-info analysis/device_info.json \
        --sdk-list analysis/sdk_list.json \
        --output violation_report
"""

import json
import os
import re
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from pathlib import Path
import argparse
from datetime import datetime


# ============================================================
# 第一部分：数据结构定义
# ============================================================

class ViolationType(Enum):
    """违规类型枚举"""
    APP_UNDECLARED = "APP自身违规收集未声明数据"
    SDK_UNDECLARED = "SDK违规收集未声明数据"
    VAGUE_DECLARATION = "模糊声明"


@dataclass
class ViolationRecord:
    """违规记录"""
    violation_type: ViolationType
    data_field: str  # 实际收集的数据字段（标准名称）
    behavior_field: str  # 行为数据中的原始字段名
    category: str  # 数据类别
    source: str  # 来源（APP域名或SDK名称）
    sdk_name: str = ""  # SDK名称（如果是第三方SDK）
    declared_text: str = ""  # 相关的声明文本（如有）
    count: int = 1  # 收集次数
    details: str = ""  # 详细说明
    severity: str = "中"  # 严重程度：高/中/低


@dataclass
class DetectionResult:
    """检测结果"""
    package_name: str
    analysis_time: str
    detection_time: str = ""
    violations: List[ViolationRecord] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    declared_data_summary: Dict[str, Any] = field(default_factory=dict)
    collected_data_summary: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# 第二部分：配置加载器
# ============================================================

class ConfigLoader:
    """配置文件加载器"""

    @staticmethod
    def load_json(filepath: str) -> Dict:
        """加载JSON文件"""
        if not os.path.exists(filepath):
            print(f"警告: 文件不存在: {filepath}")
            return {}

        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    @staticmethod
    def load_jsonl(filepath: str) -> List[Dict]:
        """加载JSONL文件"""
        if not os.path.exists(filepath):
            print(f"警告: 文件不存在: {filepath}")
            return []

        results = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"JSON解析错误: {e}")
        return results


# ============================================================
# 第三部分：数据映射体系（核心）
# ============================================================

class PrivacyDataMapper:
    """
    隐私数据映射器
    利用 it_info.json 和 device_info.json 建立映射关系
    """

    def __init__(self, it_info_path: str, device_info_path: str, sdk_list_path: str = None):
        """
        初始化映射器

        Args:
            it_info_path: 信息类别列表文件路径
            device_info_path: 字段映射配置文件路径
            sdk_list_path: SDK列表文件路径
        """
        # 加载配置文件
        self.it_info = ConfigLoader.load_json(it_info_path)
        self.device_info = ConfigLoader.load_json(device_info_path)
        self.sdk_list = ConfigLoader.load_json(sdk_list_path) if sdk_list_path else []

        # 构建映射表
        self._build_mappings()

    def _build_mappings(self):
        """构建各种映射表"""

        # 1. 行为字段 -> (类别, 标准名称) 的映射
        # 从 device_info.json 的 _categories 中提取
        self.field_to_category = {}
        categories_config = self.device_info.get('_categories', {})
        for field_name, category_info in categories_config.items():
            if field_name.startswith('_'):
                continue
            if isinstance(category_info, list) and len(category_info) >= 2:
                self.field_to_category[field_name] = {
                    'category': category_info[0],
                    'standard_name': category_info[1]
                }

        # 2. 标准名称 -> 类别 的映射（从 it_info.json 构建）
        self.standard_to_category = {}
        for category, items in self.it_info.items():
            for item in items:
                self.standard_to_category[item.lower()] = category
                self.standard_to_category[item] = category

        # 3. 类别 -> 该类别下所有标准名称 的映射
        self.category_to_standards = defaultdict(set)
        for category, items in self.it_info.items():
            for item in items:
                self.category_to_standards[category].add(item)

        # 4. 声明文本可能的表述 -> 标准名称 的映射
        # 这是关键的映射，用于将隐私政策中的表述映射到标准名称
        self._build_declaration_mapping()

        # 5. SDK域名 -> SDK信息 的映射
        self._build_sdk_mapping()

        # 6. 模糊声明词 -> 具体数据项 的映射
        self._build_vague_mapping()

    def _build_declaration_mapping(self):
        """构建声明文本到标准名称的映射"""
        self.declaration_to_standard = {}

        # 基于 it_info.json 中的标准名称，构建可能的声明表述
        declaration_variants = {
            # 设备信息
            "device id": ["设备ID", "设备标识", "设备标识符", "device id", "deviceid"],
            "IMEI": ["IMEI", "imei", "国际移动设备识别码", "设备IMEI"],
            "MEID": ["MEID", "meid", "移动设备识别码"],
            "Android ID": ["Android ID", "android id", "安卓ID", "AndroidID"],
            "SN": ["SN", "序列号", "设备序列号", "serial number"],
            "GUID": ["GUID", "guid", "全局唯一标识符"],
            "UUID": ["UUID", "uuid", "通用唯一标识符"],
            "型号": ["型号", "设备型号", "手机型号", "机型"],
            "系统语言": ["系统语言", "语言设置", "设备语言"],
            "平台": ["平台", "操作系统平台", "系统平台"],
            "厂商": ["厂商", "设备厂商", "手机厂商"],
            "品牌": ["品牌", "设备品牌", "手机品牌"],
            "版本信息": ["版本信息", "系统版本", "操作系统版本", "OS版本"],
            "屏幕分辨率": ["屏幕分辨率", "分辨率", "屏幕尺寸"],
            "蓝牙信息": ["蓝牙信息", "蓝牙", "蓝牙设备"],
            "蓝牙MAC": ["蓝牙MAC", "蓝牙地址", "蓝牙MAC地址"],

            # 网络信息
            "IP": ["IP", "IP地址", "ip地址", "网络IP", "设备IP"],
            "MAC": ["MAC", "MAC地址", "mac地址", "网卡地址", "物理地址"],
            "wifi": ["wifi", "WiFi", "WIFI", "无线网络", "WiFi信息"],
            "SSID": ["SSID", "ssid", "WiFi名称", "网络名称"],
            "BSSID": ["BSSID", "bssid", "WiFi BSSID"],
            "网络状态信息": ["网络状态", "网络连接状态", "联网状态"],
            "网络类型": ["网络类型", "网络制式", "联网方式"],
            "运营商信息": ["运营商", "运营商信息", "网络运营商"],

            # 位置信息
            "GPS": ["GPS", "gps", "GPS定位", "GPS信息"],
            "经纬度": ["经纬度", "经度", "纬度", "地理坐标", "坐标"],
            "基站信息": ["基站", "基站信息", "基站定位"],
            "地区": ["地区", "区域", "所在地区"],
            "城市": ["城市", "所在城市"],

            # 个人信息
            "姓名": ["姓名", "真实姓名", "用户姓名", "名字"],
            "身份证号": ["身份证", "身份证号", "身份证号码", "证件号"],
            "面部特征": ["面部", "人脸", "面部特征", "人脸信息", "面部识别"],
            "指纹": ["指纹", "指纹信息", "指纹识别"],
            "声纹": ["声纹", "声纹信息", "声音特征"],
            "手机号": ["手机号", "手机号码", "电话号码", "联系电话", "手机"],
            "邮箱": ["邮箱", "电子邮箱", "邮件地址", "email"],
            "通讯录": ["通讯录", "联系人", "联系人信息", "通讯录信息"],
            "UserId": ["用户ID", "userid", "用户标识", "账号ID"],
            "账号密码": ["密码", "账号密码", "登录密码", "口令"],
            "登录凭证": ["登录凭证", "token", "令牌", "会话", "session"],
            "通话记录": ["通话记录", "通话历史", "电话记录"],
            "短信记录": ["短信", "短信记录", "短信内容"],

            # SIM卡信息
            "IMSI": ["IMSI", "imsi", "国际移动用户识别码"],
            "ICCID": ["ICCID", "iccid", "SIM卡序列号", "SIM卡ID"],

            # 广告数据
            "OAID": ["OAID", "oaid", "匿名设备标识符", "开放匿名标识"],
            "IDFA": ["IDFA", "idfa", "广告标识符"],
            "GAID": ["GAID", "gaid", "Google广告ID"],

            # 应用信息
            "应用列表信息": ["应用列表", "已安装应用", "安装列表", "软件列表"],
            "应用版本号": ["应用版本", "APP版本", "版本号"],
            "包名信息": ["包名", "应用包名", "bundle id"],

            # 剪贴板
            "剪切板": ["剪贴板", "剪切板", "复制内容", "粘贴板"],
        }

        # 构建反向映射
        for standard_name, variants in declaration_variants.items():
            for variant in variants:
                self.declaration_to_standard[variant.lower()] = standard_name
                self.declaration_to_standard[variant] = standard_name

        # 同时将 it_info.json 中的所有项目作为标准名称
        for category, items in self.it_info.items():
            for item in items:
                self.declaration_to_standard[item.lower()] = item
                self.declaration_to_standard[item] = item

    def _build_sdk_mapping(self):
        """构建SDK域名映射"""
        self.domain_to_sdk = {}
        self.package_to_sdk = {}

        if isinstance(self.sdk_list, list):
            for sdk_info in self.sdk_list:
                sdk_name = sdk_info.get('name', '')

                # 域名映射
                for domain in sdk_info.get('domains', []):
                    self.domain_to_sdk[domain.lower()] = sdk_info

                # 包名映射
                for package in sdk_info.get('packages', []):
                    self.package_to_sdk[package.lower()] = sdk_info

    def _build_vague_mapping(self):
        """构建模糊声明词到具体数据项的映射"""
        # 模糊声明词 -> 该类别下的所有具体数据项
        self.vague_to_specific = {
            "设备信息": list(self.it_info.get("设备信息", [])),
            "网络信息": list(self.it_info.get("网络信息", [])),
            "位置信息": list(self.it_info.get("位置信息", [])),
            "个人信息": list(self.it_info.get("个人信息", [])),
            "SIM卡信息": list(self.it_info.get("SIM卡信息", [])),
            "广告数据": list(self.it_info.get("广告数据", [])),
            "应用信息": list(self.it_info.get("应用信息", [])),
            "传感器信息": list(self.it_info.get("传感器信息", [])),
            "媒体信息": list(self.it_info.get("媒体信息", [])),
            "日志信息": list(self.it_info.get("日志信息", [])),
            "上网记录": list(self.it_info.get("上网记录", [])),

            # 额外的模糊表述
            "设备标识": ["device id", "IMEI", "MEID", "Android ID", "SN", "GUID", "UUID"],
            "设备标识符": ["device id", "IMEI", "MEID", "Android ID", "SN", "GUID", "UUID", "OAID"],
            "唯一标识符": ["device id", "IMEI", "Android ID", "GUID", "UUID", "OAID"],
            "地理位置": ["GPS", "经纬度", "基站位置信息", "地区", "城市"],
            "定位信息": ["GPS", "经纬度", "基站位置信息", "WLAN接入点"],
            "账户信息": ["UserId", "账号密码", "登录凭证"],
            "身份信息": ["姓名", "身份证号", "手机号"],
            "生物特征": ["面部特征", "指纹", "声纹"],
            "联系方式": ["手机号", "邮箱", "通讯录"],
        }

    def get_field_info(self, behavior_field: str) -> Dict[str, str]:
        """
        获取行为字段的信息

        Args:
            behavior_field: 行为数据中的字段名（如 "imei-word"）

        Returns:
            {"category": "设备信息", "standard_name": "IMEI"}
        """
        # 首先从 _categories 配置中查找
        if behavior_field in self.field_to_category:
            return self.field_to_category[behavior_field]

        # 尝试去掉后缀再查找
        base_field = behavior_field.replace('-word', '').replace('-token', '')
        if base_field in self.field_to_category:
            return self.field_to_category[base_field]

        # 返回默认值
        return {
            'category': '其他信息',
            'standard_name': behavior_field
        }

    def normalize_declaration(self, declaration_text: str) -> str:
        """
        将声明文本标准化

        Args:
            declaration_text: 隐私政策中的数据描述文本

        Returns:
            标准化后的名称
        """
        text_lower = declaration_text.lower().strip()

        # 直接匹配
        if text_lower in self.declaration_to_standard:
            return self.declaration_to_standard[text_lower]

        if declaration_text in self.declaration_to_standard:
            return self.declaration_to_standard[declaration_text]

        # 模糊匹配
        for key, standard in self.declaration_to_standard.items():
            if key in text_lower or text_lower in key:
                return standard

        return declaration_text

    def is_vague_term(self, term: str) -> bool:
        """判断是否为模糊声明词"""
        return term in self.vague_to_specific or term in self.it_info

    def get_specific_items(self, vague_term: str) -> List[str]:
        """获取模糊声明词对应的具体数据项"""
        if vague_term in self.vague_to_specific:
            return self.vague_to_specific[vague_term]
        if vague_term in self.it_info:
            return self.it_info[vague_term]
        return []

    def identify_sdk(self, host: str, app_package: str) -> Tuple[bool, str, str]:
        """
        识别主机是否为第三方SDK

        Args:
            host: 主机域名
            app_package: APP包名

        Returns:
            (is_third_party, sdk_name, sdk_company)
        """
        host_lower = host.lower()

        # 检查是否为APP自身域名
        # 从包名提取可能的域名关键词
        package_parts = app_package.lower().split('.')
        app_keywords = [p for p in package_parts if
                        len(p) > 2 and p not in ['com', 'cn', 'org', 'net', 'android', 'app']]

        for keyword in app_keywords:
            if keyword in host_lower:
                return False, "", ""

        # 检查SDK列表
        for domain, sdk_info in self.domain_to_sdk.items():
            if domain in host_lower or host_lower.endswith('.' + domain):
                return True, sdk_info.get('name', ''), sdk_info.get('company', '')

        # 使用启发式规则判断常见第三方SDK
        third_party_patterns = [
            (r'.*\.baidu\.com$', '百度SDK', '百度'),
            (r'.*\.qq\.com$', '腾讯SDK', '腾讯'),
            (r'.*\.tencent\.com$', '腾讯SDK', '腾讯'),
            (r'.*\.aliyun\.com$', '阿里云SDK', '阿里巴巴'),
            (r'.*\.alibaba\.com$', '阿里SDK', '阿里巴巴'),
            (r'.*\.taobao\.com$', '淘宝SDK', '阿里巴巴'),
            (r'.*\.umeng\.com$', '友盟SDK', '友盟'),
            (r'.*\.umengcloud\.com$', '友盟SDK', '友盟'),
            (r'.*\.jpush\.cn$', '极光推送', '极光'),
            (r'.*\.jiguang\.cn$', '极光SDK', '极光'),
            (r'.*\.getui\.com$', '个推SDK', '个推'),
            (r'.*\.igexin\.com$', '个推SDK', '个推'),
            (r'.*\.mob\.com$', 'Mob SDK', 'Mob'),
            (r'.*\.sensors.*\.com$', '神策SDK', '神策'),
            (r'.*\.growingio\.com$', 'GrowingIO', 'GrowingIO'),
            (r'.*\.bugly\..*$', 'Bugly', '腾讯'),
            (r'.*\.crashlytics\..*$', 'Crashlytics', 'Google'),
            (r'.*\.firebase\..*$', 'Firebase', 'Google'),
            (r'.*\.google\..*$', 'Google SDK', 'Google'),
            (r'.*\.facebook\..*$', 'Facebook SDK', 'Meta'),
            (r'.*\.huawei\.com$', '华为SDK', '华为'),
            (r'.*\.hicloud\.com$', '华为云', '华为'),
            (r'.*\.xiaomi\.com$', '小米SDK', '小米'),
            (r'.*\.miui\.com$', '小米SDK', '小米'),
            (r'.*\.oppo\.com$', 'OPPO SDK', 'OPPO'),
            (r'.*\.vivo\.com$', 'vivo SDK', 'vivo'),
            (r'.*\.meizu\.com$', '魅族SDK', '魅族'),
            (r'.*\.bytedance\.com$', '字节SDK', '字节跳动'),
            (r'.*\.snssdk\.com$', '字节SDK', '字节跳动'),
            (r'.*\.pstatp\.com$', '字节SDK', '字节跳动'),
        ]

        for pattern, sdk_name, company in third_party_patterns:
            if re.match(pattern, host_lower):
                return True, sdk_name, company

        return False, "", ""


# ============================================================
# 第四部分：声明数据解析器
# ============================================================

class DeclarationParser:
    """
    声明数据解析器
    从LLM提取结果中解析出声明的数据项
    """

    def __init__(self, mapper: PrivacyDataMapper):
        self.mapper = mapper

    def parse(self, llm_results: List[Dict]) -> Dict[str, Any]:
        """
        解析LLM提取结果

        Args:
            llm_results: LLM提取结果列表

        Returns:
            {
                "declared_data": Set[str],           # 明确声明的数据项（标准化名称）
                "declared_data_raw": Set[str],       # 原始声明文本
                "vague_declarations": Dict[str, str], # 模糊声明 -> 原文
                "collection_acts": List[Dict],       # 收集行为
                "sharing_acts": List[Dict],          # 共享行为
                "by_controller": Dict[str, List],    # 按主体分组
            }
        """
        result = {
            "declared_data": set(),
            "declared_data_raw": set(),
            "vague_declarations": {},
            "collection_acts": [],
            "sharing_acts": [],
            "by_controller": defaultdict(list),
        }

        for item in llm_results:
            self._process_item(item, result)

        return result

    def _process_item(self, item: Dict, result: Dict):
        """处理单条LLM提取结果"""
        text = item.get('text', '')
        entities = item.get('entities', [])

        # 提取各类实体
        controller = None
        action_type = None
        action_verb = None
        data_items = []
        purpose = None
        receiver = None

        for entity in entities:
            label = entity.get('label', '').lower()
            entity_text = entity.get('text', '').strip()

            if not entity_text:
                continue

            if label == 'controller':
                controller = entity_text
            elif label in ['collection', 'sharing', 'other']:
                action_type = label
                action_verb = entity_text
            elif label == 'data':
                data_items.append(entity_text)
            elif label == 'purpose':
                purpose = entity_text
            elif label == 'receiver':
                receiver = entity_text

        # 处理数据项
        for data_text in data_items:
            # 保存原始文本
            result['declared_data_raw'].add(data_text)

            # 标准化
            standard_name = self.mapper.normalize_declaration(data_text)
            result['declared_data'].add(standard_name)

            # 检查是否为模糊声明
            if self.mapper.is_vague_term(data_text) or self.mapper.is_vague_term(standard_name):
                result['vague_declarations'][data_text] = text

        # 记录处理行为
        if action_type and data_items:
            act_record = {
                'text': text,
                'controller': controller or '我们',
                'action_type': action_type,
                'action_verb': action_verb,
                'data_items': data_items,
                'purpose': purpose,
                'receiver': receiver,
            }

            if action_type == 'collection':
                result['collection_acts'].append(act_record)
            elif action_type == 'sharing':
                result['sharing_acts'].append(act_record)

            # 按主体分组
            result['by_controller'][controller or '我们'].append(act_record)


# ============================================================
# 第五部分：行为数据解析器
# ============================================================

class BehaviorParser:
    """
    行为数据解析器
    从leak.json中解析实际收集行为
    """

    def __init__(self, mapper: PrivacyDataMapper):
        self.mapper = mapper

    def parse(self, leak_data: Dict) -> Dict[str, Any]:
        """
        解析行为数据

        Returns:
            {
                "package": str,
                "analysis_time": str,
                "total_leaks": int,
                "collected_data": Dict[str, Dict],  # 标准名称 -> 详细信息
                "by_source": Dict[str, Dict],       # 来源 -> 详细信息
                "app_sources": List[str],           # APP自身来源
                "sdk_sources": List[str],           # 第三方SDK来源
            }
        """
        result = {
            "package": leak_data.get('package', ''),
            "analysis_time": leak_data.get('analysis_time', ''),
            "total_leaks": 0,
            "collected_data": {},
            "by_source": {},
            "app_sources": [],
            "sdk_sources": [],
        }

        summary = leak_data.get('summary', {})
        result['total_leaks'] = summary.get('total_leaks', 0)

        # 解析按类别的数据
        by_category = summary.get('by_category', {})
        for category, cat_data in by_category.items():
            fields = cat_data.get('fields', {})
            for field_name, count in fields.items():
                field_info = self.mapper.get_field_info(field_name)
                standard_name = field_info['standard_name']

                if standard_name not in result['collected_data']:
                    result['collected_data'][standard_name] = {
                        'category': field_info['category'],
                        'behavior_field': field_name,
                        'count': 0,
                        'sources': [],
                    }
                result['collected_data'][standard_name]['count'] += count

        # 解析按来源的数据
        by_sdk = summary.get('by_sdk', {})
        for host, sdk_data in by_sdk.items():
            is_third_party, sdk_name, sdk_company = self.mapper.identify_sdk(
                host, result['package']
            )

            # 如果数据中已标记，优先使用数据中的标记
            if sdk_data.get('is_third_party'):
                is_third_party = True

            source_info = {
                'host': host,
                'is_third_party': is_third_party,
                'sdk_name': sdk_name,
                'sdk_company': sdk_company,
                'count': sdk_data.get('count', 0),
                'fields': sdk_data.get('fields', []),
            }

            result['by_source'][host] = source_info

            if is_third_party:
                result['sdk_sources'].append(host)
            else:
                result['app_sources'].append(host)

            # 更新 collected_data 中的来源信息
            for field_name in sdk_data.get('fields', []):
                field_info = self.mapper.get_field_info(field_name)
                standard_name = field_info['standard_name']

                if standard_name in result['collected_data']:
                    if host not in result['collected_data'][standard_name]['sources']:
                        result['collected_data'][standard_name]['sources'].append(host)

        return result


# ============================================================
# 第六部分：违规检测器（核心）
# ============================================================

# ============================================================
# 第六部分：违规检测器（核心）
# ============================================================

class PrivacyViolationDetector:
    """
    隐私违规检测器
    核心检测逻辑
    """

    def __init__(self, mapper: PrivacyDataMapper):
        self.mapper = mapper
        self.declaration_parser = DeclarationParser(mapper)
        self.behavior_parser = BehaviorParser(mapper)

    def detect(self, llm_results: List[Dict], leak_data: Dict) -> DetectionResult:
        """
        执行检测

        Args:
            llm_results: LLM提取结果列表
            leak_data: leak.json数据

        Returns:
            DetectionResult: 检测结果
        """
        # 解析数据
        declarations = self.declaration_parser.parse(llm_results)
        behaviors = self.behavior_parser.parse(leak_data)

        result = DetectionResult(
            package_name=behaviors.get('package', ''),
            analysis_time=behaviors.get('analysis_time', ''),
            detection_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

        # 保存解析摘要
        result.declared_data_summary = {
            'total_declared': len(declarations['declared_data']),
            'declared_items': list(declarations['declared_data']),
            'vague_count': len(declarations['vague_declarations']),
            'collection_acts_count': len(declarations['collection_acts']),
            'sharing_acts_count': len(declarations['sharing_acts']),
        }

        result.collected_data_summary = {
            'total_collected': len(behaviors['collected_data']),
            'collected_items': list(behaviors['collected_data'].keys()),
            'app_sources_count': len(behaviors['app_sources']),
            'sdk_sources_count': len(behaviors['sdk_sources']),
            'total_leaks': behaviors['total_leaks'],
        }

        # 执行三类检测
        self._detect_app_undeclared(declarations, behaviors, result)
        self._detect_sdk_undeclared(declarations, behaviors, result)
        self._detect_vague_declarations(declarations, behaviors, result)

        # 生成摘要
        self._generate_summary(result)

        return result

    def _detect_app_undeclared(self, declarations: Dict, behaviors: Dict, result: DetectionResult):
        """检测APP自身未声明的数据收集"""
        declared_data = declarations['declared_data']
        declared_data_raw = declarations['declared_data_raw']
        collected_data = behaviors['collected_data']
        by_source = behaviors['by_source']
        app_sources = behaviors['app_sources']

        for standard_name, data_info in collected_data.items():
            # 检查是否已声明
            is_declared = self._check_if_declared(
                standard_name,
                data_info['category'],
                declared_data,
                declared_data_raw
            )

            if is_declared:
                continue

            # 检查是否来自APP自身
            for source in data_info.get('sources', []):
                source_info = by_source.get(source, {})

                # 只处理APP自身的来源
                if source_info.get('is_third_party', False):
                    continue

                violation = ViolationRecord(
                    violation_type=ViolationType.APP_UNDECLARED,
                    data_field=standard_name,
                    behavior_field=data_info.get('behavior_field', ''),
                    category=data_info.get('category', '未知'),
                    source=source,
                    count=data_info.get('count', 1),
                    severity=self._get_severity(standard_name, data_info.get('category', '')),
                    details=f"APP收集了「{standard_name}」，但隐私政策中未找到相关声明"
                )
                result.violations.append(violation)
                break  # 每个数据项只记录一次APP违规

    def _detect_sdk_undeclared(self, declarations: Dict, behaviors: Dict, result: DetectionResult):
        """检测第三方SDK未声明的数据收集"""
        declared_data = declarations['declared_data']
        declared_data_raw = declarations['declared_data_raw']
        collected_data = behaviors['collected_data']
        by_source = behaviors['by_source']

        for standard_name, data_info in collected_data.items():
            # 检查是否已声明
            is_declared = self._check_if_declared(
                standard_name,
                data_info['category'],
                declared_data,
                declared_data_raw
            )

            if is_declared:
                continue

            # 检查是否来自第三方SDK
            for source in data_info.get('sources', []):
                source_info = by_source.get(source, {})

                # 只处理第三方SDK的来源
                if not source_info.get('is_third_party', False):
                    continue

                sdk_name = source_info.get('sdk_name', '') or source
                sdk_company = source_info.get('sdk_company', '')

                violation = ViolationRecord(
                    violation_type=ViolationType.SDK_UNDECLARED,
                    data_field=standard_name,
                    behavior_field=data_info.get('behavior_field', ''),
                    category=data_info.get('category', '未知'),
                    source=source,
                    sdk_name=sdk_name,
                    count=data_info.get('count', 1),
                    severity=self._get_severity(standard_name, data_info.get('category', '')),
                    details=f"第三方SDK「{sdk_name}」({sdk_company})收集了「{standard_name}」，但隐私政策中未找到相关声明"
                )
                result.violations.append(violation)

    def _detect_vague_declarations(self, declarations: Dict, behaviors: Dict, result: DetectionResult):
        """检测模糊声明"""
        vague_declarations = declarations['vague_declarations']
        collected_data = behaviors['collected_data']

        for vague_term, original_text in vague_declarations.items():
            # 获取该模糊词对应的具体数据项
            specific_items = self.mapper.get_specific_items(vague_term)

            if not specific_items:
                continue

            # 检查是否收集了具体数据项
            collected_specific = []
            for item in specific_items:
                # 检查标准名称
                if item in collected_data:
                    collected_specific.append(item)
                    continue

                # 检查是否有匹配的收集数据
                for collected_name in collected_data.keys():
                    if item.lower() in collected_name.lower() or collected_name.lower() in item.lower():
                        collected_specific.append(f"{item}({collected_name})")
                        break

            if collected_specific:
                # 截断原文，避免过长
                truncated_text = original_text[:100] + '...' if len(original_text) > 100 else original_text

                violation = ViolationRecord(
                    violation_type=ViolationType.VAGUE_DECLARATION,
                    data_field=vague_term,
                    behavior_field="",
                    category="模糊声明",
                    source="隐私政策",
                    declared_text=truncated_text,
                    severity="中",
                    details=f"声明中使用模糊表述「{vague_term}」，实际收集了具体数据: {', '.join(collected_specific[:5])}"
                            + (f" 等{len(collected_specific)}项" if len(collected_specific) > 5 else "")
                )
                result.violations.append(violation)

    def _check_if_declared(self, standard_name: str, category: str,
                           declared_data: Set[str], declared_data_raw: Set[str]) -> bool:
        """
        检查数据项是否已声明

        采用多级匹配策略：
        1. 精确匹配标准名称
        2. 精确匹配原始声明文本
        3. 模糊匹配（包含关系）
        4. 类别级别匹配（如果声明了整个类别）
        """
        # 1. 精确匹配标准名称
        if standard_name in declared_data:
            return True

        # 2. 精确匹配（忽略大小写）
        standard_lower = standard_name.lower()
        for declared in declared_data:
            if declared.lower() == standard_lower:
                return True

        # 3. 检查原始声明文本
        for raw in declared_data_raw:
            if standard_lower in raw.lower() or raw.lower() in standard_lower:
                return True

        # 4. 模糊匹配
        for declared in declared_data:
            declared_lower = declared.lower()
            # 双向包含检查
            if standard_lower in declared_lower or declared_lower in standard_lower:
                return True

            # 关键词匹配
            standard_keywords = set(standard_lower.replace('-', ' ').replace('_', ' ').split())
            declared_keywords = set(declared_lower.replace('-', ' ').replace('_', ' ').split())
            if standard_keywords & declared_keywords:  # 有交集
                return True

        # 5. 类别级别匹配（如果声明了整个类别，则认为该类别下的数据都已声明）
        if category in declared_data or category in declared_data_raw:
            return True

        return False

    def _get_severity(self, data_field: str, category: str) -> str:
        """
        获取违规严重程度

        高：敏感个人信息（生物特征、身份证、金融信息等）
        中：一般个人信息（设备标识、位置等）
        低：非敏感信息（应用版本等）
        """
        high_severity_items = {
            '身份证号', '面部特征', '指纹', '声纹', '银行卡',
            '密码', '账号密码', '通话记录', '短信记录', '通讯录',
            'IMEI', 'IMSI', '手机号', '姓名', '真实姓名'
        }

        high_severity_categories = {'个人信息', 'SIM卡信息'}

        low_severity_items = {
            '应用版本号', '版本信息', '系统语言', '屏幕分辨率',
            '屏幕方向', '时区', '平台'
        }

        low_severity_categories = {'应用信息', '设备参数'}

        # 检查高严重度
        if data_field in high_severity_items:
            return "高"
        if category in high_severity_categories:
            return "高"

        # 检查低严重度
        if data_field in low_severity_items:
            return "低"
        if category in low_severity_categories:
            return "低"

        return "中"

    def _generate_summary(self, result: DetectionResult):
        """生成检测摘要"""
        summary = {
            'total_violations': len(result.violations),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_category': defaultdict(list),
            'undeclared_by_app': [],
            'undeclared_by_sdk': [],
            'vague_declarations': [],
            'affected_sdks': set(),
        }

        for v in result.violations:
            # 按类型统计
            summary['by_type'][v.violation_type.value] += 1

            # 按严重程度统计
            summary['by_severity'][v.severity] += 1

            # 按类别统计
            summary['by_category'][v.category].append(v.data_field)

            # 分类记录
            if v.violation_type == ViolationType.APP_UNDECLARED:
                summary['undeclared_by_app'].append({
                    'field': v.data_field,
                    'category': v.category,
                    'source': v.source,
                    'count': v.count,
                    'severity': v.severity,
                })
            elif v.violation_type == ViolationType.SDK_UNDECLARED:
                summary['undeclared_by_sdk'].append({
                    'field': v.data_field,
                    'category': v.category,
                    'sdk_name': v.sdk_name,
                    'source': v.source,
                    'count': v.count,
                    'severity': v.severity,
                })
                summary['affected_sdks'].add(v.sdk_name or v.source)
            elif v.violation_type == ViolationType.VAGUE_DECLARATION:
                summary['vague_declarations'].append({
                    'term': v.data_field,
                    'details': v.details,
                })

        # 转换set为list以便JSON序列化
        summary['affected_sdks'] = list(summary['affected_sdks'])
        summary['by_type'] = dict(summary['by_type'])
        summary['by_severity'] = dict(summary['by_severity'])
        summary['by_category'] = dict(summary['by_category'])

        result.summary = summary


# ============================================================
# 第七部分：报告生成器
# ============================================================

class ReportGenerator:
    """报告生成器"""

    @staticmethod
    def generate_json_report(result: DetectionResult, output_path: str):
        """生成JSON格式报告"""
        report = {
            'meta': {
                'package_name': result.package_name,
                'analysis_time': result.analysis_time,
                'detection_time': result.detection_time,
                'report_version': '2.0',
            },
            'summary': result.summary,
            'declared_data_summary': result.declared_data_summary,
            'collected_data_summary': result.collected_data_summary,
            'violations': [
                {
                    'type': v.violation_type.value,
                    'data_field': v.data_field,
                    'behavior_field': v.behavior_field,
                    'category': v.category,
                    'source': v.source,
                    'sdk_name': v.sdk_name,
                    'declared_text': v.declared_text,
                    'count': v.count,
                    'severity': v.severity,
                    'details': v.details,
                }
                for v in result.violations
            ]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"✓ JSON报告已保存至: {output_path}")

    @staticmethod
    def generate_text_report(result: DetectionResult, output_path: str = None) -> str:
        """生成文本格式报告"""
        lines = []

        # 标题
        lines.append("=" * 70)
        lines.append("                    隐私泄露检测报告")
        lines.append("=" * 70)
        lines.append("")

        # 基本信息
        lines.append("【基本信息】")
        lines.append(f"  应用包名: {result.package_name}")
        lines.append(f"  行为分析时间: {result.analysis_time}")
        lines.append(f"  检测执行时间: {result.detection_time}")
        lines.append("")

        # 数据概览
        lines.append("【数据概览】")
        lines.append(f"  隐私政策声明数据项: {result.declared_data_summary.get('total_declared', 0)} 项")
        lines.append(f"  实际收集数据项: {result.collected_data_summary.get('total_collected', 0)} 项")
        lines.append(f"  总泄露次数: {result.collected_data_summary.get('total_leaks', 0)} 次")
        lines.append("")

        # 检测结果摘要
        summary = result.summary
        lines.append("【检测结果摘要】")
        lines.append(f"  检测到违规总数: {summary.get('total_violations', 0)} 项")
        lines.append("")

        by_type = summary.get('by_type', {})
        if by_type:
            lines.append("  按违规类型:")
            for vtype, count in by_type.items():
                lines.append(f"    - {vtype}: {count} 项")
            lines.append("")

        by_severity = summary.get('by_severity', {})
        if by_severity:
            lines.append("  按严重程度:")
            for severity, count in by_severity.items():
                icon = "🔴" if severity == "高" else ("🟡" if severity == "中" else "🟢")
                lines.append(f"    - {icon} {severity}风险: {count} 项")
            lines.append("")

        # 详细违规列表
        violations_by_type = defaultdict(list)
        for v in result.violations:
            violations_by_type[v.violation_type].append(v)

        # APP未声明收集
        if ViolationType.APP_UNDECLARED in violations_by_type:
            violations = violations_by_type[ViolationType.APP_UNDECLARED]
            lines.append("-" * 70)
            lines.append(f"【{ViolationType.APP_UNDECLARED.value}】 共 {len(violations)} 项")
            lines.append("-" * 70)

            for i, v in enumerate(violations, 1):
                severity_icon = "🔴" if v.severity == "高" else ("🟡" if v.severity == "中" else "🟢")
                lines.append(f"  {i}. {severity_icon} {v.data_field}")
                lines.append(f"     类别: {v.category}")
                lines.append(f"     来源: {v.source}")
                lines.append(f"     收集次数: {v.count}")
                lines.append(f"     详情: {v.details}")
                lines.append("")

        # SDK未声明收集
        if ViolationType.SDK_UNDECLARED in violations_by_type:
            violations = violations_by_type[ViolationType.SDK_UNDECLARED]
            lines.append("-" * 70)
            lines.append(f"【{ViolationType.SDK_UNDECLARED.value}】 共 {len(violations)} 项")
            lines.append("-" * 70)

            # 按SDK分组显示
            by_sdk = defaultdict(list)
            for v in violations:
                by_sdk[v.sdk_name or v.source].append(v)

            for sdk_name, sdk_violations in by_sdk.items():
                lines.append(f"  ▶ SDK: {sdk_name}")
                for i, v in enumerate(sdk_violations, 1):
                    severity_icon = "🔴" if v.severity == "高" else ("🟡" if v.severity == "中" else "🟢")
                    lines.append(f"    {i}. {severity_icon} {v.data_field} ({v.category})")
                    lines.append(f"       收集次数: {v.count}")
                lines.append("")

        # 模糊声明
        if ViolationType.VAGUE_DECLARATION in violations_by_type:
            violations = violations_by_type[ViolationType.VAGUE_DECLARATION]
            lines.append("-" * 70)
            lines.append(f"【{ViolationType.VAGUE_DECLARATION.value}】 共 {len(violations)} 项")
            lines.append("-" * 70)

            for i, v in enumerate(violations, 1):
                lines.append(f"  {i}. 模糊表述: 「{v.data_field}」")
                lines.append(f"     {v.details}")
                if v.declared_text:
                    lines.append(f"     原文: {v.declared_text}")
                lines.append("")

        # 结尾
        lines.append("=" * 70)
        lines.append("                      报告结束")
        lines.append("=" * 70)

        report_text = "\n".join(lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"✓ 文本报告已保存至: {output_path}")

        return report_text

    @staticmethod
    def generate_csv_report(result: DetectionResult, output_path: str):
        """生成CSV格式报告（便于导入Excel分析）"""
        import csv

        with open(output_path, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)

            # 写入表头
            writer.writerow([
                '违规类型', '数据字段', '行为字段', '类别',
                '来源', 'SDK名称', '收集次数', '严重程度', '详情'
            ])

            # 写入数据
            for v in result.violations:
                writer.writerow([
                    v.violation_type.value,
                    v.data_field,
                    v.behavior_field,
                    v.category,
                    v.source,
                    v.sdk_name,
                    v.count,
                    v.severity,
                    v.details,
                ])

        print(f"✓ CSV报告已保存至: {output_path}")


# ============================================================
# 第八部分：主程序
# ============================================================

class PrivacyViolationAnalyzer:
    """隐私违规分析器 - 主入口类"""

    def __init__(self, it_info_path: str, device_info_path: str, sdk_list_path: str = None):
        """
        初始化分析器

        Args:
            it_info_path: 信息类别列表文件路径
            device_info_path: 字段映射配置文件路径
            sdk_list_path: SDK列表文件路径（可选）
        """
        self.mapper = PrivacyDataMapper(it_info_path, device_info_path, sdk_list_path)
        self.detector = PrivacyViolationDetector(self.mapper)

    def analyze(self, declaration_path: str, behavior_path: str) -> DetectionResult:
        """
        执行分析

        Args:
            declaration_path: LLM提取结果文件路径 (jsonl格式)
            behavior_path: 行为分析结果文件路径 (json格式)

        Returns:
            DetectionResult: 检测结果
        """
        # 加载数据
        print(f"正在加载声明数据: {declaration_path}")
        llm_results = ConfigLoader.load_jsonl(declaration_path)
        print(f"  - 加载了 {len(llm_results)} 条声明记录")

        print(f"正在加载行为数据: {behavior_path}")
        leak_data = ConfigLoader.load_json(behavior_path)
        print(f"  - 包名: {leak_data.get('package', 'N/A')}")
        print(f"  - 总泄露次数: {leak_data.get('summary', {}).get('total_leaks', 0)}")

        # 执行检测
        print("\n正在执行违规检测...")
        result = self.detector.detect(llm_results, leak_data)
        print(f"  - 检测到 {len(result.violations)} 项违规")

        return result

    def generate_reports(self, result: DetectionResult, output_prefix: str,
                         formats: List[str] = None):
        """
        生成报告

        Args:
            result: 检测结果
            output_prefix: 输出文件名前缀
            formats: 输出格式列表 ['json', 'text', 'csv']
        """
        if formats is None:
            formats = ['json', 'text', 'csv']

        print("\n正在生成报告...")

        if 'json' in formats:
            ReportGenerator.generate_json_report(result, f"{output_prefix}.json")

        if 'text' in formats:
            report_text = ReportGenerator.generate_text_report(result, f"{output_prefix}.txt")
            # 同时打印到控制台
            print("\n" + report_text)

        if 'csv' in formats:
            ReportGenerator.generate_csv_report(result, f"{output_prefix}.csv")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='隐私泄露检测脚本 - 对比隐私政策声明与APP实际行为',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python privacy_violation_detector.py \\
      -d result/llm_extraction_results.jsonl \\
      -b leak.json \\
      --it-info analysis/it_info.json \\
      --device-info analysis/device_info.json \\
      --sdk-list analysis/sdk_list.json \\
      -o violation_report
        """
    )

    parser.add_argument('--declaration', '-d', required=True,
                        help='LLM提取结果文件路径 (llm_extraction_results.jsonl)')
    parser.add_argument('--behavior', '-b', required=True,
                        help='行为分析结果文件路径 (leak.json)')
    parser.add_argument('--it-info', required=True,
                        help='信息类别列表文件路径 (it_info.json)')
    parser.add_argument('--device-info', required=True,
                        help='字段映射配置文件路径 (device_info.json)')
    parser.add_argument('--sdk-list', default=None,
                        help='SDK列表文件路径 (可选)')
    parser.add_argument('--output', '-o', default='violation_report',
                        help='输出报告文件名前缀 (默认: violation_report)')
    parser.add_argument('--format', '-f', nargs='+',
                        choices=['json', 'text', 'csv'],
                        default=['json', 'text', 'csv'],
                        help='输出格式 (默认: json text csv)')

    args = parser.parse_args()

    # 创建分析器
    analyzer = PrivacyViolationAnalyzer(
        it_info_path=args.it_info,
        device_info_path=args.device_info,
        sdk_list_path=args.sdk_list
    )

    # 执行分析
    result = analyzer.analyze(args.declaration, args.behavior)

    # 生成报告
    analyzer.generate_reports(result, args.output, args.format)

    # 返回违规数量作为退出码（0表示无违规）
    return min(len(result.violations), 255)


if __name__ == "__main__":
    exit(main())

