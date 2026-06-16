import json
import os
from collections import defaultdict
from urllib.parse import unquote


class APIPrivacyAnalyzer:
    """
    兼容性优化的隐私分析器
    对接主分析函数，支持 SDK 归因、详细统计与摘要输出
    """

    SENSITIVE_URI_PATTERNS = {
        'contacts': ['content://com.android.contacts', 'content://contacts', 'contactscontract'],
        'calllog': ['content://call_log', 'content://calls', 'calllog.calls'],
        'sms': ['content://sms', 'content://mms', 'content://mms-sms'],
        'calendar': ['content://com.android.calendar', 'calendarcontract'],
        'media': ['content://media/', 'mediastore'],
        'oaid': ['idprovider/identifierid', 'vivo.vms.idprovider', 'huawei.hms.ads', 'xiaomi.ad.identifier']
    }

    MUST_RECORD_METHODS = [
        'getDeviceId', 'getImei', 'getSimSerialNumber', 'getSubscriberId',
        'getScanResults', 'open', 'takePicture', 'startRecording', 'getCurrentLocation'
    ]

    def __init__(self, api_info_path, itinfo_path, sdk_info_path=None):
        """初始化，增加对 sdk_info 的可选支持"""
        self.api_mapping, self.conditional_apis = self._load_api_mapping(api_info_path)
        self.type_to_top = self._load_itinfo_categories(itinfo_path)

        # 如果提供了 sdk_info 路径则加载，否则使用默认归因
        if sdk_info_path and os.path.exists(sdk_info_path):
            self.sdk_features = self._load_sdk_info(sdk_info_path)
        else:
            self.sdk_features = []
            print("⚠️ 警告：未提供有效的 sdk_info_path，将无法进行第三方SDK识别。")

    def _load_itinfo_categories(self, itinfo_file):
        with open(itinfo_file, 'r', encoding='utf-8') as f:
            itinfo = json.load(f)
        mapping = {}
        for top_cat, children in itinfo.items():
            for item in children:
                if item not in mapping: mapping[item] = set()
                mapping[item].add(top_cat)
        return mapping

    def _load_api_mapping(self, json_file):
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        simple, conditional = {}, defaultdict(list)
        for item in data:
            cls, method = item.get('class', ''), item.get('method') or item.get('field', '')
            if not cls or not method: continue
            key = (cls, method)
            info = {'privacy_type': item.get('type', '未知'), 'category': item.get('category', ''),
                    'note': item.get('note', '')}
            if info['note'] or cls == 'android.content.ContentResolver':
                conditional[key].append(info)
            else:
                simple[key] = info
        return simple, dict(conditional)

    def _load_sdk_info(self, sdk_info_path):
        with open(sdk_info_path, 'r', encoding='utf-8') as f:
            sdk_data = json.load(f)
        flat = []
        for sdk in sdk_data:
            # 关键：我们只关注 package 前缀匹配
            for pkg in sdk.get('packages', []):
                flat.append({'prefix': pkg, 'name': sdk['name'], 'company': sdk['company']})

        # 确保更长的包名前缀优先匹配
        flat.sort(key=lambda x: len(x['prefix']), reverse=True)
        return flat

    def _identify_sdk(self, called_from):
        if not called_from: return "系统/核心库"
        for feature in self.sdk_features:
            if called_from.startswith(feature['prefix']):
                return feature['name']
        return "应用自身业务"

    def _match_api(self, log):
        cls, method, args = log.get('class', ''), log.get('method', ''), log.get('args', [])
        key = (cls, method)
        if cls == 'android.content.ContentResolver' and args:
            uri = unquote(str(args[0]).lower())
            for noise in ['sensorsdata', 'umeng', 'bugly', 'fileprovider']:
                if noise in uri: return None
            for u_type, patterns in self.SENSITIVE_URI_PATTERNS.items():
                if any(p in uri for p in patterns):
                    return {'privacy_type': f"访问{u_type}", 'note': f"URI: {args[0]}"}
            return None
        if key in self.conditional_apis:
            for rule in self.conditional_apis[key]:
                note_kw = rule['note'].split('=')[-1].lower() if '=' in rule['note'] else ""
                if not note_kw or any(note_kw in str(a).lower() for a in args): return rule
        return self.api_mapping.get(key)

    def analyze_app(self, app_dir):
        """核心方法：按照你主逻辑要求的接口返回'详细版'结果"""
        all_records = []
        for stage in [1, 2]:
            file_path = os.path.join(app_dir, f"permission-{stage}.txt")
            if not os.path.exists(file_path): continue
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log = json.loads(line)
                        rule = self._match_api(log)
                        if not rule: continue
                        ret_val = log.get('returnValue', '')
                        if (log.get('method') not in self.MUST_RECORD_METHODS) and \
                                (ret_val in ['null', '[]', '{}', '', None] and not log.get('args')):
                            continue
                        sdk_info = self._identify_sdk(log.get('calledFrom', ''))  # <-- 返回可能是字符串或字典

                        # 处理 sdk_info
                        sdk_name = sdk_info['name'] if isinstance(sdk_info, dict) else sdk_info
                        sdk_company = sdk_info.get('company', '') if isinstance(sdk_info, dict) else ''
                        is_third_party = isinstance(sdk_info, dict)  # 明确标记是否为第三方

                        all_records.append({
                            'timestamp': log.get('ts', ''),
                            'privacy_type': rule['privacy_type'],
                            'api': f"{log.get('class')}.{log.get('method')}",
                            'return_value': str(ret_val)[:150],
                            'called_from': log.get('calledFrom', 'unknown'),

                            # ✨ 关键：增加清晰的 SDK 归因字段
                            'sdk_name': sdk_name,
                            'sdk_company': sdk_company,
                            'is_third_party': is_third_party,
                        })
                    except:
                        continue

        # 构建详细报告结构
        report = {"summary": {"total_calls": len(all_records)}, "categories": {}}
        for r in all_records:
            top_cats = list(self.type_to_top.get(r['privacy_type'], ["其他信息"]))
            for top_cat in top_cats:
                if top_cat not in report["categories"]:
                    report["categories"][top_cat] = {"count": 0, "privacy_types": defaultdict(int),
                                                     "api_calls": defaultdict(int), "records": []}
                node = report["categories"][top_cat]
                node["count"] += 1
                node["privacy_types"][r['privacy_type']] += 1
                node["api_calls"][r['api']] += 1
                node["records"].append(r)

        # 转换 defaultdict
        for cat in report["categories"]:
            report["categories"][cat]["privacy_types"] = dict(report["categories"][cat]["privacy_types"])
            report["categories"][cat]["api_calls"] = dict(report["categories"][cat]["api_calls"])

        report["summary"]["category_count"] = len(report["categories"])
        return report

    def get_simplified_result(self, privacy_result):
        # 聚合结构: {entity_key: {category_name: {privacy_type: count}}}
        aggregator = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        app_package = privacy_result.get("package", "Unknown_App")
        app_entity_key = f"App_{app_package}"

        # 1. 遍历所有记录并进行三级聚合 (与之前保持一致)
        for category_name, cat_data in privacy_result.get("categories", {}).items():
            for rec in cat_data.get("records", []):
                privacy_type = rec['privacy_type']
                if rec.get('is_third_party', False):
                    sdk_name = rec.get('sdk_name', 'Unknown_SDK')
                    key = sdk_name
                else:
                    key = app_entity_key
                aggregator[key][category_name][privacy_type] += 1

        # 2. 辅助函数：将三级聚合转换为合并后的 details 列表
        def build_merged_details_list(agg_data):
            merged_details = []

            # 按 Category 遍历
            for category, types_map in agg_data.items():
                privacy_types_list = []
                total_count = 0

                # 遍历 Privacy Type
                for ptype, count in types_map.items():
                    privacy_types_list.append({
                        "type": ptype,
                        "count": count
                    })
                    total_count += count

                # 将该 Category 下的所有 Type 合并为一个记录
                if privacy_types_list:
                    merged_details.append({
                        "category": category,
                        "privacy_types": privacy_types_list,
                        "total_count": total_count
                    })

            return merged_details

        # 3. 构建 simplified 列表 (App-Owned 优先)
        simplified = []

        # 优先处理 App-Owned
        if app_entity_key in aggregator:
            app_findings = aggregator.pop(app_entity_key)
            app_item = {
                "entity_type": "App-Owned",
                "entity_name": app_package,
                "details": build_merged_details_list(app_findings)
            }
            simplified.append(app_item)

        # 处理第三方 SDK
        for sdk_name, findings in aggregator.items():
            sdk_item = {
                "entity_type": "Third-Party",
                "entity_name": sdk_name,
                "details": build_merged_details_list(findings)
            }
            simplified.append(sdk_item)
        return simplified

    def print_summary(self, privacy_result):
        """兼容性方法：打印控制台摘要"""
        print("\n" + "=" * 50)
        print(f"📱 隐私调用分析完成 - 总计: {privacy_result['summary']['total_calls']} 次")
        for cat, data in privacy_result['categories'].items():
            print(f" • [{cat}]: {data['count']} 次")
        print("=" * 50)

    def save_result(self, result, output_file):
        """兼容性方法：保存 JSON"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    def _extract_package_from_called_from(self, called_from):
        """
        从 called_from 字符串中提取最可能的包名/类名部分。
        示例: com.alipay.sdk.app.b.a(SourceFile:23) -> com.alipay.sdk.app.b
        """
        if not called_from:
            return None

        # 1. 移除源文件信息 (e.g., (SourceFile:23) 或 (A.java:42))
        called_from = called_from.split('(')[0].strip()

        # 2. 移除方法名 (最后一个 .)
        # 示例: com.alipay.sdk.app.b.a -> com.alipay.sdk.app.b
        if '.' in called_from and not called_from.endswith('.'):
            # 找到最后一个 '.' 之前的部分，即类名
            return called_from.rsplit('.', 1)[0]

        return called_from

    def _identify_sdk(self, called_from):
        if not called_from:
            return "系统/核心库"

        # 提取类名/包名进行匹配
        package_or_class = self._extract_package_from_called_from(called_from)

        if not package_or_class:
            return "应用自身业务"  # 无法解析，默认认为是应用自身

        for feature in self.sdk_features:
            # 使用提取出的包名/类名进行前缀匹配
            if package_or_class.startswith(feature['prefix']):
                # 优化：如果匹配到 SDK，返回 SDK 的完整信息
                return {
                    'name': feature['name'],
                    'company': feature['company'],
                    'match_package': feature['prefix']
                }

        # 如果没有匹配到任何 SDK
        # 简单判断是否是系统包名（如 android., java., sun. 等）
        if package_or_class.startswith(('android.', 'java.', 'sun.', 'org.apache.')):
            return "系统/核心库"

        # 既不是已知SDK也不是系统库，认为是应用自身
        return "应用自身业务"

