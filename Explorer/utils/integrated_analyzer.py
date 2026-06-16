# utils/integrated_analyzer.py
"""
整合 API 调用分析与网络流量分析的结果
区分向外传输的信息类型
"""

import json
import os
from collections import defaultdict
from datetime import datetime


class IntegratedPrivacyAnalyzer:
    """
    整合分析器：将 API 分析结果和网络泄露分析结果合并
    """
    
    def __init__(self, it_info_path, device_info_path=None):
        """
        初始化整合分析器
        
        Args:
            it_info_path: it_info.json 路径（信息类型分类）
            device_info_path: device_info.json 路径（可选，用于字段分类映射）
        """
        self.it_info = self._load_json(it_info_path)
        self.device_info = self._load_json(device_info_path) if device_info_path else {}
        self.category_mapping = self._build_category_mapping()
    
    def _load_json(self, path):
        """加载 JSON 文件"""
        if path and os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    
    def _build_category_mapping(self):
        """构建信息类型到顶级分类的映射"""
        mapping = {}
        # 从 it_info 构建映射
        for top_cat, children in self.it_info.items():
            for child in children:
                mapping[child] = top_cat
        # 从 device_info 的 _categories 获取额外映射
        if "_categories" in self.device_info:
            for field, cats in self.device_info["_categories"].items():
                if isinstance(cats, list) and len(cats) > 0:
                    mapping[field] = cats[0]
        return mapping
    
    def _get_top_category(self, privacy_type):
        """获取隐私类型的顶级分类"""
        # 直接匹配
        if privacy_type in self.category_mapping:
            return self.category_mapping[privacy_type]
        
        # 模糊匹配
        privacy_lower = privacy_type.lower()
        for key, value in self.category_mapping.items():
            if key.lower() in privacy_lower or privacy_lower in key.lower():
                return value
        
        return "其他信息"
    
    def _parse_network_leak(self, leak_str):
        """
        解析网络泄露字符串
        格式: field%value[encode]*meta@crypt>host 或 field%value[encode]<host
        """
        info = {
            "raw": leak_str,
            "privacy_type": "",
            "value": "",
            "encode_type": "normal",
            "encrypted": False,
            "direction": "outbound",  # outbound(>) 或 inbound(<)
            "host": "",
            "meta": "",
            "is_crypt": False
        }
        
        try:
            remaining = leak_str
            
            # 解析字段名
            if "|" in remaining.split(">")[0].split("<")[0]:
                sep_idx = remaining.index("|")
                info["privacy_type"] = remaining[:sep_idx]
                remaining = remaining[sep_idx + 1:]
            elif "%" in remaining:
                sep_idx = remaining.index("%")
                info["privacy_type"] = remaining[:sep_idx]
                remaining = remaining[sep_idx + 1:]
            
            # 解析编码类型
            if "[" in remaining and "]" in remaining:
                bracket_start = remaining.index("[")
                bracket_end = remaining.index("]")
                encode_content = remaining[bracket_start+1:bracket_end]
                # 检查是否是加密标记
                if encode_content.startswith("crypt:") or ":" in encode_content:
                    info["is_crypt"] = True
                else:
                    info["encode_type"] = encode_content
            
            # 检测是否加密传输
            if "@" in remaining:
                info["encrypted"] = True
                info["is_crypt"] = True
            
            # 解析方向和主机
            if ">" in remaining:
                info["direction"] = "outbound"
                info["host"] = remaining.split(">")[-1].replace("/ws", "").strip()
            elif "<" in remaining:
                info["direction"] = "inbound"
                info["host"] = remaining.split("<")[-1].replace("/ws", "").strip()
            
            # 解析元数据位置
            if "*" in remaining:
                meta_start = remaining.index("*") + 1
                meta_end = len(remaining)
                for marker in ["@", ">", "<"]:
                    if marker in remaining[meta_start:]:
                        meta_end = min(meta_end, remaining.index(marker, meta_start))
                info["meta"] = remaining[meta_start:meta_end]
            
            # 提取值预览
            if "%" in leak_str:
                value_start = leak_str.index("%") + 1
                value_end = len(leak_str)
                for marker in ["[", "*", "@", ">", "<"]:
                    if marker in leak_str[value_start:]:
                        idx = leak_str.index(marker, value_start)
                        value_end = min(value_end, idx)
                info["value"] = leak_str[value_start:value_end][:100]  # 截断
                
        except Exception as e:
            info["parse_error"] = str(e)
        
        return info
    
    def integrate(self, leak_result, api_privacy_result, app_package="unknown"):
        """
        整合网络泄露分析和 API 调用分析的结果
        
        Args:
            leak_result: leak.json 的内容（网络泄露分析结果）
            api_privacy_result: api_privacy_full.json 的内容（API 调用分析结果）
            app_package: 应用包名
            
        Returns:
            dict: 整合后的分析报告
        """
        report = {
            "app_package": app_package,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            
            # 总体统计
            "summary": {
                "total_info_types": 0,
                "api_access_count": 0,
                "network_leak_count": 0,
                "outbound_count": 0,
                "inbound_count": 0,
                "encrypted_count": 0,
                "plaintext_count": 0
            },
            
            # 按信息类型整合（核心）
            "by_info_type": {},
            
            # 网络传输详情（区分方向）
            "network_transmissions": {
                "outbound": [],  # 向外发送的数据
                "inbound": []    # 接收的数据
            },
            
            # 目标主机统计
            "target_hosts": {},
            
            # SDK 归因统计
            "sdk_summary": {},
            
            # 风险评估
            "risk_items": []
        }
        
        # 1. 处理网络泄露数据
        self._process_network_leaks(leak_result, report)
        
        # 2. 处理 API 调用数据
        self._process_api_calls(api_privacy_result, report)
        
        # 3. 生成风险评估
        self._generate_risk_assessment(report)
        
        # 4. 更新统计
        self._update_summary(report)
        
        return report
    
    def _process_network_leaks(self, leak_result, report):
        """处理网络泄露数据"""
        if not leak_result:
            return
        
        # 需要处理的泄露类型键
        leak_keys = [
            "http", "https", "http_crypt", "https_crypt",
            "non_http_packets", "non_http_crypt",
            "file_buffer", "file_buffer_crypt",
            "file", "file_crypt", "crypt_direct"
        ]
        
        for key in leak_keys:
            if key not in leak_result or not leak_result[key]:
                continue
            
            source_type = key  # 来源类型
            
            for leak_str in leak_result[key]:
                parsed = self._parse_network_leak(leak_str)
                privacy_type = parsed["privacy_type"]
                top_category = self._get_top_category(privacy_type)
                
                # 构建传输记录
                transmission = {
                    "privacy_type": privacy_type,
                    "top_category": top_category,
                    "value_preview": parsed["value"][:50] + "..." if len(parsed["value"]) > 50 else parsed["value"],
                    "encoding": parsed["encode_type"],
                    "encrypted": parsed["encrypted"] or parsed["is_crypt"],
                    "host": parsed["host"],
                    "source": source_type,
                    "meta": parsed["meta"]
                }
                
                # 按方向分类
                direction = parsed["direction"]
                report["network_transmissions"][direction].append(transmission)
                
                # 更新信息类型统计
                if privacy_type not in report["by_info_type"]:
                    report["by_info_type"][privacy_type] = {
                        "top_category": top_category,
                        "api_access_count": 0,
                        "network_outbound_count": 0,
                        "network_inbound_count": 0,
                        "encrypted_count": 0,
                        "plaintext_count": 0,
                        "target_hosts": set(),
                        "sources": set(),
                        "sdks": set()
                    }
                
                info_stat = report["by_info_type"][privacy_type]
                if direction == "outbound":
                    info_stat["network_outbound_count"] += 1
                else:
                    info_stat["network_inbound_count"] += 1
                
                if transmission["encrypted"]:
                    info_stat["encrypted_count"] += 1
                else:
                    info_stat["plaintext_count"] += 1
                
                info_stat["target_hosts"].add(parsed["host"])
                info_stat["sources"].add(source_type)
                
                # 更新主机统计
                host = parsed["host"]
                if host and host not in report["target_hosts"]:
                    report["target_hosts"][host] = {
                        "outbound_count": 0,
                        "inbound_count": 0,
                        "privacy_types": set(),
                        "encrypted_count": 0,
                        "plaintext_count": 0
                    }
                
                if host:
                    host_stat = report["target_hosts"][host]
                    if direction == "outbound":
                        host_stat["outbound_count"] += 1
                    else:
                        host_stat["inbound_count"] += 1
                    host_stat["privacy_types"].add(privacy_type)
                    if transmission["encrypted"]:
                        host_stat["encrypted_count"] += 1
                    else:
                        host_stat["plaintext_count"] += 1
    
    def _process_api_calls(self, api_result, report):
        """处理 API 调用数据"""
        if not api_result or "categories" not in api_result:
            return
        
        for category, cat_data in api_result.get("categories", {}).items():
            for record in cat_data.get("records", []):
                privacy_type = record.get("privacy_type", "unknown")
                sdk = record.get("sdk", "unknown")
                api = record.get("api", "unknown")
                
                # 更新信息类型统计
                if privacy_type not in report["by_info_type"]:
                    report["by_info_type"][privacy_type] = {
                        "top_category": category,
                        "api_access_count": 0,
                        "network_outbound_count": 0,
                        "network_inbound_count": 0,
                        "encrypted_count": 0,
                        "plaintext_count": 0,
                        "target_hosts": set(),
                        "sources": set(),
                        "sdks": set()
                    }
                
                info_stat = report["by_info_type"][privacy_type]
                info_stat["api_access_count"] += 1
                info_stat["sdks"].add(sdk)
                
                # 更新 SDK 统计
                if sdk not in report["sdk_summary"]:
                    report["sdk_summary"][sdk] = {
                        "api_call_count": 0,
                        "privacy_types": set(),
                        "apis_used": set()
                    }
                
                sdk_stat = report["sdk_summary"][sdk]
                sdk_stat["api_call_count"] += 1
                sdk_stat["privacy_types"].add(privacy_type)
                sdk_stat["apis_used"].add(api)
    
    def _generate_risk_assessment(self, report):
        """生成风险评估"""
        # 高风险信息类型
        high_risk_keywords = [
            "imei", "imsi", "phone", "contacts", "sms", "call_log",
            "location", "gps", "password", "token", "身份证", "手机号"
        ]
        
        medium_risk_keywords = [
            "android_id", "mac", "wifi", "installed_apps", "account",
            "email", "device_id", "oaid", "设备标识"
        ]
        
        for privacy_type, data in report["by_info_type"].items():
            ptype_lower = privacy_type.lower()
            
            # 判断风险等级
            risk_level = "low"
            for kw in high_risk_keywords:
                if kw in ptype_lower:
                    risk_level = "high"
                    break
            
            if risk_level == "low":
                for kw in medium_risk_keywords:
                    if kw in ptype_lower:
                        risk_level = "medium"
                        break
            
            # 如果有明文外发，提升风险
            if data["network_outbound_count"] > 0 and data["plaintext_count"] > 0:
                if risk_level == "low":
                    risk_level = "medium"
                elif risk_level == "medium":
                    risk_level = "high"
            
            if data["network_outbound_count"] > 0 or data["api_access_count"] > 0:
                report["risk_items"].append({
                    "privacy_type": privacy_type,
                    "top_category": data["top_category"],
                    "risk_level": risk_level,
                    "api_access": data["api_access_count"],
                    "outbound": data["network_outbound_count"],
                    "plaintext_outbound": data["plaintext_count"],
                    "target_hosts_count": len(data["target_hosts"])
                })
        
        # 按风险等级排序
        risk_order = {"high": 0, "medium": 1, "low": 2}
        report["risk_items"].sort(key=lambda x: (risk_order[x["risk_level"]], -x["outbound"]))
    
    def _update_summary(self, report):
        """更新统计摘要"""
        summary = report["summary"]
        
        summary["total_info_types"] = len(report["by_info_type"])
        
        for data in report["by_info_type"].values():
            summary["api_access_count"] += data["api_access_count"]
            summary["outbound_count"] += data["network_outbound_count"]
            summary["inbound_count"] += data["network_inbound_count"]
            summary["encrypted_count"] += data["encrypted_count"]
            summary["plaintext_count"] += data["plaintext_count"]
        
        summary["network_leak_count"] = summary["outbound_count"] + summary["inbound_count"]
        
        # 转换 set 为 list（JSON 序列化）
        for data in report["by_info_type"].values():
            data["target_hosts"] = list(data["target_hosts"])
            data["sources"] = list(data["sources"])
            data["sdks"] = list(data["sdks"])
        
        for host_data in report["target_hosts"].values():
            host_data["privacy_types"] = list(host_data["privacy_types"])
        
        for sdk_data in report["sdk_summary"].values():
            sdk_data["privacy_types"] = list(sdk_data["privacy_types"])
            sdk_data["apis_used"] = list(sdk_data["apis_used"])

    # 假设这是 IntegratedPrivacyAnalyzer 类中的 generate_text_report 方法

    def generate_text_report(self, integrated_report):
        lines = []
        lines.append("=" * 80)
        lines.append("              隐私数据分析整合报告（API + 网络流量）")
        lines.append("=" * 80)

        # 1. 总体统计 (保持不变)
        lines.append(f"应用包名: {integrated_report['app_package']}")
        lines.append(f"分析时间: {integrated_report['analysis_time']}")

        summary = integrated_report['summary']
        lines.append("\n【总体统计】")
        lines.append(f"  • 涉及隐私类型数: {summary.get('total_info_types', 0)} 种")
        lines.append(f"  • API 调用总次数: {summary.get('api_access_count', 0)} 次")
        lines.append(f"  • 网络传输总次数: {summary.get('network_leak_count', 0)} 次")
        lines.append(f"    - 向外发送 (⬆): {summary.get('outbound_count', 0)} 次")
        lines.append(f"    - 接收数据 (⬇): {summary.get('inbound_count', 0)} 次")
        lines.append(f"  • 加密传输: {summary.get('encrypted_count', 0)} 次")
        lines.append(
            f"  • 明文传输: {summary.get('plaintext_count', 0)} 次 {'⚠️' if summary.get('plaintext_count', 0) > 0 else ''}")

        # 2. 风险项概览 (利用 risk_items)
        risk_items = integrated_report.get('risk_items', [])
        lines.append("\n【风险概览 (按风险等级)】")

        risk_groups = defaultdict(list)
        for item in risk_items:
            risk_groups[item['risk_level']].append(item)

        for level in ['high', 'medium', 'low']:
            if risk_groups[level]:
                lines.append(f"  ▶ {level.upper()} 风险项 ({len(risk_groups[level])} 个):")
                for item in risk_groups[level]:
                    api_count = item['api_access']
                    net_count = item['outbound']
                    status = f"(API:{api_count} / ⬆:{net_count} / 明文:{item['plaintext_outbound']})"
                    lines.append(f"    - {item['privacy_type']} [{item['top_category']}] {status}")
                    if net_count > 0 and item.get('target_hosts'):
                        hosts = ", ".join(item['target_hosts'][:2])
                        lines.append(f"      -> 目标: {hosts}{'...' if len(item['target_hosts']) > 2 else ''}")

        # 3. 目标主机汇总 (保持不变，但格式略美化)
        lines.append("\n【数据外发目标主机 TOP 10】")
        sorted_hosts = sorted(integrated_report.get('target_hosts', {}).items(),
                              key=lambda x: x[1]['outbound_count'], reverse=True)

        for host, host_data in sorted_hosts[:10]:
            lines.append(f"  🌐 {host}")
            lines.append(f"     外发: {host_data['outbound_count']} | 接收: {host_data['inbound_count']}")
            lines.append(f"     加密: {host_data['encrypted_count']} | 明文: {host_data['plaintext_count']}")

            # 仅显示泄露的数据类型
            p_types = ", ".join(host_data['privacy_types'][:3])
            lines.append(f"     数据类型: {p_types}{'...' if len(host_data['privacy_types']) > 3 else ''}")

        # 4. 泄露路径详情 (新结构，提高价值)
        lines.append("\n【详细泄露路径分析】")
        lines.append("----------------------------------------------------------------------")

        # 使用 by_info_type 结构，按 Top Category 聚合
        aggregated_by_top_category = defaultdict(list)
        for p_type, data in integrated_report.get('by_info_type', {}).items():
            aggregated_by_top_category[data['top_category']].append({'type': p_type, 'data': data})

        for top_cat, items in aggregated_by_top_category.items():
            total_api = sum(item['data']['api_access_count'] for item in items)
            total_outbound = sum(item['data']['network_outbound_count'] for item in items)

            lines.append(f"\n📁 {top_cat} (API 总调用: {total_api} / 网络外发总数: {total_outbound})")

            for item in items:
                p_type = item['type']
                data = item['data']

                api_count = data['api_access_count']
                out_count = data['network_outbound_count']

                access_summary = f"API访问: {api_count} 次"
                leak_summary = f"外发: {out_count} 次 (明文:{data['plaintext_count']}, 加密:{data['encrypted_count']})"

                lines.append(f"  ▶ {p_type}")

                # API 访问详情
                if api_count > 0:
                    sdks = ", ".join(data['sdks']) if data['sdks'] else "未知"
                    lines.append(f"    - 内部使用: {access_summary} | SDK/实体: {sdks}")

                # 网络传输详情 (外发)
                if out_count > 0:
                    hosts = data['target_hosts']
                    host_str = hosts[0] if len(hosts) == 1 else f"{len(hosts)} 个目标"

                    # 查找具体的泄露记录，提供预览
                    leak_records = [r for r in integrated_report['network_transmissions']['outbound']
                                    if r['privacy_type'] == p_type]

                    if leak_records:
                        first_record = leak_records[0]
                        leak_status = "明文" if not first_record['encrypted'] else "加密"
                        preview = first_record['value_preview'][:50] + "..."

                        lines.append(f"    - 传输泄露: {leak_summary}")
                        lines.append(f"      -> 目标: {host_str} ({first_record['host']})")
                        lines.append(f"      -> 状态: {leak_status} | 预览: {preview}")

        # 5. SDK/实体行为摘要 (新结构，更实用)
        lines.append("\n【SDK/实体行为摘要】")
        lines.append("----------------------------------------------------------------------")

        sdk_summary = integrated_report.get('sdk_summary', {})

        for sdk_name, sdk_data in sdk_summary.items():
            lines.append(f"📦 实体: {sdk_name}")
            lines.append(f"  • API调用总数: {sdk_data['api_call_count']} 次")

            # 找出该 SDK 对应的网络传输 (虽然当前的 SDK 汇总中没有网络目标，但结构上应该包含)
            networked_types = []
            api_only_types = []

            for p_type in sdk_data['privacy_types']:
                p_data = integrated_report['by_info_type'].get(p_type, {})
                if p_data.get('network_outbound_count', 0) > 0:
                    networked_types.append(p_type)
                else:
                    api_only_types.append(p_type)

            lines.append(f"  • 仅内部访问数据类型 ({len(api_only_types)} 种): {', '.join(api_only_types[:5])}...")

            if networked_types:
                lines.append(f"  • **存在传输风险的数据类型 ({len(networked_types)} 种):**")
                for p_type in networked_types:
                    p_data = integrated_report['by_info_type'][p_type]
                    hosts = ", ".join(p_data['target_hosts'][:2])
                    lines.append(f"    - {p_type} (外发:{p_data['network_outbound_count']} 次, 目标:{hosts})")

        lines.append("\n" + "=" * 80)
        return "\n".join(lines)

    def save_report(self, integrated_report, output_dir):
        """保存整合报告"""
        # JSON 格式
        json_path = os.path.join(output_dir, "integrated_privacy_report.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(integrated_report, f, ensure_ascii=False, indent=2)
        
        # 文本格式
        text_report = self.generate_text_report(integrated_report)
        text_path = os.path.join(output_dir, "integrated_privacy_report.txt")
        with open(text_path, 'w', encoding='utf-8') as f:
            f.write(text_report)
        
        return json_path, text_path
