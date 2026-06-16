"""Privacy policy and runtime behavior compliance checks."""

from datetime import datetime
import json
from pathlib import Path
import re


class ComplianceChecker:
    """Evaluate the eight privacy compliance rules used by the UI."""

    LABEL_ALIASES = {
        "A1": {"处理者"},
        "C1": {"个人信息收集与使用"},
        "C2": {"处理的个人信息类别"},
        "C4": {"个人信息来源"},
        "D1": {"个人信息分享"},
        "D2": {"接收方"},
        "E1": {"数据主体权利"},
        "E3": {"政策更新"},
        "E6": {"获取权", "访问权"},
        "E7": {"修改权", "更正权"},
        "E8": {"删除权"},
        "E11": {"撤回同意权", "注销权"},
        "F1": {"投诉"},
        "I1": {"数据存储细节"},
        "I2": {"存储时长"},
        "I3": {"存储地点"},
        "J1": {"个人信息安全"},
    }
    CORE_MODULES = ("A1", "C1", "D1", "E1", "F1", "I1", "J1")
    R1_CORE_MODULE_PROXY_TAGS = {
        "A1": {"处理者", "身份"},
        "C1": {"个人信息收集与使用", "处理的个人信息类别", "个人信息来源", "处理目的"},
        "D1": {"个人信息分享", "合并分立"},
        "E1": {"数据主体权利", "获取权", "修改权", "删除权", "撤回同意权", "政策更新", "数据泄露通知"},
        "F1": {"响应时间", "拒绝情形", "投诉"},
        "I1": {"数据存储细节", "存储时长", "存储地点"},
        "J1": {"个人信息安全"},
    }
    STORAGE_PROXY_TAGS = {"数据存储细节", "存储时长", "存储地点", "处理方法"}
    RIGHTS_PROXY_TAGS = {
        "数据主体权利",
        "获取权",
        "修改权",
        "删除权",
        "撤回同意权",
        "知情权",
        "拒绝权",
        "自动决策权",
    }
    CORE_RIGHTS = {
        "E6": "获取权",
        "E7": "修改权",
        "E8": "删除权",
        "E11": "撤回同意权",
    }
    FIELD_ALIASES = {
        "imei": "IMEI",
        "imsi": "IMSI",
        "oaid": "OAID",
        "idfa": "IDFA",
        "idfv": "IDFV",
        "uuid": "UUID",
        "guid": "GUID",
        "android-id": "Android ID",
        "android_id": "Android ID",
        "deviceid": "device id",
        "wifi-mac": "MAC",
        "mac": "MAC",
        "ssid": "SSID",
        "bssid": "BSSID",
        "latitude": "GPS",
        "longitude": "GPS",
        "applist": "应用列表信息",
        "package": "包名信息",
        "appversion": "应用版本号",
        "osversion": "版本信息",
        "model": "型号",
        "realname": "真实姓名",
        "password": "密码",
    }
    OWN_CONTROLLERS = {"", "我们", "本公司", "本应用", "app", "application"}

    def __init__(self):
        self.compliance_result = {}
        explorer_dir = Path(__file__).resolve().parent.parent / "Explorer"
        analysis_dir = explorer_dir / "analysis"
        self.dumps_dir = explorer_dir / "dumps"
        self.it_info = self._load_json(analysis_dir / "it_info.json", {})
        self.sdk_info = self._load_json(analysis_dir / "sdk_info.json", [])

    def check(self, policy_result, behavior_result):
        policy_result = policy_result or {}
        behavior_result = behavior_result or {}
        policy = self._parse_policy(policy_result)
        behavior = self._parse_behavior(behavior_result)
        policy_compliance = self._perform_compliance_analysis(policy, behavior)
        overall_score = self._calculate_overall_score(
            policy_result.get("score", 0), behavior_result.get("score", 0)
        )
        violations = policy_compliance["violations"]
        statuses = policy_compliance["rules_status"].values()
        if violations:
            status = "non_compliant"
        elif "证据不足" in statuses:
            status = "inconclusive"
        else:
            status = "compliant"

        self.compliance_result = {
            "overall_score": overall_score,
            "status": status,
            "issues": [
                f"违规: {violation['name']} - {violation['reason']}"
                for violation in violations
            ],
            "policy_compliance": policy_compliance,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return self.compliance_result

    @staticmethod
    def _load_json(path, default):
        try:
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
        except (OSError, ValueError, TypeError):
            return default

    def _parse_policy(self, policy_result):
        labels = {str(label).strip() for label in policy_result.get("keywords_found", [])}
        ids = set()
        for label in labels:
            match = re.search(r"\b([A-Z][0-9]+(?:\.[0-9]+)?)\b", label.upper())
            if match:
                ids.add(match.group(1))

        entity_items = policy_result.get("llm_entities", []) or []
        declared_data = set(self._flatten_values(policy_result.get("declared_data", [])))
        receivers = set()
        controllers = set()
        texts = []
        for item in entity_items:
            if not isinstance(item, dict):
                continue
            text = str(item.get("text", "")).strip()
            if text:
                texts.append(text)
            for entity in item.get("entities", []) or []:
                if not isinstance(entity, dict):
                    continue
                label = str(entity.get("label", "")).lower()
                value = str(entity.get("text", "")).strip()
                if not value:
                    continue
                if label == "data":
                    declared_data.add(value)
                elif label == "receiver":
                    receivers.add(value)
                elif label == "controller":
                    controllers.add(value)
            declared_data.update(
                self._flatten_values(item.get("data_collected_or_shared", []))
            )
            receivers.update(self._flatten_values(item.get("receiver", [])))
            controllers.update(self._flatten_values(item.get("controller", [])))

        return {
            "labels": labels,
            "ids": ids,
            "declared_data": declared_data,
            "receivers": receivers,
            "controllers": controllers,
            "text": "\n".join(texts),
        }

    def _parse_behavior(self, behavior_result):
        leak_data = behavior_result.get("leak_data", behavior_result)
        records = (
            leak_data.get("records")
            or leak_data.get("leak_records")
            or behavior_result.get("leak_records")
            or []
        )
        summary = leak_data.get("summary") or behavior_result.get("leak_summary") or {}
        by_source = (
            leak_data.get("leak_by_source")
            or behavior_result.get("leak_by_source")
            or {}
        )
        accesses = []
        sdk_activities = []

        for record in records:
            if not isinstance(record, dict):
                continue
            record_sdk = record.get("sdk") or {}
            accesses.append(
                {
                    "item": self._standard_field(record.get("privacy_field", "")),
                    "category": str(
                        record.get("category_level1")
                        or record.get("category")
                        or "其他信息"
                    ),
                    "source": str(record.get("host") or record.get("source") or ""),
                    "sdk_name": str(record_sdk.get("name", "")),
                    "third_party": bool(record_sdk.get("is_third_party", False)),
                    "raw": record,
                }
            )
            if record_sdk.get("is_third_party"):
                sdk_activities.append(
                    {
                        "name": str(record_sdk.get("name", "")),
                        "company": str(record_sdk.get("company", "")),
                        "fields": [self._standard_field(record.get("privacy_field", ""))],
                    }
                )

        if not accesses:
            for category, category_info in summary.get("by_category", {}).items():
                for field in (category_info.get("fields", {}) if isinstance(category_info, dict) else {}):
                    accesses.append(
                        {
                            "item": self._standard_field(field),
                            "category": str(category),
                            "source": "",
                            "sdk_name": "",
                            "third_party": False,
                            "raw": {},
                        }
                    )

        api_entities = (
            behavior_result.get("api_simplified_result")
            or leak_data.get("api_simplified_result")
            or []
        )
        for entity in api_entities:
            if not isinstance(entity, dict):
                continue
            third_party = entity.get("entity_type") == "Third-Party"
            entity_name = str(entity.get("entity_name", ""))
            entity_fields = []
            for detail in entity.get("details", []) or []:
                for privacy_type in detail.get("privacy_types", []) or []:
                    item = str(privacy_type.get("type", "")).strip()
                    if item:
                        entity_fields.append(item)
                        accesses.append(
                            {
                                "item": item,
                                "category": str(detail.get("category", "其他信息")),
                                "source": entity_name,
                                "sdk_name": entity_name if third_party else "",
                                "third_party": third_party,
                                "raw": detail,
                            }
                        )
            if third_party:
                sdk_activities.append({
                    "name": entity_name,
                    "company": self._lookup_sdk_company(entity_name),
                    "fields": sorted(set(entity_fields)),
                })

        third_party = by_source.get("third_party", {}).get("sdks", {})
        for name, details in third_party.items():
            sdk_activities.append(
                {
                    "name": str(details.get("sdk_name") or name),
                    "company": str(details.get("company", "")),
                    "fields": [
                        self._standard_field(field)
                        for field in details.get("fields", [])
                    ],
                }
            )
        if not third_party:
            for name, details in summary.get("by_sdk", {}).items():
                if details.get("is_third_party"):
                    sdk_activities.append(
                        {
                            "name": str(name),
                            "company": "",
                            "fields": [
                                self._standard_field(field)
                                for field in details.get("fields", [])
                            ],
                        }
                    )

        agree_evidence = self._load_agree_gate_evidence(behavior_result)
        if agree_evidence is not None:
            pre_consent = agree_evidence["pre_click_apis"]
        else:
            timing_result = dict(leak_data) if isinstance(leak_data, dict) else {}
            timing_result.update(behavior_result)
            pre_consent = self._extract_pre_consent_accesses(timing_result, accesses)
        return {
            "accesses": self._unique_accesses(accesses),
            "sdk_activities": self._unique_sdks(sdk_activities),
            "pre_consent_accesses": pre_consent,
            "has_behavior_evidence": bool(accesses or sdk_activities),
            "has_consent_timing": pre_consent is not None,
            "agree_gate_evidence": agree_evidence,
        }

    def _load_agree_gate_evidence(self, behavior_result):
        """Read pre-click API evidence recorded on the first agreement page."""
        candidates = []
        for key in ("package_name", "package", "app_name"):
            value = str(behavior_result.get(key, "")).strip()
            if value and value.lower() not in {"unknown", "error"} and value not in candidates:
                candidates.append(value)

        for package_name in candidates:
            package_dir = self.dumps_dir / package_name
            if not package_dir.exists():
                continue
            checked_files = []
            pre_click_apis = []
            for path in sorted(package_dir.glob("*_AGREE_0/textual_semantics.json")):
                data = self._load_json(path, None)
                if not isinstance(data, dict) or not isinstance(data.get("pre_click_apis"), list):
                    continue
                checked_files.append(str(path))
                pre_click_apis.extend(data["pre_click_apis"])
            if checked_files:
                return {
                    "package_name": package_name,
                    "files": checked_files,
                    "pre_click_apis": pre_click_apis,
                }
        return None

    def _extract_pre_consent_accesses(self, behavior_result, accesses):
        explicit = []
        for key in ("pre_consent_accesses", "before_consent_accesses", "pre_consent_records"):
            if key in behavior_result:
                items = behavior_result.get(key) or []
                if not isinstance(items, (list, tuple, set)):
                    items = [items]
                for item in items:
                    if isinstance(item, dict):
                        explicit.append(
                            self._standard_field(
                                item.get("privacy_field")
                                or item.get("item")
                                or item.get("type")
                                or "个人信息"
                            )
                        )
                    else:
                        explicit.extend(self._flatten_values(item))
        if explicit:
            return explicit

        marked = []
        for access in accesses:
            raw = access.get("raw", {})
            phase = str(raw.get("phase") or raw.get("consent_phase") or "").lower()
            if (
                raw.get("before_consent") is True
                or raw.get("pre_consent") is True
                or raw.get("consent_granted") is False
                or phase in {"pre_consent", "before_consent", "before_agree", "startup"}
            ):
                marked.append(access.get("item") or "个人信息")
        if marked:
            return marked

        phase = str(
            behavior_result.get("phase")
            or behavior_result.get("consent_phase")
            or behavior_result.get("analysis_phase")
            or ""
        ).lower()
        if (
            behavior_result.get("consent_granted") is False
            or behavior_result.get("user_consented") is False
            or phase in {"pre_consent", "before_consent", "before_agree"}
        ):
            return [access["item"] for access in accesses]

        timing_keys = {
            "consent_granted",
            "user_consented",
            "phase",
            "consent_phase",
            "analysis_phase",
        }
        if timing_keys.intersection(behavior_result):
            return []
        return None

    def _perform_compliance_analysis(self, policy, behavior):
        report = {
            "violations": [],
            "rules_status": {},
            "evidence": {
                "actual_access_count": len(behavior["accesses"]),
                "third_party_sdk_count": len(behavior["sdk_activities"]),
                "consent_timing_available": behavior["has_consent_timing"],
                "agree_gate_evidence": behavior["agree_gate_evidence"],
                "rule_details": {},
            },
        }

        missing_modules = [
            code for code in self.CORE_MODULES if not self._has_r1_module(policy, code)
        ]
        self._set_rule(
            report,
            "R1",
            "结构完整性缺失",
            bool(missing_modules),
            "缺失表3-1第一层级核心模块中的任意一类(A1/C1/D1/E1/F1/I1/J1): "
            + ", ".join(missing_modules),
        )

        self._set_rule(
            report,
            "R2",
            "信息来源缺失",
            self._has_exact_tag(policy, "C2", "处理的个人信息类别")
            and not self._has_exact_tag(policy, "C4", "个人信息来源"),
            "存在处理的个人信息类别(C2)，但缺失个人信息来源(C4)",
        )

        missing_storage = [
            code
            for code, label in (("I2", "存储时长"), ("I3", "存储地点"))
            if not self._has_exact_tag(policy, code, label)
        ]
        storage_present = self._has_any_tag(policy, self.STORAGE_PROXY_TAGS) or self._has_id(
            policy, "I1"
        )
        self._set_rule(
            report,
            "R3",
            "存储生命周期缺失",
            storage_present and bool(missing_storage),
            "存在数据存储细节相关声明(I1)，但缺失: " + ", ".join(missing_storage),
        )

        missing_rights = [
            code
            for code, label in self.CORE_RIGHTS.items()
            if not self._has_exact_tag(policy, code, label)
        ]
        rights_present = self._has_any_tag(policy, self.RIGHTS_PROXY_TAGS) or self._has_id(
            policy, "E1"
        )
        self._set_rule(
            report,
            "R4",
            "用户核心权利缺失",
            rights_present and bool(missing_rights),
            "存在数据主体权利相关声明(E1)，但缺失: " + ", ".join(missing_rights),
        )
        self._set_rule(
            report,
            "R5",
            "政策更新机制缺失",
            not self._has_exact_tag(policy, "E3", "政策更新"),
            "隐私政策未包含政策更新机制(E3)",
        )

        pre_consent = behavior["pre_consent_accesses"]
        r6_reason = "未找到 AGREE_0 textual_semantics.json 中的 pre_click_apis 证据"
        if pre_consent:
            r6_reason = "同意按钮点击前检测到个人信息 API 访问: " + ", ".join(
                sorted(set(str(item) for item in pre_consent))[:8]
            )
        elif behavior["agree_gate_evidence"] is not None:
            r6_reason = "AGREE_0 页面 pre_click_apis 为空，未检测到同意前访问"
        self._set_rule(
            report,
            "R6",
            "未经同意收集",
            bool(pre_consent),
            r6_reason,
            evaluated=pre_consent is not None,
        )
        report["evidence"]["rule_details"]["R6"] = {
            "title": "R6 未经同意收集",
            "summary": r6_reason,
            "records": self._build_r6_records(pre_consent, behavior),
        }

        undisclosed_sdks = self._find_undisclosed_sdks(policy, behavior["sdk_activities"])
        self._set_rule(
            report,
            "R7",
            "违规扩散",
            bool(undisclosed_sdks),
            "实际参与个人信息处理但未披露参与事实或接收方的 SDK: "
            + ", ".join(undisclosed_sdks[:8]),
            evaluated=behavior["has_behavior_evidence"],
        )
        report["evidence"]["rule_details"]["R7"] = {
            "title": "R7 违规扩散",
            "summary": "实际参与个人信息处理但未披露参与事实或接收方的 SDK",
            "records": self._build_r7_records(undisclosed_sdks, behavior),
        }

        vague_matches = self._find_vague_disclosures(policy, behavior["accesses"])
        self._set_rule(
            report,
            "R8",
            "模糊披露",
            bool(vague_matches),
            "仅披露信息大类而实际访问了细粒度信息: "
            + "; ".join(vague_matches[:8]),
            evaluated=bool(policy["declared_data"] and behavior["accesses"]),
        )
        report["evidence"]["rule_details"]["R8"] = {
            "title": "R8 模糊披露",
            "summary": "隐私政策只披露信息大类，但动态分析访问了更细粒度的信息项",
            "records": self._build_r8_records(vague_matches, behavior),
        }
        return report

    def _build_r6_records(self, pre_consent, behavior):
        if pre_consent is None:
            return [{
                "结论": "证据不足",
                "说明": "未找到同意前/同意后阶段标记，无法判断是否发生同意前访问。",
            }]
        if not pre_consent:
            records = [{"结论": "未命中", "说明": "已找到同意页面证据，但 pre_click_apis 为空。"}]
        else:
            records = [{"同意前访问": str(item)} for item in pre_consent[:30]]

        agree_evidence = behavior.get("agree_gate_evidence") or {}
        files = agree_evidence.get("files") or []
        if files:
            records.append({"证据文件": "\n".join(files[:5])})
        return records

    def _build_r7_records(self, undisclosed_sdks, behavior):
        if not undisclosed_sdks:
            return [{"结论": "未命中", "说明": "动态分析未发现未披露的第三方 SDK 处理行为。"}]

        names = {str(name).strip() for name in undisclosed_sdks}
        records = []
        for sdk in behavior.get("sdk_activities", []):
            name = str(sdk.get("name", "")).strip()
            company = str(sdk.get("company", "")).strip()
            if name in names or company in names:
                fields = set(sdk.get("fields", []) or [])
                fields.update(
                    access.get("item", "")
                    for access in behavior.get("accesses", [])
                    if access.get("sdk_name") == name or access.get("source") == name
                )
                records.append({
                    "SDK": name or "-",
                    "公司": company or self._lookup_sdk_company(name) or "-",
                    "涉及字段": ", ".join(sorted(field for field in fields if field)) or "-",
                })
        return records or [{"未披露SDK": name} for name in sorted(names)]

    @staticmethod
    def _build_r8_records(vague_matches, behavior):
        if not vague_matches:
            return [{"结论": "未命中", "说明": "未发现“仅披露大类但实际访问细粒度信息”的证据。"}]

        records = []
        for match in vague_matches[:30]:
            broad, _, item = str(match).partition(" -> ")
            related = next(
                (access for access in behavior.get("accesses", []) if access.get("item") == item),
                {},
            )
            records.append({
                "政策披露大类": broad or "-",
                "实际访问细项": item or str(match),
                "动态分类": related.get("category", "-"),
                "来源/Host": related.get("source", "-"),
                "SDK": related.get("sdk_name", "-"),
            })
        return records

    def _find_undisclosed_sdks(self, policy, sdk_activities):
        if not sdk_activities:
            return []
        policy_text = "\n".join(
            [policy["text"], *policy["receivers"], *policy["controllers"]]
        ).lower()
        sharing_declared = self._has_label(policy, "D1") or bool(policy["receivers"])
        missing = []
        for sdk in sdk_activities:
            name = sdk.get("name", "").strip()
            company = sdk.get("company", "").strip()
            named = any(
                value and value.lower() in policy_text for value in (name, company)
            )
            if not sharing_declared or not named:
                missing.append(name or company or "未知第三方SDK")
        return sorted(set(missing))

    def _find_vague_disclosures(self, policy, accesses):
        declarations = policy["declared_data"]
        if not declarations:
            return []
        results = []
        for access in accesses:
            item = access["item"]
            category = access["category"]
            if not item or self._is_explicitly_declared(item, declarations):
                continue
            categories = self._categories_for_item(item, category)
            broad_terms = categories | self._broad_aliases(categories)
            declared_broad = [
                term for term in broad_terms if self._contains_term(term, declarations)
            ]
            if declared_broad:
                results.append(f"{declared_broad[0]} -> {item}")
        return sorted(set(results))

    def _categories_for_item(self, item, category):
        categories = {category} if category else set()
        item_lower = item.lower()
        for parent, children in self.it_info.items():
            if any(item_lower == str(child).lower() for child in children):
                categories.add(parent)
        return categories

    @staticmethod
    def _broad_aliases(categories):
        aliases = {
            "设备信息": {"设备标识", "设备标识符", "唯一标识符"},
            "位置信息": {"地理位置", "定位信息"},
            "个人信息": {"身份信息", "账户信息"},
        }
        terms = set()
        for category in categories:
            terms.update(aliases.get(category, set()))
        return terms

    def _has_label(self, policy, code):
        if self._has_id(policy, code):
            return True
        return bool(self.LABEL_ALIASES.get(code, set()).intersection(policy["labels"]))

    def _has_r1_module(self, policy, code):
        return self._has_id(policy, code) or self._has_any_tag(
            policy, self.R1_CORE_MODULE_PROXY_TAGS[code]
        )

    @staticmethod
    def _has_id(policy, code):
        return any(item == code or item.startswith(code + ".") for item in policy["ids"])

    @staticmethod
    def _has_any_tag(policy, tags):
        return bool(set(tags).intersection(policy["labels"]))

    def _has_exact_tag(self, policy, code, label):
        return self._has_id(policy, code) or label in policy["labels"]

    @staticmethod
    def _set_rule(report, rule_id, name, violated, reason, evaluated=True):
        if violated:
            report["violations"].append({"id": rule_id, "name": name, "reason": reason})
            report["rules_status"][rule_id] = "违规"
        elif evaluated:
            report["rules_status"][rule_id] = "合规"
        else:
            report["rules_status"][rule_id] = "证据不足"

    def _standard_field(self, field):
        field = str(field or "").strip()
        base = re.sub(r"-(?:word|token)$", "", field, flags=re.IGNORECASE)
        return self.FIELD_ALIASES.get(base.lower(), field)

    @staticmethod
    def _contains_term(term, candidates):
        term_lower = str(term).lower()
        return any(term_lower == str(candidate).lower() for candidate in candidates)

    @staticmethod
    def _is_explicitly_declared(item, declarations):
        item_lower = item.lower()
        for declaration in declarations:
            declaration_lower = str(declaration).lower()
            if item_lower in declaration_lower or declaration_lower == item_lower:
                return True
        return False

    @staticmethod
    def _flatten_values(value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value.strip() else []
        if isinstance(value, dict):
            return [str(item) for item in value.keys()]
        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value if str(item).strip()]
        return [str(value)]

    @staticmethod
    def _unique_accesses(accesses):
        unique = {}
        for access in accesses:
            key = (
                access.get("item"),
                access.get("category"),
                access.get("source"),
                access.get("sdk_name"),
            )
            unique[key] = access
        return list(unique.values())

    @staticmethod
    def _unique_sdks(sdks):
        unique = {}
        for sdk in sdks:
            key = sdk.get("name") or sdk.get("company")
            if key:
                if key in unique:
                    existing = unique[key]
                    existing_fields = set(existing.get("fields", []) or [])
                    existing_fields.update(sdk.get("fields", []) or [])
                    existing["fields"] = sorted(existing_fields)
                    if not existing.get("company") and sdk.get("company"):
                        existing["company"] = sdk.get("company")
                else:
                    unique[key] = sdk
        return list(unique.values())

    def _lookup_sdk_company(self, sdk_name):
        sdk_name = str(sdk_name or "").strip().lower()
        if not sdk_name:
            return ""
        for sdk in self.sdk_info:
            name = str(sdk.get("name", "")).strip()
            if not name:
                continue
            name_lower = name.lower()
            if sdk_name == name_lower or sdk_name in name_lower or name_lower in sdk_name:
                return str(sdk.get("company", "")).strip()
        return ""

    @staticmethod
    def _calculate_overall_score(policy_score, behavior_score):
        return round(policy_score * 0.4 + behavior_score * 0.6, 1)
