"""Manual test entry point for compliance rules R6-R8.

Examples:
    python manual_test_r678.py ^
        --policy result/app/llm_extraction_results.jsonl ^
        --behavior ../Explorer/analysis/sac/app/leak.json ^
        --package com.example.app

    python manual_test_r678.py ^
        --policy result/app/policy_result.json ^
        --behavior ../Explorer/analysis/sac/app/leak.json ^
        --api-summary ../Explorer/analysis/sac/app/api_privacy_summary.json ^
        --output r678_test_result.json
"""

import argparse
import json
from pathlib import Path

from compliance_checker import ComplianceChecker


RULE_NAMES = {
    "R6": "未经同意收集",
    "R7": "违规扩散",
    "R8": "模糊披露",
}


def _load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def _load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} 第 {line_number} 行不是有效 JSON: {exc}") from exc
    return rows


def load_policy_result(policy_path):
    """Load a policy analyzer JSON result or LLM extraction JSONL file."""
    path = Path(policy_path)
    if path.suffix.lower() == ".jsonl":
        entities = _load_jsonl(path)
        labels = []
        for item in entities:
            labels.extend(item.get("label", []) if isinstance(item, dict) else [])
        return {
            "keywords_found": sorted(set(labels)),
            "llm_entities": entities,
        }

    result = _load_json(path)
    if isinstance(result, list):
        labels = []
        for item in result:
            labels.extend(item.get("label", []) if isinstance(item, dict) else [])
        return {
            "keywords_found": sorted(set(labels)),
            "llm_entities": result,
        }
    if not isinstance(result, dict):
        raise ValueError("隐私政策分析文件应为 JSON 对象、JSON 数组或 JSONL 文件")
    return result


def load_behavior_result(behavior_path, package_name=None, api_summary_path=None):
    """Load anal5 leak.json and attach optional data needed by the checker."""
    result = _load_json(Path(behavior_path))
    if not isinstance(result, dict):
        raise ValueError("应用行为分析文件应为 anal5 输出的 JSON 对象")

    if package_name:
        result["package_name"] = package_name
    elif result.get("package") and not result.get("package_name"):
        result["package_name"] = result["package"]

    if api_summary_path:
        api_summary = _load_json(Path(api_summary_path))
        if not isinstance(api_summary, list):
            raise ValueError("api_privacy_summary.json 应为实体列表")
        result["api_simplified_result"] = api_summary
    return result


def run_manual_r678_test(
    policy_path,
    behavior_path,
    package_name=None,
    api_summary_path=None,
    output_path=None,
):
    """Run R6-R8 checks using manually selected policy and behavior files."""
    policy_result = load_policy_result(policy_path)
    behavior_result = load_behavior_result(behavior_path, package_name, api_summary_path)
    result = ComplianceChecker().check(policy_result, behavior_result)
    compliance = result["policy_compliance"]
    violations = {item["id"]: item for item in compliance.get("violations", [])}

    report = {
        "inputs": {
            "policy": str(policy_path),
            "behavior": str(behavior_path),
            "package_name": behavior_result.get("package_name", ""),
            "api_summary": str(api_summary_path) if api_summary_path else "",
        },
        "rules": {
            rule_id: {
                "name": name,
                "status": compliance["rules_status"].get(rule_id, "证据不足"),
                "reason": violations.get(rule_id, {}).get("reason", _normal_reason(rule_id, compliance)),
            }
            for rule_id, name in RULE_NAMES.items()
        },
        "evidence": compliance.get("evidence", {}),
    }

    print_manual_report(report)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2)
        print(f"\n结果 JSON 已保存: {output_path}")
    return report


def _normal_reason(rule_id, compliance):
    status = compliance["rules_status"].get(rule_id)
    if rule_id == "R6":
        evidence = compliance.get("evidence", {}).get("agree_gate_evidence")
        if status == "合规" and evidence is not None:
            return "AGREE_0 页面 pre_click_apis 为空，未检测到同意前访问"
        return "未发现违规证据" if status == "合规" else "未找到 AGREE_0 证据文件"
    if rule_id == "R7":
        return "未检测到未披露的第三方 SDK 处理行为"
    return "未检测到仅声明大类而实际访问细粒度信息的情况"


def print_manual_report(report):
    print("=" * 68)
    print("R6-R8 人工核验结果")
    print("=" * 68)
    print(f"隐私政策文件: {report['inputs']['policy']}")
    print(f"行为分析文件: {report['inputs']['behavior']}")
    print(f"应用包名:     {report['inputs']['package_name'] or '未提供'}")

    for rule_id in ("R6", "R7", "R8"):
        item = report["rules"][rule_id]
        print(f"\n{rule_id} {item['name']}: {item['status']}")
        print(f"  说明: {item['reason']}")

    evidence = report["evidence"]
    agree = evidence.get("agree_gate_evidence")
    print("\n证据摘要:")
    if agree:
        print(f"  R6 检查文件数: {len(agree.get('files', []))}")
        for path in agree.get("files", []):
            print(f"    - {path}")
        print(f"  pre_click_apis: {agree.get('pre_click_apis', [])}")
    else:
        print("  R6: 未定位到 *_AGREE_0/textual_semantics.json")
    print(f"  实际访问信息项数: {evidence.get('actual_access_count', 0)}")
    print(f"  实际第三方 SDK 数: {evidence.get('third_party_sdk_count', 0)}")

def main():
    parser = argparse.ArgumentParser(description="人工指定文件核验 R6-R8 检测结果")
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY_PATH,
        help=f"隐私政策提取结果：llm_extraction_results.jsonl 或完整 policy_result.json；默认：{DEFAULT_POLICY_PATH}",
    )
    parser.add_argument(
        "--behavior",
        default=DEFAULT_BEHAVIOR_PATH,
        help=f"应用分析结果文件：anal5 生成的 leak.json；默认：{DEFAULT_BEHAVIOR_PATH}",
    )
    parser.add_argument(
        "--package",
        default=DEFAULT_PACKAGE_NAME,
        help=f"应用包名，用于查找 Explorer/dumps/<package>/*_AGREE_0；默认：{DEFAULT_PACKAGE_NAME}",
    )
    parser.add_argument(
        "--api-summary",
        default=DEFAULT_API_SUMMARY_PATH,
        help=f"可选：anal5 生成的 api_privacy_summary.json，可补充 R7/R8 API 访问证据；默认：{DEFAULT_API_SUMMARY_PATH}",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        help=f"可选：将 R6-R8 核验摘要保存为 JSON 文件；默认：{DEFAULT_OUTPUT_PATH}",
    )
    args = parser.parse_args()

    run_manual_r678_test(
        policy_path=args.policy,
        behavior_path=args.behavior,
        package_name=args.package,
        api_summary_path=args.api_summary,
        output_path=args.output,
    )

if __name__ == "__main__":
    DEFAULT_POLICY_PATH = r"/ui/result/七猫免费小说1\llm_extraction_results.jsonl"
    DEFAULT_BEHAVIOR_PATH = r"G:\iie\mylab\guitest\Explorer\analysis\sac_yes\com.kmxs.reader_all\leak.json"
    DEFAULT_PACKAGE_NAME = "com.kmxs.reader"
    DEFAULT_API_SUMMARY_PATH = r"G:\iie\mylab\guitest\Explorer\analysis\sac_yes\com.kmxs.reader_all\api_privacy_summary.json"
    DEFAULT_OUTPUT_PATH = r"G:\iie\mylab\guitest\r678_qimao_result.json"
    main()
