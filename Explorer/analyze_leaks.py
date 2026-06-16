#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import glob
import json
import os
from collections import Counter, defaultdict

NETWORK_SOURCES = {"http", "https"}
FILE_SOURCES_PREFIX = ("file_", "file")     # e.g., file_buffer
CRYPT_SOURCES_PREFIX = ("crypt",)           # e.g., crypt_direct


def safe_get(d, path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def is_file_record(r: dict) -> bool:
    src = (r.get("source") or "").lower()
    host = (r.get("host") or "").lower()
    if src.startswith(FILE_SOURCES_PREFIX):
        return True
    # 你的文件 host 里常直接带 /storage... 或 1-xxx-/storage...
    if "/storage/" in host or host.startswith("1-") and "/storage/" in host:
        return True
    return False


def is_crypt_record(r: dict) -> bool:
    src = (r.get("source") or "").lower()
    host = r.get("host") or ""
    if src.startswith(CRYPT_SOURCES_PREFIX):
        return True
    if host == "CryptoAPI":
        return True
    if isinstance(r.get("crypt"), dict):
        return True
    return False


def is_network_record(r: dict) -> bool:
    src = (r.get("source") or "").lower()
    host = (r.get("host") or "")
    if src in NETWORK_SOURCES:
        return True
    # 兜底：像 shop-gateway.tuhu.cn 这种 host（包含点）通常是网络
    if "." in host and host != "CryptoAPI":
        return True
    return False


def is_third_party_record(r: dict) -> bool:
    sdk = r.get("sdk") or {}
    crypt = r.get("crypt") or {}
    if isinstance(sdk, dict) and sdk.get("is_third_party") is True:
        return True
    if isinstance(crypt, dict) and crypt.get("third_party") is True:
        return True
    return False


def meta_is_nonempty(r: dict) -> bool:
    meta = r.get("meta")
    return isinstance(meta, str) and meta.strip() != ""


def parse_one_report(fp: str) -> dict:
    with open(fp, "r", encoding="utf-8") as f:
        data = json.load(f)

    package = data.get("package") or os.path.basename(os.path.dirname(fp))
    analysis_time = data.get("analysis_time", "")

    records = data.get("records") or []
    if not isinstance(records, list):
        records = []

    # 基础计数（尽量从 records 算，避免 summary 与 records 不一致）
    total = len(records)
    network_cnt = 0
    file_cnt = 0
    crypt_cnt = 0
    encrypted_cnt = 0
    plaintext_cnt = 0
    third_party_cnt = 0

    # 可解释性/结构化证据指标（你可在论文里叫“字段定位信息覆盖率”）
    network_meta_nonempty = 0
    network_total = 0

    # 编码/解码贡献（递归解码如果有，encode_type 往往不是 normal）
    decode_non_normal = 0

    # 覆盖统计
    cats_level1 = set()
    fields_set = set()
    hosts_set = set()
    file_paths_set = set()

    for r in records:
        if not isinstance(r, dict):
            continue

        # 分类/字段
        c1 = r.get("category_level1")
        if isinstance(c1, str) and c1.strip():
            cats_level1.add(c1.strip())

        pf = r.get("privacy_field")
        if isinstance(pf, str) and pf.strip():
            fields_set.add(pf.strip())

        # 三方
        if is_third_party_record(r):
            third_party_cnt += 1

        # 加密/明文
        if r.get("encrypted") is True:
            encrypted_cnt += 1
        else:
            plaintext_cnt += 1

        # decode类型
        enc_t = r.get("encode_type")
        if isinstance(enc_t, str) and enc_t.strip() and enc_t.strip().lower() != "normal":
            decode_non_normal += 1

        # 网络/文件/加密组件
        if is_network_record(r):
            network_cnt += 1
            h = r.get("host")
            if isinstance(h, str) and h.strip():
                hosts_set.add(h.strip())

            network_total += 1
            if meta_is_nonempty(r):
                network_meta_nonempty += 1

        if is_file_record(r):
            file_cnt += 1
            h = r.get("host")
            if isinstance(h, str) and h.strip():
                file_paths_set.add(h.strip())

        if is_crypt_record(r):
            crypt_cnt += 1

    meta_ratio = (network_meta_nonempty / network_total) if network_total else 0.0

    # 也读一下 summary（可用于交叉验证/补充）
    summary = data.get("summary") or {}
    summary_total = safe_get(summary, ["total_leaks"])
    summary_network = safe_get(summary, ["network_leak_count"])
    summary_file = safe_get(summary, ["local_file_count"])
    summary_enc = safe_get(summary, ["encrypted_count"])

    return {
        "file": fp,
        "package": package,
        "analysis_time": analysis_time,

        "total_leaks_records": total,
        "cats_level1_cnt": len(cats_level1),
        "unique_privacy_fields_cnt": len(fields_set),

        "network_records_cnt": network_cnt,
        "unique_hosts_cnt": len(hosts_set),

        "local_file_records_cnt": file_cnt,
        "unique_file_paths_cnt": len(file_paths_set),

        "crypt_related_records_cnt": crypt_cnt,
        "encrypted_records_cnt": encrypted_cnt,
        "plaintext_records_cnt": plaintext_cnt,

        "third_party_records_cnt": third_party_cnt,

        "network_meta_nonempty_ratio": round(meta_ratio, 4),
        "decode_non_normal_cnt": decode_non_normal,

        # summary（可选）
        "summary_total_leaks": summary_total if summary_total is not None else "",
        "summary_network_leaks": summary_network if summary_network is not None else "",
        "summary_local_file_leaks": summary_file if summary_file is not None else "",
        "summary_encrypted_count": summary_enc if summary_enc is not None else "",
    }


def build_ablation_rows(report: dict) -> dict:
    """
    用“过滤模拟”的方式，生成分析模块组件贡献（对应你论文 4.4 的实验支撑）。
    注意：这不是重新跑算法，而是基于输出记录做“关闭某组件后会少哪些记录”的近似统计。
    """
    total = report["total_leaks_records"]
    no_crypt = total - report["crypt_related_records_cnt"]
    no_file = total - report["local_file_records_cnt"]

    plaintext_only = report["plaintext_records_cnt"]
    network_only = report["network_records_cnt"]

    # “桥接贡献”你可以直接用 crypt_related 或 encrypted（看你论文怎么定义）
    crypt_only = report["crypt_related_records_cnt"]
    encrypted_only = report["encrypted_records_cnt"]

    return {
        "package": report["package"],
        "all": total,
        "no_crypt_bridge(approx)": no_crypt,
        "no_local_file_sink(approx)": no_file,
        "plaintext_only": plaintext_only,
        "network_only": network_only,
        "crypt_related_only": crypt_only,
        "encrypted_only": encrypted_only,
    }


def write_csv(rows, out_fp, fieldnames):
    os.makedirs(os.path.dirname(out_fp) or ".", exist_ok=True)
    with open(out_fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=r"G:\iie\mylab\guitest\Explorer\analysis\sac_yes")
    ap.add_argument("--pattern", default="**/leak.json", help="glob pattern，默认 **/leak.json")
    ap.add_argument("--out_summary", default="summary.csv")
    ap.add_argument("--out_ablation", default="ablation.csv")
    args = ap.parse_args()

    pattern = os.path.join(args.input, args.pattern)
    files = sorted(glob.glob(pattern, recursive=True))
    if not files:
        raise SystemExit(f"未找到文件：{pattern}")

    summary_rows = []
    ablation_rows = []

    for fp in files:
        try:
            rep = parse_one_report(fp)
        except Exception as e:
            print(f"[WARN] 解析失败：{fp} -> {e}")
            continue
        summary_rows.append(rep)
        ablation_rows.append(build_ablation_rows(rep))

    summary_fields = [
        "package", "analysis_time", "file",
        "total_leaks_records",
        "cats_level1_cnt", "unique_privacy_fields_cnt",
        "network_records_cnt", "unique_hosts_cnt",
        "local_file_records_cnt", "unique_file_paths_cnt",
        "crypt_related_records_cnt",
        "encrypted_records_cnt", "plaintext_records_cnt",
        "third_party_records_cnt",
        "network_meta_nonempty_ratio",
        "decode_non_normal_cnt",
        "summary_total_leaks", "summary_network_leaks",
        "summary_local_file_leaks", "summary_encrypted_count",
    ]
    ablation_fields = [
        "package", "all",
        "no_crypt_bridge(approx)",
        "no_local_file_sink(approx)",
        "plaintext_only",
        "network_only",
        "crypt_related_only",
        "encrypted_only",
    ]

    write_csv(summary_rows, args.out_summary, summary_fields)
    write_csv(ablation_rows, args.out_ablation, ablation_fields)

    print(f"OK: {len(summary_rows)} apps")
    print(f"Summary -> {args.out_summary}")
    print(f"Ablation -> {args.out_ablation}")


if __name__ == "__main__":
    main()
