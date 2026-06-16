import os
import json
import pandas as pd

# --- 核心配置区域 ---
# 在这里定义你要对比的所有算法
# 格式: (显示名称, 数据目录路径, 步数)
ALGORITHMS = [
    ("DroidBot", "analysis/droidbot", 600),
    ("Fastbot", "analysis/fastbot", 600),
    ("SACBot", "analysis/sacbot", 600),  # 新增 SACBot
]
OUTPUT_FOLDER = "analysis_compare"


def load_json_file(json_path):
    if not os.path.exists(json_path):
        return None
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"读取 JSON 失败: {json_path}, error={e}")
        return None


def extract_app_metrics_from_folder(app_dir):
    """
    从单个 app 分析目录中提取指标
    """
    calls = 0
    cats = 0

    leak_path = os.path.join(app_dir, "leak.json")
    api_path = os.path.join(app_dir, "api_privacy_full.json")

    # 读取 leak.json
    leak_data = load_json_file(leak_path)
    if leak_data:
        by_category = leak_data.get("summary", {}).get("by_category", {})
        if isinstance(by_category, dict):
            cats = len(by_category)

    # 读取 api_privacy_full.json
    api_data = load_json_file(api_path)
    if api_data:
        calls = api_data.get("summary", {}).get("total_calls", 0)
        if not isinstance(calls, (int, float)):
            calls = 0

    return {"calls": int(calls), "cats": int(cats)}


def build_dataset_from_analysis_root(analysis_root):
    """
    遍历分析根目录，构建 {app_name: metrics} 数据集
    """
    dataset = {}
    if not os.path.exists(analysis_root):
        print(f"目录不存在: {analysis_root}")
        return dataset

    for app_name in sorted(os.listdir(analysis_root)):
        app_dir = os.path.join(analysis_root, app_name)
        if not os.path.isdir(app_dir):
            continue

        # 如果目录是空的或者没有必要的文件，跳过
        if not os.path.exists(os.path.join(app_dir, "leak.json")):
            continue

        metrics = extract_app_metrics_from_folder(app_dir)
        dataset[app_name] = metrics

    return dataset


def process_and_save_explorer():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    # 1. 动态加载所有算法的数据
    all_data_map = {}
    valid_algorithms = []

    print(f"正在加载 {len(ALGORITHMS)} 个算法的数据...")
    for name, path, steps in ALGORITHMS:
        data = build_dataset_from_analysis_root(path)
        if data:
            all_data_map[name] = {"data": data, "steps": steps}
            valid_algorithms.append((name, steps))
            print(f" - {name}: 加载成功 ({len(data)} 个App)")
        else:
            print(f" - {name}: 加载失败或目录为空")

    if not valid_algorithms:
        print("没有有效数据，程序退出。")
        return

    # 2. 计算宏观指标
    summary_list = []

    for name, steps in valid_algorithms:
        data = all_data_map[name]["data"]

        total_apps = len(data)
        total_calls = sum(v['calls'] for v in data.values())
        total_cats = sum(v['cats'] for v in data.values())

        avg_calls = total_calls / total_apps if total_apps > 0 else 0
        avg_cats = total_cats / total_apps if total_apps > 0 else 0

        # 计算公式 (4-6) 和 (4-7)
        # DI: 每100步触发次数
        di = (avg_calls / steps) * 100 if steps > 0 else 0
        # DE: 每100步发现类别数
        de = (avg_cats / steps) * 100 if steps > 0 else 0

        summary_list.append({
            "Algorithm": name,
            "Success_Apps": total_apps,
            "Total_Calls": total_calls,
            "Total_Cats": total_cats,
            "Avg_Calls_Per_App": round(avg_calls, 2),
            "Avg_Cats_Per_App": round(avg_cats, 2),
            "Intensity(DI)": round(di, 4),
            "Efficiency(DE)": round(de, 4),
            "Steps_Per_App": steps
        })

    df_summary = pd.DataFrame(summary_list)
    df_summary.to_csv(
        os.path.join(OUTPUT_FOLDER, "summary_metrics.csv"),
        index=False, encoding="utf-8-sig"
    )
    print("成功生成宏观指标表: summary_metrics.csv")

    # 3. 生成详细对比表
    # 获取所有算法中出现过的所有 App 包名（并集）
    all_packages = set()
    for item in all_data_map.values():
        all_packages.update(item["data"].keys())

    all_packages = sorted(list(all_packages))
    detailed_rows = []

    for pkg in all_packages:
        row = {"App_Package": pkg}

        # 动态填充每个算法的数据
        for name, steps in valid_algorithms:
            data = all_data_map[name]["data"]
            metrics = data.get(pkg, {"calls": 0, "cats": 0})

            calls = metrics["calls"]
            cats = metrics["cats"]

            # 计算单App的 DI 和 DE
            # 注意：这里统一使用 (Calls/Steps) 作为密度，DE乘以100
            di_val = round(calls / steps, 4) if steps > 0 else 0
            de_val = round((cats / steps) * 100, 4) if steps > 0 else 0

            row[f"{name}_Calls"] = calls
            row[f"{name}_Cats"] = cats
            row[f"{name}_DI"] = di_val
            row[f"{name}_DE"] = de_val

        # 计算差异值 (仅计算 SACBot 与 DroidBot 的差值作为示例，或者可以循环计算)
        # 这里为了保持通用，只计算所有算法两两之间的差值比较复杂
        # 建议：如果需要差值，可以在 Excel 中自行计算，或者指定基准算法
        if "DroidBot_Calls" in row and "SACBot_Calls" in row:
            row["Calls_Diff(SAC-Droid)"] = row["SACBot_Calls"] - row["DroidBot_Calls"]

        detailed_rows.append(row)

    df_detailed = pd.DataFrame(detailed_rows)
    # 排序：优先按 SACBot 的 Calls 降序，其次 DroidBot
    sort_cols = [f"{name}_Calls" for name, _ in valid_algorithms]
    df_detailed = df_detailed.sort_values(by=sort_cols, ascending=False)

    df_detailed.to_csv(
        os.path.join(OUTPUT_FOLDER, "detailed_app_comparison.csv"),
        index=False, encoding="utf-8-sig"
    )
    print("成功生成详细对比表: detailed_app_comparison.csv")


if __name__ == "__main__":
    process_and_save_explorer()