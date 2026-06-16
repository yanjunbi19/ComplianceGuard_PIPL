import json
import os
from pathlib import Path


def analyze_leak_json(file_path):
    """分析单个leak.json文件，返回大类数和小类数"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    by_category = data.get('summary', {}).get('by_category', {})

    major_count = len(by_category)
    minor_count = 0

    for category, info in by_category.items():
        fields = info.get('fields', {})
        minor_count += len(fields)

    return major_count, minor_count, by_category


def analyze_all_configs(base_dir, app_name, configs=None):
    """分析一个应用的所有配置"""
    if configs is None:
        configs = ['ALL', 'NOAPI', 'NOWidgt', 'NOESP']

    results = []

    for config in configs:
        folder_name = f"{app_name}_{config}"

        file_path = Path(base_dir) / folder_name / 'leak.json'

        if file_path.exists():
            major, minor, categories = analyze_leak_json(file_path)
            results.append({
                'config': config,
                'major_categories': major,
                'minor_categories': minor,
                'details': categories
            })
        else:
            print(f"文件不存在: {file_path}")
            results.append({
                'config': config,
                'major_categories': None,
                'minor_categories': None,
                'details': None
            })

    return results


def print_results_table(app_name, results):
    """打印结果表格"""
    print(f"\n{'=' * 60}")
    print(f"应用: {app_name}")
    print(f"{'=' * 60}")
    print(f"{'配置':<12}{'大类数':<10}{'小类数':<10}")
    print(f"{'-' * 32}")

    for r in results:
        if r['major_categories'] is not None:
            print(f"{r['config']:<12}{r['major_categories']:<10}{r['minor_categories']:<10}")
        else:
            print(f"{r['config']:<12}{'N/A':<10}{'N/A':<10}")

    # 打印详细分类信息
    print(f"\n详细分类（以ALL配置为例）:")
    print(f"{'-' * 50}")

    all_config = next((r for r in results if r['config'] == 'ALL' and r['details']), None)
    if all_config:
        for category, info in all_config['details'].items():
            fields = info.get('fields', {})
            print(f"  {category}: {len(fields)}个子类")
            for field_name in fields.keys():
                print(f"    - {field_name}")


def generate_latex_table(all_apps_results):
    """生成LaTeX表格格式"""
    print("\n" + "=" * 60)
    print("LaTeX表格数据:")
    print("=" * 60)
    print("应用\t配置\t大类数\t小类数")

    for app_name, results in all_apps_results.items():
        for i, r in enumerate(results):
            if r['major_categories'] is not None:
                app_col = app_name if i == 0 else ""
                print(f"{app_col}\t{r['config']}\t{r['major_categories']}\t{r['minor_categories']}")


# 主程序
if __name__ == "__main__":
    # 配置参数 - 根据实际情况修改
    BASE_DIR = r"G:\iie\mylab\guitest\Explorer\analysis\abl"  # 数据根目录

    # 应用包名列表 - 根据实际情况修改
    APPS = [
        "com.aiweather2345",  # APP1
        "com.kmxs.reader",  # APP2
        "com.ss.android.ugc.live"  # APP3
    ]

    all_results = {}

    for app in APPS:
        results = analyze_all_configs(BASE_DIR, app)
        all_results[app] = results
        print_results_table(app, results)

    # 生成汇总表格
    generate_latex_table(all_results)
