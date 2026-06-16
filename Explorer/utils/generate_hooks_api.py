# generate_hooks_cache.py
import os
import json
from loguru import logger
from static_analysis import analyze_apk_for_hooks

APK_DIR = r"G:\iie\mylab\guitest\Explorer\apps\ap6end"
HOOKS_DIR = r"G:\iie\mylab\guitest\Explorer\hooks"

os.makedirs(HOOKS_DIR, exist_ok=True)

def main():    
    filenames = sorted(os.listdir(APK_DIR))
    
    for fname in filenames:
        if not fname.endswith(".apk"):
            continue
        apk_path = os.path.join(APK_DIR, fname)
        package_name = fname[:-4]  # 去掉 .apk
        output_path = os.path.join(HOOKS_DIR, f"{package_name}.json")

        # 如果已存在缓存，跳过
        if os.path.exists(output_path):
            logger.info(f"✅ Skip {package_name}, already cached.")
            continue

        logger.info(f"🔍 Analyzing {package_name}...")
        try:
            hooks = analyze_apk_for_hooks(apk_path)
            if hooks:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(hooks, f, indent=2, ensure_ascii=False)
                logger.info(f"💾 Saved {len(hooks)} hooks to {output_path}")
            else:
                logger.info(f"📊 No suspicious methods found in {package_name}.")
        except Exception as e:
            logger.error(f"❌ Failed to analyze {package_name}: {e}")

if __name__ == "__main__":
    main()