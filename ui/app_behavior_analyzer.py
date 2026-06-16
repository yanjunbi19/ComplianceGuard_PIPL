import os
import json
import pickle
import subprocess
import traceback
from pathlib import Path
from androguard.core.bytecodes.apk import APK

class AppBehaviorAnalyzer:
    def __init__(self, apk_path, output_root="analysis",algo="sac"):
        self.apk_path = apk_path
        self.output_root = output_root
        self.app_name = os.path.basename(os.path.splitext(apk_path)[0])
        self.package_name = "unknown"
        self.algo = algo

    def analyze(self):
        """主分析函数：衔接静态与动态分析"""
        try:
            return self.merge_results(self.analyze_static(), self.analyze_dynamic())
        except Exception as e:
            print(f"分析失败: {e}")
            traceback.print_exc()
            return {}

    def analyze_static(self):
        cached_info = self._load_static_cache()
        if cached_info.get('from_cache'):
            if cached_info.get('package_name') and cached_info.get('package_name') != 'unknown':
                self.package_name = cached_info['package_name']
            return cached_info

        static_info = self._do_static_analysis()
        return {
            'package_name': static_info.get('package_name'),
            'app_name': self.app_name,
            'permissions': static_info.get('permissions', []),
            'static_apis': [],
            'from_cache': False,
        }

    def analyze_dynamic(self):
        dynamic_info = self._load_dynamic_results()
        privacy_info = self._load_privacy_analysis_results()
        return {
            'package_name': self.package_name,
            'app_name': self.app_name,
            'sensitive_apis': dynamic_info.get('triggered_apis', []),
            'network_activities': dynamic_info.get('network', []),
            'leak_data': privacy_info.get('leak_data', {}),
            'api_simplified_result': privacy_info.get('api_simplified_result', []),
            'leak_path': privacy_info.get('leak_path', ''),
        }

    def merge_results(self, static_info=None, dynamic_info=None):
        static_info = static_info or {}
        dynamic_info = dynamic_info or {}
        results = {
            'package_name': static_info.get('package_name') or dynamic_info.get('package_name'),
            'app_name': self.app_name,
            'permissions': static_info.get('permissions', []),
            'static_apis': static_info.get('static_apis', []),
            'sensitive_apis': dynamic_info.get('sensitive_apis', []),
            'network_activities': dynamic_info.get('network_activities', []),
            'leak_data': dynamic_info.get('leak_data', {}),
            'api_simplified_result': dynamic_info.get('api_simplified_result', []),
            'leak_path': dynamic_info.get('leak_path', ''),
            'risk_level': 'low',
            'score': 100
        }
        self._calculate_risk(results)
        return results

    def _load_static_cache(self):
        workspace_root = Path(__file__).resolve().parent.parent
        info_path = workspace_root / "Explorer" / "apps" / "ap1" / "apinfo" / f"{self.app_name}.json"
        hooks_path = workspace_root / "Explorer" / "hooks" / f"{self.app_name}.json"

        permissions = []
        package_name = self.package_name
        static_apis = []
        loaded_any = False

        if info_path.exists():
            try:
                with open(info_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                package_name = data.get('package_name') or data.get('package') or self.app_name
                for permission in data.get('permissions', []) or []:
                    permissions.append({
                        'name': str(permission).split('.')[-1],
                        'level': 'unknown',
                    })
                loaded_any = True
            except Exception as e:
                print(f"读取静态权限缓存失败: {e}")

        if hooks_path.exists():
            try:
                with open(hooks_path, 'r', encoding='utf-8') as file:
                    hooks_data = json.load(file)
                for item in hooks_data if isinstance(hooks_data, list) else [hooks_data]:
                    category = item.get("Category", "Unknown")
                    for hook in item.get("hooks", []) or []:
                        clazz = hook.get("clazz", "")
                        method = hook.get("method", "")
                        static_apis.append(f"[{category}] {clazz}.{method}()")
                loaded_any = True
            except Exception as e:
                print(f"读取静态 API 缓存失败: {e}")

        if not loaded_any:
            return {}

        return {
            'package_name': package_name,
            'app_name': self.app_name,
            'permissions': permissions,
            'static_apis': static_apis,
            'from_cache': True,
            'cache_paths': {
                'permissions': str(info_path) if info_path.exists() else '',
                'hooks': str(hooks_path) if hooks_path.exists() else '',
            },
        }

    def _do_static_analysis(self):
        """静态分析：提取包名和权限"""
        print(f"正在执行静态分析: {self.app_name}")
        try:
            # 使用 androguard 解析 APK
            a = APK(self.apk_path)
            self.package_name = a.get_package()

            # 获取权限并标记危险等级
            raw_permissions = a.get_permissions()
            permissions = []
            for p in raw_permissions:
                # 简化逻辑：包含 .CAMERA, .LOCATION, .CONTACTS 等通常为 dangerous
                level = 'normal'
                if any(risk in p for risk in ['LOCATION', 'CAMERA', 'CONTACTS', 'STORAGE', 'PHONE', 'SMS']):
                    level = 'dangerous'
                permissions.append({'name': p.split('.')[-1], 'level': level})

            return {
                'package_name': self.package_name,
                'permissions': permissions
            }
        except Exception as e:
            print(f"静态分析出错: {e}")
            return {'package_name': 'error', 'permissions': []}

    def _load_dynamic_results(self):
        """衔接 explore3.py 的输出结果"""
        triggered_apis = []
        network_info = []

        # 对应 explore3.py 中保存路径: apiTrigger/{app_name}_api_trigger.pkl
        api_pkl_path = os.path.join('apiTrigger', self.algo, f'{self.app_name}_api_trigger.pkl')

        # 流量监控路径变为：analysis/sac/app_name/monitor_result.pkl
        net_pkl_path = os.path.join('analysis', self.algo, self.app_name, 'monitor_result.pkl')

        # 读取敏感 API 触发记录
        if os.path.exists(api_pkl_path):
            try:
                with open(api_pkl_path, 'rb') as f:
                    # explore3.py 保存的是 app.all_sensitive_api_list
                    triggered_apis = pickle.load(f)
            except Exception as e:
                print(f"读取动态API结果失败: {e}")

        # 读取网络监控记录
        if os.path.exists(net_pkl_path):
            try:
                with open(net_pkl_path, 'rb') as f:
                    net_data = pickle.load(f)
                    # 提取域名或请求信息
                    network_info = net_data.get('domains', []) # 假设 monitor_result 包含 domains
            except Exception as e:
                print(f"读取网络结果失败: {e}")

        return {
            'triggered_apis': list(set(triggered_apis)), # 去重
            'network': network_info
        }

    def _load_privacy_analysis_results(self):
        """Load anal5 JSON outputs so compliance checks can consume runtime evidence."""
        leak_path = self.find_privacy_result_path()
        if leak_path is None:
            return {}

        try:
            with open(leak_path, 'r', encoding='utf-8') as file:
                leak_data = json.load(file)
            summary_path = leak_path.parent / "api_privacy_summary.json"
            api_summary = []
            if summary_path.exists():
                with open(summary_path, 'r', encoding='utf-8') as file:
                    api_summary = json.load(file)
            print(f"已加载隐私行为结果: {leak_path}")
            return {
                'leak_data': leak_data,
                'api_simplified_result': api_summary if isinstance(api_summary, list) else [],
                'leak_path': str(leak_path),
            }
        except Exception as e:
            print(f"读取隐私行为结果失败: {e}")
            return {}

    def has_cached_privacy_results(self):
        return self.find_privacy_result_path() is not None

    def find_privacy_result_path(self):
        if self.package_name in {"unknown", "error"}:
            try:
                self.package_name = APK(self.apk_path).get_package()
            except Exception:
                pass

        analysis_root = Path(__file__).resolve().parent.parent / "Explorer" / "analysis"
        candidate_names = [
            name for name in (self.package_name, self.app_name)
            if name and name not in {"unknown", "error"}
        ]
        candidates = []
        for name in candidate_names:
            candidates.extend([
                analysis_root / self.algo / name / "leak.json",
            ])

        leak_path = next((path for path in candidates if path.exists()), None)
        return leak_path

    def _calculate_risk(self, results):
        """根据静态权限和动态 API 计算分数"""
        score = 100
        # 1. 根据危险权限扣分
        danger_perms = [p for p in results['permissions'] if p['level'] == 'dangerous']
        score -= len(danger_perms) * 2

        # 2. 根据动态触发的敏感 API 扣分 (权重更高)
        score -= len(results['sensitive_apis']) * 5

        results['score'] = max(0, score)
        if score < 60:
            results['risk_level'] = 'high'
        elif score < 85:
            results['risk_level'] = 'medium'
        else:
            results['risk_level'] = 'low'
