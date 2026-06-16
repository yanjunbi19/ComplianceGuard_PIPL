import csv
import os
import time


class ExperimentRecorder:
    def __init__(self, app_name, algo, stage, weights):
        """
        weights: 奖励权重字典, 例如 {'api': 200, 'new': 100, 'redun': -30, 'wid': 10}
        """
        self.output_dir = os.path.join("analysis", algo, app_name)
        os.makedirs(self.output_dir, exist_ok=True)

        # 将权重转化为字符串，用于文件名，例如 "api200_new100_p30"
        weight_str = "_".join([f"{k}{abs(v)}" for k, v in weights.items()])
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # 文件名包含阶段、权重和时间戳
        self.filename = os.path.join(self.output_dir, f"metrics_S{stage}_{weight_str}_{timestamp}.csv")

        self.headers = [
            'step', 'reward', 'cum_reward',
            'api_count', 'unique_apis',
            'current_activity', 'unique_activities',
            'is_stuck', 'recovered',
            'xml_score', 'img_same',
            'input_performed',
            'reward_debug',
        ]
        with open(self.filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([f"# Experiment Config: Algo={algo}, Stage={stage}, Weights={weights}"])
            writer.writerow(self.headers)
        self.cumulative_reward = 0.0
        self.unique_api_set = set()
        self.unique_activity_set = set()  # 记录跑过多少个不重复的页面

    def record_step(
            self, step, reward, api_list, activity, is_stuck,
            recovered=False, xml_score=0.0, img_same=False,
            input_performed=False, reward_debug=""
    ):
        self.cumulative_reward += float(reward)

        api_list = api_list or []
        if api_list:
            self.unique_api_set.update(api_list)

        if activity and activity != "unknown":
            self.unique_activity_set.add(activity)

        with open(self.filename, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                step,
                round(float(reward), 2),
                round(self.cumulative_reward, 2),

                len(api_list),
                len(self.unique_api_set),

                activity or "unknown",
                len(self.unique_activity_set),

                1 if is_stuck else 0,
                1 if recovered else 0,

                round(float(xml_score), 4),
                1 if img_same else 0,

                1 if input_performed else 0,

                reward_debug,
            ])
