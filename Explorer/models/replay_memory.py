from collections import namedtuple, deque
import random

# 修改Transition，将done设为可选参数（默认False）
Transition = namedtuple('Transition', ('state', 'action', 'next_state', 'reward', 'done'), defaults=[False])
# defaults=[False] 表示当不传递done时，默认值为False

class ReplayMemory(object):
    def __init__(self, capacity):
        self.memory = deque([], maxlen=capacity)

    def push(self, *args):
        """接受4个参数（DQN）或5个参数（SAC）"""
        self.memory.append(Transition(*args))  # 自动适配参数数量

    # 其他方法（sample/clear/__len__）保持不变
    def sample(self, batch_size):
        if len(self.memory) < batch_size:
            return list(self.memory)
        return random.sample(self.memory, batch_size)

    def clear(self):
        self.memory.clear()

    def __len__(self):
        return len(self.memory)