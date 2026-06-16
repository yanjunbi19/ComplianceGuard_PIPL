import torch
import torch.nn as nn
import torch.nn.functional as F
from sentence_transformers import SentenceTransformer
from models.widget_embed import WidgetEmbed
from models.replay_memory import ReplayMemory, Transition
from models.autoencoder import LayoutAutoEncoder
import numpy as np
import random
from loguru import logger
import imgsim
import os


# ========== 多模态融合模块 (保持 RNN) ==========
class MultiModal2Vec(nn.Module):
    def __init__(self, bert_size=768, addition_visual_size=768, addition_layout_size=64, addition_coords=4):
        super(MultiModal2Vec, self).__init__()
        self.bert_size = bert_size
        # batch_first=True 方便处理维度
        self.net = nn.RNN(bert_size + addition_coords + 1, bert_size, batch_first=True)
        self.lin = nn.Linear(self.bert_size + addition_visual_size + addition_layout_size, self.bert_size)
        self.lin.weight.data.normal_(0, 0.1)

    def forward(self, widget_embeddings, visual_feature, layout_feature):
        batch_size = len(widget_embeddings)
        device = visual_feature.device
        screen_embeddings = torch.empty(batch_size, 1, self.bert_size, device=device)

        for batch_num in range(batch_size):
            # widget_embeddings[batch_num] 形状为 [NumWidgets, Dim]
            # 增加 Batch 维度变为 [1, NumWidgets, Dim]
            widget_set = widget_embeddings[batch_num].unsqueeze(0)

            # RNN 返回 h 形状为 [1, 1, Hidden]
            _, h = self.net(widget_set)
            h_final = h.squeeze(0)  # [1, Hidden]

            v = visual_feature[batch_num].view(1, -1)
            l = layout_feature[batch_num].view(1, -1)

            concat_emb = torch.cat((h_final, v, l), dim=1)
            final_emb = self.lin(concat_emb)
            screen_embeddings[batch_num] = final_emb

        return screen_embeddings


# ========== 网络主体 ==========
class Net(nn.Module):
    def __init__(self, bert, bert_size=768):
        super(Net, self).__init__()
        self.bert = bert
        self.widget_model = WidgetEmbed(self.bert)
        self.multimodalModel = MultiModal2Vec()
        self.dense_layer1 = nn.Linear(bert_size, 100)
        self.dense_layer2 = nn.Linear(100, 100)
        self.out = nn.Linear(100, 100)

    def parse_single_label_texts(self, labeled_text_tmp):
        # 稳健提取
        widget_clickable = [w[3] for w in labeled_text_tmp]
        widget_text = [w[0] for w in labeled_text_tmp]
        widget_class = [w[1] for w in labeled_text_tmp]
        widget_coords = [w[2] for w in labeled_text_tmp]
        return widget_clickable, widget_text, widget_class, widget_coords

    def forward(self, observation):
        visual_feature, layout_feature, labeled_text_tmp, visit_count, shallow_visit_count, _mask = observation
        device = visual_feature.device

        # 1. 解析 Widget 文本属性
        n_widget_click, n_widget_text, n_widget_class, n_widget_coords = [], [], [], []
        for text_item in labeled_text_tmp:
            w_click, w_text, w_class, w_coords = self.parse_single_label_texts(text_item)
            n_widget_click.append(w_click)
            n_widget_text.append(w_text)
            n_widget_class.append(w_class)
            n_widget_coords.append(w_coords)

        # 2. 获取 BERT Embedding (DQN 模式下通常不微调 BERT)
        with torch.no_grad():
            widget_embeddings = self.widget_model([n_widget_text, n_widget_class, n_widget_click])

        # 3. 拼接坐标和访问计数
        for i in range(len(widget_embeddings)):
            coords = torch.as_tensor(n_widget_coords[i], dtype=torch.float32, device=device)
            visits = torch.as_tensor(visit_count[i], dtype=torch.float32, device=device).unsqueeze(-1)
            widget_embeddings[i] = torch.cat((widget_embeddings[i].to(device), coords, visits), dim=-1)

        # 4. 多模态融合
        combined_feature = self.multimodalModel(widget_embeddings, visual_feature, layout_feature)
        x = F.relu(combined_feature.squeeze(1))

        # 5. MLP 层
        x = F.relu(self.dense_layer1(x))
        x = F.relu(self.dense_layer2(x))
        return self.out(x)


class DQN(nn.Module):
    def __init__(self):
        super(DQN, self).__init__()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        logger.info("DQN: 正在加载 BERT 模型...")
        self.bert = SentenceTransformer(
            'G:\iie\mylab\guitest\Explorer\\basemodel\paraphrase-multilingual-mpnet-base-v2')
        for param in self.bert.parameters(): param.requires_grad = False

        self.eval_net = Net(self.bert).to(self.device)
        self.target_net = Net(self.bert).to(self.device)
        self.target_net.load_state_dict(self.eval_net.state_dict())

        self.layout_autoencoder = LayoutAutoEncoder().to(self.device)
        self.layout_autoencoder.load_state_dict(torch.load('./pretrainedModel/layout_encoder_best_val_loss.pth'))
        self.vtr = imgsim.Vectorizer(device='cuda')

        self.optimizer = torch.optim.Adam(self.eval_net.parameters(), lr=0.0005)
        self.loss_func = nn.MSELoss()

        self.memory = ReplayMemory(50000)
        self.tmp_memory = ReplayMemory(10000)
        self.BATCH_SIZE = 32
        self.GAMMA = 0.99
        self.EPISILO = 0.9
        self.NUM_ACTIONS = 100
        self.Q_NETWORK_ITERATION = 500
        self.learn_step_counter = 0

    def choose_action(self, app):
        try:
            state = app.observation
            # 这里的解包必须和环境返回的 SAC 格式一致
            # state[2] = [[text...]], state[3] = [[v_count...]], state[4] = [[svc...]], state[5] = [mask...]
            visual, layout = state[0], state[1]
            raw_text = state[2][0]
            raw_v_count = state[3][0]
            raw_svc = state[4][0]
            raw_mask = state[5]

            if not app.usable_widgets: return None, None, None

            # 准备推理 Batch (Size=1)
            obs_tensor = [
                torch.as_tensor(visual, dtype=torch.float32, device=self.device),
                torch.as_tensor(layout, dtype=torch.float32, device=self.device),
                [raw_text], [raw_v_count], [raw_svc], [raw_mask]
            ]

            if np.random.uniform() <= self.EPISILO:
                self.eval_net.eval()
                with torch.no_grad():
                    q_values = self.eval_net(obs_tensor)
                    probs = torch.softmax(q_values, dim=1).squeeze(0)  # [100]

                # 访问惩罚逻辑
                PENALTY_FACTOR = 20.0
                svc_tensor = torch.as_tensor(raw_svc, dtype=torch.float32, device=self.device)
                vc_mask_eff = 1.0 / (svc_tensor * PENALTY_FACTOR + 1.0)

                # 合并掩码
                combined_mask = torch.zeros(self.NUM_ACTIONS, device=self.device)
                fill_len = min(len(raw_mask), self.NUM_ACTIONS, len(vc_mask_eff))

                # 显式转换确保不是 int
                m_tensor = torch.as_tensor(raw_mask[:fill_len], dtype=torch.float32, device=self.device)
                combined_mask[:fill_len] = m_tensor * vc_mask_eff[:fill_len]

                masked_probs = probs * combined_mask
                action = torch.argmax(masked_probs).item()
            else:
                valid_indices = [i for i, m in enumerate(raw_mask) if m > 0]
                action = random.choice(valid_indices) if valid_indices else 0

            if action < len(app.usable_widgets):
                return state, action, app.all_widget_dict[app.usable_widgets[action]]
            return None, None, None

        except Exception as e:
            logger.error(f"DQN choose_action 异常: {e}")
            import traceback
            traceback.print_exc()
            return None, None, None

    def store_transition(self, state, action, next_state, reward):
        self.memory.push(state, action, next_state, reward)
        self.tmp_memory.push(state, action, next_state, reward)

    def parse_batch_state(self, batch_states):
        v_l, l_l, t_l, vc_l, svc_l, m_l = [], [], [], [], [], []
        for s in batch_states:
            v_l.append(s[0])
            l_l.append(s[1])
            # 这里的索引取法参考 SAC: state[2] 是 [[text_data]], 所以 s[2][0] 才是真正的列表数据
            t_l.append(s[2][0])
            vc_l.append(s[3][0])
            svc_l.append(s[4][0])
            m_l.append(s[5])

        return [torch.cat(v_l).to(self.device), torch.cat(l_l).to(self.device), t_l, vc_l, svc_l, m_l]

    def learn(self, commands):
        active_memory = self.tmp_memory if commands == 'currentApp' else self.memory
        if len(active_memory) < self.BATCH_SIZE: return

        if self.learn_step_counter % self.Q_NETWORK_ITERATION == 0:
            self.target_net.load_state_dict(self.eval_net.state_dict())
        self.learn_step_counter += 1

        transitions = active_memory.sample(self.BATCH_SIZE)
        batch = Transition(*zip(*transitions))

        b_s = self.parse_batch_state(batch.state)
        b_s_ = self.parse_batch_state(batch.next_state)
        b_a = torch.as_tensor(batch.action, dtype=torch.long, device=self.device).view(-1, 1)
        b_r = torch.as_tensor(batch.reward, dtype=torch.float32, device=self.device).view(-1, 1)

        self.eval_net.train()
        q_eval = self.eval_net(b_s).gather(1, b_a)
        with torch.no_grad():
            q_next = self.target_net(b_s_).max(1)[0].view(-1, 1)
            q_target = b_r + self.GAMMA * q_next

        loss = self.loss_func(q_eval, q_target)
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.eval_net.parameters(), 1.0)
        self.optimizer.step()
