import torch
import torch.nn as nn
import torch.nn.functional as F
from sentence_transformers import SentenceTransformer
from torch.distributions import Categorical
from models.widget_embed import WidgetEmbed
from models.replay_memory import ReplayMemory, Transition
from models.autoencoder import LayoutAutoEncoder
import numpy as np
import random
from loguru import logger
import copy
import imgsim
import os


def _deep_copy_observation(obs_element):
    """
    递归地深度拷贝观测状态中的元素。
    """
    if isinstance(obs_element, torch.Tensor):
        return obs_element.detach().clone()
    elif isinstance(obs_element, (list, tuple)):
        return type(obs_element)(_deep_copy_observation(item) for item in obs_element)
    else:
        return copy.deepcopy(obs_element)


# ========== 多模态融合模块 ==========
class MultiModal2Vec(nn.Module):
    def __init__(self, bert_size=768, addition_visual_size=768, addition_layout_size=64, addition_coords=4):
        super(MultiModal2Vec, self).__init__()
        self.bert_size = bert_size
        self.net = nn.RNN(bert_size + addition_coords + 1, bert_size, batch_first=True)
        self.lin = nn.Linear(self.bert_size + addition_visual_size + addition_layout_size, self.bert_size)
        self.lin.weight.data.normal_(0, 0.1)

    def forward(self, widget_embeddings, visual_feature, layout_feature, trace_screen_lengths=None):
        batch_size = len(widget_embeddings)
        device = visual_feature.device
        screen_embeddings = torch.empty(batch_size, 1, self.bert_size, device=device)

        for batch_num in range(batch_size):
            widget_set = widget_embeddings[batch_num].unsqueeze(0)
            full_output, h = self.net(widget_set)
            h = h.squeeze(0)

            current_visual_feature = visual_feature[batch_num].view(1, -1)
            current_layout_feature = layout_feature[batch_num].view(1, -1)

            concat_emb = torch.cat((h, current_visual_feature, current_layout_feature), dim=1)
            final_emb = self.lin(concat_emb)
            screen_embeddings[batch_num] = final_emb

        return screen_embeddings


# ========== 共享特征提取器（只有一个实例）==========
class SharedFeatureExtractor(nn.Module):
    def __init__(self, bert, bert_size=768, addition_visual_size=768, addition_layout_size=64, addition_coords=4):
        super(SharedFeatureExtractor, self).__init__()
        # ✅ 使用传入的 bert 实例，避免重复加载
        self.bert = bert
        self.widget_model = WidgetEmbed(self.bert)
        self.multimodalModel = MultiModal2Vec(bert_size, addition_visual_size, addition_layout_size, addition_coords)
        self.bert_size = bert_size

    def parse_single_label_texts(self, labeled_text_tmp):
        widget_clickable = [widget[3] for widget in labeled_text_tmp]
        widget_text = [widget[0] for widget in labeled_text_tmp]
        widget_class = [widget[1] for widget in labeled_text_tmp]
        widget_coords = [widget[2] for widget in labeled_text_tmp]
        return widget_clickable, widget_text, widget_class, widget_coords

    def forward(self, observation):
        visual_feature, layout_feature, labeled_text_tmp, visit_count, shallow_visit_count, _mask = observation
        device = visual_feature.device
        n_widget_click_list = []
        n_widget_text = []
        n_widget_class_list = []
        n_widget_coords = []
        n_visit_count = []
        n_shallow_visit_count = []

        for text_item, v_count, s_v_count in zip(labeled_text_tmp, visit_count, shallow_visit_count):
            widget_click_s, widget_text_s, widget_class_s, widget_coords_s = self.parse_single_label_texts(text_item)
            n_widget_click_list.append(widget_click_s)
            n_widget_text.append(widget_text_s)
            n_widget_class_list.append(widget_class_s)
            n_widget_coords.append(widget_coords_s)
            n_visit_count.append(v_count)  # 👈 使用当前样本的 v_count
            n_shallow_visit_count.append(s_v_count)

        widget_clickable_batch = n_widget_click_list
        widget_class_batch = n_widget_class_list
        widget_text_batch = n_widget_text
        widget_coords_batch = n_widget_coords
        widget_visit_count_batch = n_visit_count
        widget_shallow_visit_count_batch = n_shallow_visit_count

        widget_embeddings = self.widget_model([widget_text_batch, widget_class_batch, widget_clickable_batch])

        for batch_i in range(len(widget_embeddings)):
            # 确保 widget_embeddings 也在正确设备上
            widget_embeddings[batch_i] = widget_embeddings[batch_i].to(device)

            coords_tensor = torch.tensor(widget_coords_batch[batch_i], dtype=torch.float32, device=device)
            widget_embeddings[batch_i] = torch.cat((widget_embeddings[batch_i], coords_tensor), dim=-1)

            visit_tensor = torch.tensor(widget_visit_count_batch[batch_i], dtype=torch.float32, device=device)
            widget_embeddings[batch_i] = torch.cat((widget_embeddings[batch_i], visit_tensor.unsqueeze(-1)), dim=-1)

        combined_feature = self.multimodalModel(widget_embeddings, visual_feature, layout_feature, None)
        return F.relu(combined_feature.squeeze(1))


# ========== Actor 头部（不包含特征提取）==========
class SACActorHead(nn.Module):
    def __init__(self, num_actions=100, bert_size=768):
        super(SACActorHead, self).__init__()
        self.fc1 = nn.Linear(bert_size, 128)
        self.fc2 = nn.Linear(128, num_actions)

    def forward(self, shared_feature):
        """
        Args:
            shared_feature: (batch_size, bert_size) 已经提取好的特征
        Returns:
            logits, action_probs, log_probs
        """
        x = F.relu(self.fc1(shared_feature))
        logits = self.fc2(x)
        action_probs = F.softmax(logits, dim=-1)
        log_probs = F.log_softmax(logits, dim=-1)
        return logits, action_probs, log_probs


# ========== Critic 头部（不包含特征提取）==========
class SACCriticHead(nn.Module):
    def __init__(self, num_actions=100, bert_size=768):
        super(SACCriticHead, self).__init__()
        self.num_actions = num_actions

        # Q1 网络
        self.q1_fc1 = nn.Linear(bert_size + num_actions, 128)
        self.q1_fc2 = nn.Linear(128, 1)

        # Q2 网络
        self.q2_fc1 = nn.Linear(bert_size + num_actions, 128)
        self.q2_fc2 = nn.Linear(128, 1)

    def forward(self, shared_feature, action):
        """
        Args:
            shared_feature: (batch_size, bert_size) 已经提取好的特征
            action: (batch_size,) 动作索引 或 (batch_size, num_actions) 概率分布
        Returns:
            q1, q2: (batch_size, 1)
        """
        if action.dtype == torch.long or (action.dim() == 2 and action.size(1) == 1):
            if action.dim() == 2:
                action = action.squeeze(dim=1)
            action_one_hot = F.one_hot(action, num_classes=self.num_actions).float()
        else:
            action_one_hot = action.float()

        action_one_hot = action_one_hot.to(shared_feature.device)

        x1 = torch.cat([shared_feature, action_one_hot], dim=-1)
        q1 = self.q1_fc2(F.relu(self.q1_fc1(x1)))

        x2 = torch.cat([shared_feature, action_one_hot], dim=-1)
        q2 = self.q2_fc2(F.relu(self.q2_fc1(x2)))

        return q1, q2


# ========== SAC 主模型 ==========
class SACModel(nn.Module):
    def __init__(self, num_actions=100, bert_size=768):
        super(SACModel, self).__init__()

        # ✅ 只加载一次 BERT 模型
        logger.info("🔄 加载 BERT 模型...")
        model_path = os.path.expanduser("G:\iie\mylab\guitest\Explorer\\basemodel\paraphrase-multilingual-mpnet-base-v2")
        self.bert = SentenceTransformer(model_path)
        for param in self.bert.parameters():
            param.requires_grad = False
        logger.info("✅ BERT 模型加载完成")

        # ✅ 只有一个共享特征提取器
        self.shared_feature_extractor = SharedFeatureExtractor(
            self.bert,
            bert_size=bert_size
        ).cuda()

        # ✅ Actor 和 Critic 只包含头部网络（轻量级）
        self.actor_head = SACActorHead(num_actions=num_actions, bert_size=bert_size).cuda()
        self.critic1_head = SACCriticHead(num_actions=num_actions, bert_size=bert_size).cuda()
        self.critic2_head = SACCriticHead(num_actions=num_actions, bert_size=bert_size).cuda()

        # ✅ 目标网络也只有头部（不包含特征提取器）
        self.critic_target1_head = SACCriticHead(num_actions=num_actions, bert_size=bert_size).cuda()
        self.critic_target2_head = SACCriticHead(num_actions=num_actions, bert_size=bert_size).cuda()

        # 初始化目标网络参数
        self.critic_target1_head.load_state_dict(self.critic1_head.state_dict())
        self.critic_target2_head.load_state_dict(self.critic2_head.state_dict())

        # Layout 和 VTR 模型
        self.layout_autoencoder = LayoutAutoEncoder()
        self.layout_autoencoder.load_state_dict(
            torch.load('./pretrainedModel/layout_encoder_best_val_loss.pth')
        )
        self.vtr = imgsim.Vectorizer(device='cuda')

        # 1. 修改 __init__ 中的优化器定义
        self.critic_optimizer = torch.optim.Adam([
            {'params': self.shared_feature_extractor.parameters()},
            {'params': self.critic1_head.parameters()},
            {'params': self.critic2_head.parameters()}
        ], lr=0.0003)

        self.actor_optimizer = torch.optim.Adam(self.actor_head.parameters(), lr=0.0001)

        # 自动调整熵系数
        self.log_alpha = torch.zeros(1, requires_grad=True, device='cuda')
        self.alpha_optimizer = torch.optim.Adam([self.log_alpha], lr=0.0001)
        self.target_entropy = -0.6 * torch.log(torch.tensor(1.0 / num_actions, device='cuda'))

        self.memory = ReplayMemory(100000)
        self.tmp_memory = ReplayMemory(10000)

        self.gamma = 0.99
        self.tau = 0.002
        self.batch_size = 256
        self.num_actions = num_actions
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        logger.info(f"✅ SAC 模型初始化完成 (num_actions={num_actions})")

    def parse_batch_state(self, batch_states):
        visual_feature_list, layout_feature_list = [], []
        labeled_text_tmp_list, visit_count_list, shallow_visit_count_list, mask_list = [], [], [], []

        for s in batch_states:
            visual_feature_list.append(s[0])
            layout_feature_list.append(s[1])
            labeled_text_tmp_list.append(s[2][0])
            visit_count_list.append(s[3][0])
            shallow_visit_count_list.append(s[4][0])
            mask_list.append(s[5])

        visual_features = torch.cat(visual_feature_list).to(self.device)
        layout_features = torch.cat(layout_feature_list).to(self.device)
        # 将 mask 转为 tensor
        batch_masks = torch.tensor(np.array(mask_list), dtype=torch.float32).to(self.device)

        # 返回 6 个元素构成的列表
        return [visual_features, layout_features, labeled_text_tmp_list,
                visit_count_list, shallow_visit_count_list, batch_masks]

    def get_visit_count_mask_child(self, app, shallow_visit_count_list):
        """
        获取访问计数掩码（带边界检查）
        [此函数通常用于准备状态特征，保持原样]
        """
        vc_mask = []
        for visit in shallow_visit_count_list:
            vc_mask.append(1.0 / (visit * 10 + 1))

        if len(vc_mask) == 0:
            logger.warning("⚠️ No visit counts available")
            return None

        # 修复：限制 mask 长度不超过 num_actions
        effective_mask_length = min(len(vc_mask), self.num_actions)

        full_mask = [0.0] * self.num_actions
        for i in range(effective_mask_length):
            full_mask[i] = vc_mask[i]

        # 修复：限制 usable_widgets 数量不超过 num_actions
        effective_widget_count = min(len(app.usable_widgets), self.num_actions)
        app.current_mask = [1 if i < effective_widget_count else 0 for i in range(self.num_actions)]

        # 添加日志，方便调试
        if len(vc_mask) > self.num_actions:
            logger.warning(f"⚠️ Widget count ({len(vc_mask)}) exceeds num_actions ({self.num_actions}), truncating")

        return full_mask

    def choose_action(self, app):
        try:
            state = app.observation
            device = self.device

            # --- 1. 获取输入数据 ---

            # state[5] 是可用动作的布尔掩码 (list, size=self.num_actions)
            current_mask_tensor = torch.tensor(state[5], dtype=torch.float32, device=device).squeeze(0)
            num_usable = int(torch.sum(current_mask_tensor).item())

            if num_usable == 0:
                logger.warning("Agent received state with zero usable widgets.")
                return None, None, None

            # state[4][0] 是 shallow_visit_counts 列表 (list, size=实际可用控件数)
            raw_visit_counts = state[4][0]

            # 2. 生成访问计数惩罚掩码 (vc_mask)

            # 超参数：用于平衡探索和利用。访问次数越多，惩罚越重。
            PENALTY_FACTOR = 20.0

            vc_mask_list = []
            for count in raw_visit_counts:
                # 惩罚系数：1 / (count * PENALTY_FACTOR + 1.0)
                vc_mask_list.append(1.0 / (count * PENALTY_FACTOR + 1.0))

            # 填充到 num_actions 长度，确保与策略输出维度一致
            vc_mask_padded = torch.zeros(self.num_actions, device=device)
            fill_len = min(len(vc_mask_list), self.num_actions)
            vc_mask_padded[:fill_len] = torch.tensor(vc_mask_list[:fill_len],
                                                     dtype=torch.float32,
                                                     device=device)

            # 转换为 (1, num_actions) 维度
            vc_mask_tensor = vc_mask_padded.unsqueeze(0)

            # 3. 提取共享特征和原始策略
            with torch.no_grad():
                # state 是 size=1 的 batch，shared_feature 也是 size=1 的 batch
                shared_feature = self.shared_feature_extractor(state)
                # logits_raw: 原始策略输出 (1, num_actions)
                _, probs_raw, _ = self.actor_head(shared_feature)

            # 4. 应用最终掩码和惩罚

            # current_mask_tensor 需要 unsqueeze(0) 才能与 probs_raw 相乘
            current_mask_tensor_batch = current_mask_tensor.unsqueeze(0)

            # combined_mask = 可用性掩码 * 访问惩罚掩码
            combined_mask = current_mask_tensor_batch * vc_mask_tensor

            probs_masked = probs_raw * combined_mask

            # 5. 动作选择

            epsilon = 1e-6  # 极小值，用于处理浮点数精度

            if probs_masked.sum().item() < epsilon:
                # 降级策略：如果所有有效动作的概率都被惩罚为零，则在可用动作中均匀随机选择
                valid_indices = torch.nonzero(current_mask_tensor).squeeze(1)
                if len(valid_indices) > 0:
                    action_idx = random.choice(valid_indices).item()
                else:
                    logger.error("❌ No valid actions available after filtering.")
                    return None, None, None
                logger.warning(f'All masked probabilities are zero, choosing random fallback action: {action_idx}')
            else:
                # 重新归一化并采样
                probs_normalized = probs_masked / probs_masked.sum()
                m = Categorical(probs_normalized)
                action_idx = m.sample().item()

            # logger.info(f'Chosen action index: {action_idx}, usable widgets count: {len(app.usable_widgets)}')

            # 6. 返回结果

            # 确保 action_idx 在实际可用控件列表的范围内
            if action_idx >= len(app.usable_widgets):
                logger.error(
                    f"❌ Action index {action_idx} is out of bounds for usable widgets list ({len(app.usable_widgets)}). Fallback to last valid index.")
                action_idx = len(app.usable_widgets) - 1

            widget_uuid = app.usable_widgets[action_idx]
            operatable_widget = app.all_widget_dict[widget_uuid]

            return state, action_idx, operatable_widget

        except Exception as e:
            logger.error(f"❌ Error in choose_action: {e}")
            import traceback
            traceback.print_exc()
            return None, None, None

    def store_transition(self, state, action, next_state, reward, done):
        """存储经验"""
        copied_state = _deep_copy_observation(state)
        copied_next_state = _deep_copy_observation(next_state)
        self.memory.push(copied_state, action, copied_next_state, reward, done)
        self.tmp_memory.push(copied_state, action, copied_next_state, reward, done)

    def learn(self, commands):
        if len(self.memory) < self.batch_size:
            return

        transitions = self.tmp_memory.sample(self.batch_size) if commands == 'currentApp' else self.memory.sample(
            self.batch_size)
        batch = Transition(*zip(*transitions))
        batch_state = self.parse_batch_state(batch.state)
        batch_next_state = self.parse_batch_state(batch.next_state)
        state_masks = batch_state[5]
        next_masks = batch_next_state[5]
        batch_action = torch.tensor(batch.action, dtype=torch.long).to(self.device)
        batch_reward = torch.tensor(batch.reward, dtype=torch.float).unsqueeze(1).to(self.device)
        batch_done = torch.tensor(batch.done, dtype=torch.float).unsqueeze(1).to(self.device)

        # 预先创建所有动作的 One-Hot 向量 (用于 Q 值展开)
        all_actions = torch.arange(self.num_actions, device=self.device)
        all_actions_one_hot = F.one_hot(all_actions, num_classes=self.num_actions).float()

        # =============== 1. 更新 Critic ===============
        with torch.no_grad():
            feat_next = self.shared_feature_extractor(batch_next_state)
            logits_next, probs_next, log_probs_next = self.actor_head(feat_next)

            inf_mask_next = (1 - next_masks) * -1e9
            masked_logits_next = logits_next + inf_mask_next
            probs_next = F.softmax(masked_logits_next, dim=-1)
            log_probs_next = F.log_softmax(masked_logits_next, dim=-1).clamp(min=-1e4)

            # --- Q 值展开计算 V(s') ---

            # 1. 扩展特征和动作 One-Hot
            feat_next_expanded = feat_next.unsqueeze(1).repeat(1, self.num_actions, 1).view(-1, feat_next.size(-1))
            all_actions_one_hot_batch = all_actions_one_hot.unsqueeze(0).repeat(self.batch_size, 1, 1).view(-1,
                                                                                                            self.num_actions)

            # 2. 计算所有动作的 Q 值 (Batch * num_actions, 1)
            q1_values_expanded, q2_values_expanded = self.critic_target1_head(feat_next_expanded,
                                                                              all_actions_one_hot_batch)

            # 3. 重塑回 (Batch, num_actions)
            q1_values_next = q1_values_expanded.view(self.batch_size, self.num_actions)
            q2_values_next = q2_values_expanded.view(self.batch_size, self.num_actions)

            min_q_next = torch.min(q1_values_next, q2_values_next)

            # 4. Target V(s')
            next_v = (probs_next * (min_q_next - self.log_alpha.exp() * log_probs_next)).sum(dim=-1, keepdim=True)
            target_q = batch_reward + self.gamma * (1 - batch_done) * next_v

        # --- Critic Loss (当前状态 Q 值) ---
        feat_curr = self.shared_feature_extractor(batch_state)

        # 将 batch_action 转换为 One-Hot 向量
        batch_action_one_hot = F.one_hot(batch_action, num_classes=self.num_actions).float().to(self.device)

        # ❌ 修正：使用 batch_action_one_hot 作为输入
        q1_curr, q2_curr = self.critic1_head(feat_curr, batch_action_one_hot)
        q1_curr = q1_curr.squeeze(1)  # 确保维度是 [B]
        q2_curr = q2_curr.squeeze(1)  # 确保维度是 [B]

        # 目标 Q 值 target_q 维度是 [B, 1]，需要对齐
        critic_loss = F.mse_loss(q1_curr.unsqueeze(1), target_q) + F.mse_loss(q2_curr.unsqueeze(1), target_q)

        self.critic_optimizer.zero_grad()
        critic_loss.backward()
        self.critic_optimizer.step()

        # =============== 2. 更新 Actor ===============
        feat_curr_actor = feat_curr.detach()
        logits, probs, log_probs = self.actor_head(feat_curr_actor)

        inf_mask_curr = (1 - state_masks) * -1e9
        masked_logits = logits + inf_mask_curr
        probs = F.softmax(masked_logits, dim=-1)
        log_probs = F.log_softmax(masked_logits, dim=-1)

        feat_curr_expanded = feat_curr_actor.unsqueeze(1).repeat(1, self.num_actions, 1).view(-1,
                                                                                              feat_curr_actor.size(-1))
        q1_actor_expanded, q2_actor_expanded = self.critic_target1_head(feat_curr_expanded, all_actions_one_hot_batch)

        q1_actor = q1_actor_expanded.view(self.batch_size, self.num_actions)
        q2_actor = q2_actor_expanded.view(self.batch_size, self.num_actions)

        min_q_actor = torch.min(q1_actor, q2_actor)

        actor_loss = (probs * (self.log_alpha.exp().detach() * log_probs - min_q_actor)).sum(dim=-1).mean()

        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.actor_head.parameters(), max_norm=1.0)
        self.actor_optimizer.step()

        # =============== 3. 更新 Alpha (熵系数) ===============
        # 计算当前策略的熵
        with torch.no_grad():
            current_entropy = -(probs * log_probs).sum(dim=-1).mean()

        # Alpha 损失：让熵接近目标熵
        alpha_loss = (self.log_alpha.exp() * (current_entropy - self.target_entropy).detach()).mean()

        self.alpha_optimizer.zero_grad()
        alpha_loss.backward()
        self.alpha_optimizer.step()

        # =============== 4. 软更新目标网络 ===============
        for param, target_param in zip(self.critic1_head.parameters(), self.critic_target1_head.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

        for param, target_param in zip(self.critic2_head.parameters(), self.critic_target2_head.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

    def _filter_large_backbones(self,sd):
        # 只要命中这些前缀，就不写入 checkpoint
        drop_prefixes = (
            "bert.",  # SharedFeatureExtractor.bert
            "widget_model.bert.",  # WidgetEmbed 里若注册了 bert
            "widget_model.model.",  # 有些封装会叫 model
            "multimodalModel.bert.",  # 以防万一
        )
        out = {}
        for k, v in sd.items():
            if k.startswith(drop_prefixes):
                continue
            out[k] = v
        return out

    def save_model(self, path_prefix, save_optim=False):
        import os
        dir_name = os.path.dirname(path_prefix)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name)
        sfe_sd = self.shared_feature_extractor.state_dict()
        sfe_sd = self._filter_large_backbones(sfe_sd)
        save_dict = {
            "shared_feature_extractor": sfe_sd,
            "actor_head": self.actor_head.state_dict(),
            "critic1_head": self.critic1_head.state_dict(),
            "critic2_head": self.critic2_head.state_dict(),
            "critic_target1_head": self.critic_target1_head.state_dict(),
            "critic_target2_head": self.critic_target2_head.state_dict(),
            "log_alpha": self.log_alpha.detach().cpu(),
        }
        if save_optim:
            save_dict.update({
                "actor_optimizer": self.actor_optimizer.state_dict(),
                "critic_optimizer": self.critic_optimizer.state_dict(),
                "alpha_optimizer": self.alpha_optimizer.state_dict(),
            })
        save_path = f"{path_prefix}_sac_model.pth"
        torch.save(save_dict, save_path)
        logger.info(f"✅ 模型已保存(已剥离BERT): {save_path}")

    def load_model(self, path):
        import os
        if not os.path.exists(path):
            logger.error(f"❌ 模型文件不存在: {path}")
            return
        checkpoint = torch.load(path, map_location=self.device)
        # strict=False：因为 checkpoint 里不会有 bert 相关权重
        self.shared_feature_extractor.load_state_dict(
            checkpoint["shared_feature_extractor"], strict=False
        )
        self.actor_head.load_state_dict(checkpoint["actor_head"])
        self.critic1_head.load_state_dict(checkpoint["critic1_head"])
        self.critic2_head.load_state_dict(checkpoint["critic2_head"])
        self.critic_target1_head.load_state_dict(checkpoint["critic_target1_head"])
        self.critic_target2_head.load_state_dict(checkpoint["critic_target2_head"])
        with torch.no_grad():
            self.log_alpha.copy_(checkpoint["log_alpha"].to(self.device))
        if "actor_optimizer" in checkpoint:
            self.actor_optimizer.load_state_dict(checkpoint["actor_optimizer"])
        if "critic_optimizer" in checkpoint:
            self.critic_optimizer.load_state_dict(checkpoint["critic_optimizer"])
        if "alpha_optimizer" in checkpoint:
            self.alpha_optimizer.load_state_dict(checkpoint["alpha_optimizer"])
        logger.info(f"✅ 模型已加载: {path}")