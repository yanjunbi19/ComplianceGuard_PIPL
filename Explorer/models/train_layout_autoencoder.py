# train_layout_autoencoder.py
import os
import sys
import xml.etree.ElementTree as ET
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from loguru import logger

# 配置 Loguru 日志
logger.remove()
logger.add(sys.stderr, level="INFO")
logger.add("training_log.log", level="DEBUG", rotation="10 MB")

# --- 从 autoencoder.py 导入必要的类 ---
# 确保 autoencoder.py 文件与此脚本在同一个目录下
try:
    from autoencoder import ScreenLayout, LayoutAutoEncoder
except ImportError as e:
    logger.error(f"Failed to import from autoencoder.py: {e}")
    logger.error("Please ensure autoencoder.py is in your Python path or current directory.")
    sys.exit(1)


# --- 配置参数 ---
XML_ROOT_DIR = '/workspace/xml' # 你的XML数据文件的根目录
MODEL_SAVE_DIR = 'pretrained_models' # 训练好的模型保存目录
MODEL_FILENAME = 'layout_encoder.pth' # 最终模型文件的名称

BATCH_SIZE = 64        # 每次训练使用的样本数量，可根据GPU内存调整
LEARNING_RATE = 0.001  # 学习率
NUM_EPOCHS = 200       # 训练的总轮数
LOG_INTERVAL = 50      # 每隔多少个批次打印一次训练损失
SAVE_INTERVAL = 20     # 每隔多少个 epoch 保存一次模型检查点

# 检测 GPU 是否可用
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
logger.info(f"Using device: {DEVICE}")

# --- 自定义数据集类 ---
class LayoutDataset(Dataset):
    def __init__(self, xml_root_dir):
        self.xml_files = []
        for root, _, files in os.walk(xml_root_dir):
            for file in files:
                if file.endswith('.xml'):
                    self.xml_files.append(os.path.join(root, file))
        logger.info(f"Found {len(self.xml_files)} XML files for training.")
        if not self.xml_files:
            logger.warning(f"No XML files found in '{xml_root_dir}'. Please check the path and file extensions.")

    def __len__(self):
        return len(self.xml_files)

    def __getitem__(self, idx):
        xml_path = self.xml_files[idx]
        try:
            with open(xml_path, 'r', encoding='utf-8') as f:
                xml_str = f.read()

            screen_layout = ScreenLayout(xml_str)
            layout_vector = screen_layout.pixels.flatten()

            return torch.as_tensor(layout_vector, dtype=torch.float)
        except ET.ParseError as e:
            logger.warning(f"Skipping malformed XML file '{xml_path}': {e}. Returning zero tensor.")
            return torch.zeros(11200, dtype=torch.float)
        except Exception as e:
            logger.error(f"Error processing XML file '{xml_path}': {e}. Returning zero tensor.")
            return torch.zeros(11200, dtype=torch.float)


# --- 训练函数 ---
def train_layout_autoencoder():
    os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
    final_model_path = os.path.join(MODEL_SAVE_DIR, MODEL_FILENAME)

    dataset = LayoutDataset(XML_ROOT_DIR)
    if not dataset.xml_files:
        logger.error("No valid XML files found to train. Exiting.")
        return

    # **新增：划分数据集为训练集和验证集**
    train_size = int(0.8 * len(dataset)) # 80% 用于训练
    val_size = len(dataset) - train_size # 20% 用于验证
    train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
    logger.info(f"Dataset split: {len(train_dataset)} for training, {len(val_dataset)} for validation.")

    num_workers = os.cpu_count() // 2 if os.cpu_count() else 0
    if os.name == 'nt':
        num_workers = 0
    logger.info(f"Using {num_workers} data loader workers.")

    train_dataloader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, num_workers=num_workers)
    val_dataloader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, num_workers=num_workers) # 验证集不需要 shuffle

    model = LayoutAutoEncoder().to(DEVICE)
    logger.info("LayoutAutoEncoder model initialized.")

    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)

    # **新增：跟踪最佳验证损失和对应的 epoch**
    best_val_loss = float('inf')
    best_epoch = -1

    logger.info("Starting training...")
    for epoch in range(NUM_EPOCHS):
        model.train() # 设置模型为训练模式
        running_loss = 0.0
        for i, inputs in enumerate(train_dataloader): # 使用 train_dataloader
            if inputs.sum().item() == 0 and inputs.numel() == 11200:
                continue

            inputs = inputs.to(DEVICE)

            optimizer.zero_grad()
            reconstructed_outputs = model(inputs)
            loss = criterion(reconstructed_outputs, inputs)
            loss.backward()
            optimizer.step()

            running_loss += loss.item()

            if (i + 1) % LOG_INTERVAL == 0:
                logger.info(f'Epoch [{epoch+1}/{NUM_EPOCHS}], Batch [{i+1}/{len(train_dataloader)}], Train Loss: {loss.item():.4f}')

        epoch_train_loss = running_loss / len(train_dataloader)
        logger.info(f'Epoch [{epoch+1}/{NUM_EPOCHS}] finished, Average Train Loss: {epoch_train_loss:.4f}')

        # **新增：验证阶段**
        model.eval() # 设置模型为评估模式 (不更新权重，禁用 dropout 等)
        val_loss = 0.0
        with torch.no_grad(): # 在验证阶段不需要计算梯度
            for i, inputs in enumerate(val_dataloader): # 使用 val_dataloader
                if inputs.sum().item() == 0 and inputs.numel() == 11200:
                    continue
                inputs = inputs.to(DEVICE)
                reconstructed_outputs = model(inputs)
                loss = criterion(reconstructed_outputs, inputs)
                val_loss += loss.item()
        epoch_val_loss = val_loss / len(val_dataloader)
        logger.info(f'Epoch [{epoch+1}/{NUM_EPOCHS}], Average Validation Loss: {epoch_val_loss:.4f}')

        # **新增：保存最佳模型**
        if epoch_val_loss < best_val_loss:
            best_val_loss = epoch_val_loss
            best_epoch = epoch + 1
            best_model_path = os.path.join(MODEL_SAVE_DIR, f"layout_encoder_best_val_loss.pth")
            torch.save(model.state_dict(), best_model_path)
            logger.info(f"New best model saved at Epoch {best_epoch} with Validation Loss: {best_val_loss:.4f}")

        # 保存检查点 (可以保留，与最佳模型分开)
        if (epoch + 1) % SAVE_INTERVAL == 0:
            current_save_path = os.path.join(MODEL_SAVE_DIR, f"layout_encoder_ep{epoch+1}.pth")
            torch.save(model.state_dict(), current_save_path)
            logger.info(f"Model checkpoint saved to {current_save_path}")

    logger.info("Training finished.")
    logger.info(f"Best model was saved from Epoch {best_epoch} with Validation Loss: {best_val_loss:.4f}")

# --- 主程序入口 ---
if __name__ == "__main__":
    train_layout_autoencoder()
