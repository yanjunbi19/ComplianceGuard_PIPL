'''
构建领域迁移模型
'''
import torch
from transformers import BertTokenizer, BertForMaskedLM, DataCollatorForLanguageModeling
from transformers import Trainer, TrainingArguments
from datasets import Dataset, load_dataset

# Step 1: 加载你的隐私政策段落文件
def load_text_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    return {'text': lines}

# Step 2: 构建 Dataset 对象
file_path = "processed_paragraphs/all_paragraphs.txt"
raw_data = load_text_file(file_path)
dataset = Dataset.from_dict(raw_data)

# Step 3: 加载中文 BERT tokenizer 和模型
model_name = "hfl/chinese-roberta-wwm-ext"
tokenizer = BertTokenizer.from_pretrained(model_name)
model = BertForMaskedLM.from_pretrained(model_name)

# Step 4: 分词函数
def tokenize_function(examples):
    return tokenizer(
        examples["text"],
        padding="max_length",
        truncation=True,
        max_length=512,
        return_special_tokens_mask=True,
    )

# Step 5: 应用分词
tokenized_datasets = dataset.map(tokenize_function, batched=True, num_proc=4, remove_columns=["text"])

# Step 6: 设置 MLM 数据增强器
data_collator = DataCollatorForLanguageModeling(
    tokenizer=tokenizer,
    mlm=True,
    mlm_probability=0.15
)

# Step 7: 定义训练参数
training_args = TrainingArguments(
    output_dir="models/cpp-chinese-roberta-wwm-ext-transfer",
    overwrite_output_dir=True,
    num_train_epochs=10,
    per_device_train_batch_size=32,
    learning_rate=1e-5,
    save_strategy="epoch",
    logging_steps=100,
    save_total_limit=2,
    seed=42
)

# Step 8: 初始化 Trainer 并开始训练
trainer = Trainer(
    model=model,
    args=training_args,
    data_collator=data_collator,
    train_dataset=tokenized_datasets,
)

# 开始训练
trainer.train()

# Step 9: 保存最终模型
model.save_pretrained("models/cpp-chinese-roberta-wwm-ext-transfer")
tokenizer.save_pretrained("models/cpp-chinese-roberta-wwm-ext-transfer")