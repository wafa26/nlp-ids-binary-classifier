import os
import torch
from torch.utils.data import DataLoader
from transformers import (
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
    DistilBertTokenizerFast
)
from datasets import load_from_disk

#GPU:
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"\n Using device: {device}")

#CONFIG
model_name = "distilbert-base-uncased"
output_dir = "models/distilbert_model_output"
data_dir = "../tokenized_output_distilbert"

#LOAD DATA
dataset = load_from_disk(data_dir)
dataset = dataset.train_test_split(test_size=0.2)

#COMPUTE CLASS WEIGHTS
label_list = dataset['train']['label']
num_malicious = sum(label_list)
num_benign = len(label_list) - num_malicious
total = len(label_list)
weight_benign = total / (2 * num_benign)
weight_malicious = total / (2 * num_malicious)
class_weights = torch.tensor([weight_benign, weight_malicious])

print(f"Benign: {num_benign}, Malicious: {num_malicious}")
print(f"Class Weights: {class_weights}")


model = DistilBertForSequenceClassification.from_pretrained(model_name, num_labels=2)
model.to(device)

#METRICS
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = torch.argmax(torch.tensor(logits), dim=1)
    acc = (preds == torch.tensor(labels)).float().mean()
    return {"accuracy": acc.item()}

#CUSTOM TRAINER
class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.logits
        loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights.to(logits.device))
        loss = loss_fn(logits, labels)
        return (loss, outputs) if return_outputs else loss

#TRAINING ARGS
training_args = TrainingArguments(
    output_dir=output_dir,
    evaluation_strategy="epoch",      
    save_strategy="epoch",            
    save_total_limit=2,
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=32,
    num_train_epochs=5,
    weight_decay=0.01,
    load_best_model_at_end=True,
    logging_dir="./logs",
    logging_steps=100,
    report_to="none",                
)

#TRAINER
trainer = WeightedTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset["train"],
    eval_dataset=dataset["test"],
    tokenizer=DistilBertTokenizerFast.from_pretrained(model_name),
    compute_metrics=compute_metrics,
    callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
)


trainer.train()
trainer.save_model(output_dir)
print(f"\n Model saved to {output_dir}")
