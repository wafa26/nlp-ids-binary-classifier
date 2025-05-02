
import torch
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from datasets import load_from_disk
from torch.utils.data import DataLoader
import os

#config:
eval_dir = "outpout_evaluation"
os.makedirs(eval_dir, exist_ok=True)
#Load model:
model_path = "models/distilbert_model_output"
data_path = "tokenized_output_distilbert"

model = DistilBertForSequenceClassification.from_pretrained(model_path).eval()
tokenizer =DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

device =torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

#load dataset:
dataset = load_from_disk(data_path)
test_dataset = dataset.train_test_split(test_size=0.2)["test"]
test_loader = DataLoader(test_dataset, batch_size=64)

#predict probabilities:
probs = []
labels = []

with torch.no_grad():
    for batch in test_loader:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        label = batch["label"]

        logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
        prob = torch.softmax(logits, dim=1)[:, 1]
        probs.extend(prob.cpu().numpy())
        labels.extend(label)


fpr, tpr, _ = roc_curve(labels, probs)
roc_auc =auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}", color="darkorange")
plt.plot([0, 1], [0, 1], linestyle="--", color="navy")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve")
plt.legend()
plt.savefig(os.path.join(eval_dir,"roc_curve.png"))
plt.show()
