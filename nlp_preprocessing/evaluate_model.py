import torch 
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from datasets import load_from_disk
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay,roc_curve,auc
import matplotlib.pyplot as plt
import numpy as np 
import os

#config:
eval_dir = "outpout_evaluation"
os.makedirs(eval_dir, exist_ok=True)

#Load model:
model_dir= "models/distilbert_model_output"
model= DistilBertForSequenceClassification.from_pretrained(model_dir)
tokenizer= DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
model.eval()

#GPU:
device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

#load data:
data_path= "tokenized_output_distilbert"
dataset= load_from_disk(data_path)
test_dataset= dataset.train_test_split(test_size=0.2)["test"]

#test and evaluate:
all_predictions= []
all_labels= []

for item in test_dataset:
    input_ids=torch.tensor(item["input_ids"]).unsqueeze(0).to(device)
    attention_mask=torch.tensor(item["attention_mask"]).unsqueeze(0).to(device)
    label=item["label"]

    with torch.no_grad():
        outpout=model(input_ids=input_ids, attention_mask=attention_mask)
        pred= torch.argmax(outpout.logits, dim=1).item()

    all_predictions.append(pred)
    all_labels.append(label)

#Classification report:
print("---Classification Report: ---")
print(classification_report(all_labels,all_predictions,target_names=["benign","malicious"]))

#Confusion matrix:
cm=confusion_matrix(all_labels,all_predictions)
disp=ConfusionMatrixDisplay(confusion_matrix=cm,display_labels=["benign", "malicious"])
disp.plot(cmap="Blues")
plt.title("Confusion Matrix")
plt.savefig(os.path.join(eval_dir,"confusion_matrix.png"))
plt.show()

