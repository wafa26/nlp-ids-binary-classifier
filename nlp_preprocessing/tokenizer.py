import os
import torch
from datasets import load_dataset
from transformers import DistilBertTokenizerFast
#load json :
data_path=r"merged_nlp_payload_dataset.json"
dataset= load_dataset("json", data_files=data_path, split="train", keep_in_memory=True)

#labels mapping:

def map_labels(eg):
    eg["label"] = 1 if eg["label"]=="malicious" else 0
    return eg

dataset=dataset.map(map_labels)
#load tokenizer : distilbert:
tokenizer= DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

#now tokenize:
def tokenize_batch(batch):
    texts=[str(t) if t is not None else "" for t in batch["nlp_text"]]
    return tokenizer(
        texts,
        padding="max_length",
        truncation=True,
        max_length=128
    )
tokenized_dataset=dataset.map(tokenize_batch, batched=True)

#remove the unused columns by the model:
tokenized_dataset=tokenized_dataset.remove_columns(["nlp_text", "token_count", "sql_keywords", "xss_keywords", "shell_keywords"])

tokenized_dataset.set_format("torch")
#save to disk:
output_dir = "tokenized_output_distilbert"
tokenized_dataset.save_to_disk(output_dir)
print(f"\n tokenized dataset saved to : {output_dir}")
print(tokenized_dataset[0])
