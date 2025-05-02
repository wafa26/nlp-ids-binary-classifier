import os
import pandas as pd


#---CONFIG---:
input_dir = "outpout_data"
output_dir = "outpout_data"
os.makedirs(output_dir, exist_ok=True)

##input file paths: 
pcap_csv_path = os.path.join(input_dir, "cleaned_http_data.csv")
parquet_csv_path = os.path.join(input_dir, "final_structured_cleaned_payloads.csv")

#outpout file paths:
merged_csv_path = os.path.join(output_dir, "merged_nlp_payload_dataset.csv")
merged_jsonl_path = os.path.join(output_dir, "merged_nlp_payload_dataset.json")

#load data:
df_pcap = pd.read_csv(pcap_csv_path)
df_parquet = pd.read_csv(parquet_csv_path)

#ensure keyword columns exist in both:
for col in ["sql_keywords", "xss_keywords", "shell_keywords"]:
    if col not in df_pcap.columns:
        df_pcap[col] = "[]"
    if col not in df_parquet.columns:
        df_parquet[col] = "[]"


#Normalize column names:
df_pcap.columns = df_pcap.columns.str.lower()
df_parquet.columns = df_parquet.columns.str.lower()

#Normalize label values to lowercase:
df_pcap["label"] = df_pcap["label"].str.lower()
df_parquet["label"] = df_parquet["label"].str.lower()
#keep only the necessary columns
columns_to_keep = ["nlp_text", "token_count", "label", "sql_keywords", "xss_keywords", "shell_keywords"]
df_pcap_ready = df_pcap[columns_to_keep].copy()
df_parquet_ready = df_parquet[columns_to_keep].copy()


df_merged = pd.concat([df_pcap_ready, df_parquet_ready], ignore_index=True)

#Save both CSV and JSONL
df_merged.to_csv(merged_csv_path, index=False)
df_merged.to_json(merged_jsonl_path, orient="records", lines=True)

# Check label distribution
print("Label distribution:")
print(df_merged["label"].value_counts())
#final nlp check:
print(df_merged["nlp_text"].sample(5).tolist())
print(df_merged["token_count"].describe())
