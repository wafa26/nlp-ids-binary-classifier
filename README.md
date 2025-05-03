#  Intrusion Detection System (IDS) with NLP & Deep Learning

This project implements a full pipeline for detecting malicious HTTP traffic using NLP techniques + Transformers.

---

##  Project Description 

- **Goal**: Detect attacks in HTTP requests (e.g., SQLi, XSS, Shell injection)
- **Technique**: Use NLP-based preprocessing + DistilBERT classifier
- **Data Sources**:
  - Extracted from PCAP files using PyShark
  - Parquet dataset (pre-structured payloads)
  - The data in the parquet files and the pcap files is extracted from the CSE-CIC-IDS2018: 
    `https://www.unb.ca/cic/datasets/ids-2018.html`


---

##  Project Structure

### 1. **Data Extraction from PCAP** (`data_extraction.py`)
- Parses HTTP packets from `.pcap` files
- Extracts fields like method, URL, body, headers
- Detects presence of encoded payloads and attack patterns
- Saves to `outpout_data/http_features.csv`

### 2. **Preprocessing for NLP** (`run_preprocessing.py`)
- Cleans and combines text fields into `nlp_text`
- Generates `token_count` and `label`
- Outputs `outpout_data/cleaned_http_data.csv`

### 3. **Loading Structured Parquet Dataset** (`load_parquet.ipynb`)
- Loads and processes `.parquet` files
- Extracts matching columns (e.g., `nlp_text`, `label`, `token_count`)
- Outputs `outpout_data/final_structured_cleaned_payloads.csv`

### 4. **Merging Both Datasets** (`merge.py`)
- Combines PCAP + Parquet data
- Saves as:
  - `merged_nlp_payload_dataset.csv`
  - `merged_nlp_payload_dataset.json` #This is the file that will be used for tokenization

### 5. **Tokenization & Training** ( `tokenizer.py` , `train_model.py`)
- Tokenizes merged data using `DistilBertTokenizerFast`
- Saves processed Hugging Face dataset to `tokenized_output_distilbert`
- Trains `DistilBertForSequenceClassification` using binary classification
- Saves model to `models/distilbert_model_output`

### 6. **Evaluation**
- `evaluate_model.py` → classification report + confusion matrix 
- `generate_roc.py` → ROC curve
-  Outpouts saved to `outpout_evaluation/`
---


##  Requirements
Install dependencies (from virtual env):

```bash
pip install -r requirements.txt
```

---

##  How to Run the Project

### Step-by-step:
---

### For Windows users: 

1. Activate the virtual environment and Run the data generation pipeline:
    ```bash
    double-click or type in the terminal:  `generate_data_pipeline.bat`
    ```

2. When prompted, execute the notebook `load_parquet.ipynb`
    - It must generate `outpout_data/final_structured_cleaned_payloads.csv`

3. Press any key to continue the script (it will merge datasets)

4. Tokenize and train the model (after data is ready):
    run : 
    ```bash
    python tokenizer.py
    ```

    ```bash
    python train_model.py
    ```

    - Tokenized data is saved to: `tokenized_output_distilbert/`
    - Model is saved to: `models/distilbert_model_output/`

5. Evaluate model:
    ```bash
    python evaluate_model.py
    python generate_roc.py
    ```

---

### For Linux/macOs Users: 

1. Make the pipeline script executable:
    ```bash
    chmod +x generate_data_pipeline.sh
    ```

2. Run the pipeline:
    ```bash
    ./generate_data_pipeline.sh
    ```

3. The script will automatically:
    - Run `data_extraction.py`
    - Run `run_preprocessing.py`
    - Run the notebook `load_parquet.ipynb` (no GUI) using `nbconvert`
    - Then continue with merging via `merge.py`

4. After the data is prepared, run training:
    ```bash
    python tokenizer.py
    python train_model.py
    ```

5. And evaluate:
    ```bash
    python evaluate_model.py
    python generate_roc.py
    ```

---
##  Output Samples
- `merged_nlp_payload_dataset.csv` — ready-to-train dataset
- `confusion_matrix.png`, `roc_curve.png` — saved in `outpout_evaluation/`

---

##  License
MIT License .


