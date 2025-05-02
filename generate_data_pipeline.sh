#!/bin/bash

echo "Activating virtual environment..."
source .venv/bin/activate

echo "--------------------------------------------"
echo "Step 1: Extracting data from PCAP..."
python data_extraction.py

echo "--------------------------------------------"
echo "Step 2: NLP preprocessing..."
python run_preprocessing.py

echo "--------------------------------------------"
echo "⏸ Step 3: Executing the notebook 'nlp_preprocessing/load_parquet.ipynb'.."
jupyter nbconvert --to notebook --execute nlp_preprocessing/load_parquet.ipynb --output nlp_preprocessing/load_parquet_output.ipynb


echo "--------------------------------------------"
echo "Step 4: Merging PCAP + Parquet datasets..."
python nlp_preprocessing/merge.py

echo "Done. Data is ready. JSON output will be used for tokenization."
