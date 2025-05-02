@echo off
echo  Activating virtual environment...
pause
call .venv\Scripts\activate.bat

echo --------------------------------------------
echo  Step 1: Extracting data from PCAP...
python data_extraction.py

echo --------------------------------------------
echo  Step 2: NLP preprocessing...
python run_preprocessing.py

echo --------------------------------------------
echo ⏸ Step 3: Run the notebook `load_parquet.ipynb` manually.
echo  Open the file: nlp_preprocessing\load_parquet.ipynb
echo  Make sure it generates:
echo     ➤ outpout_data\final_structured_cleaned_payloads.csv

pause

echo --------------------------------------------
echo  Step 4: Merging PCAP + Parquet datasets...
python nlp_preprocessing\merge.py

echo --------------------------------------------
echo  Done.. generating data 
echo  json file will be used for tokenization.
pause
