import pandas as pd
import json
from nlp_preprocessing.text_cleaner import clean_text, clean_cookies


df= pd.read_csv("outpout_data/http_features.csv")
print(f"{len(df)} rows are loaded.")

#convert JSON to flat text before using clean_text:
def flatten_json(x):
    try:
        if not x:
            return ""
        query_dict=json.loads(x)
        key_fields=['password','pass','token','auth','key','user_token']
        flat_query=" ".join(
            f"{k}=<TOKEN>" if any(s in k.lower() for s in key_fields if key_fields) 
            else f"{k}={v[0]}" if isinstance(v,list) else f"{k}={v}" for k,v in query_dict.items()
        )
        return clean_text(flat_query)
    except Exception:
        return clean_text(str(x))


#Clean important columns:
df['clean_body']= df['file_data'].apply(clean_text)
df['clean_query']= df['query_parameters'].apply(flatten_json)
df['clean_user_agent']= df['user_agent'].apply(clean_text)
df['clean_path']= df['url_path'].apply(clean_text)
df['clean_referer']= df['referer'].apply(clean_text)
df['clean_cookies']= df['cookies'].apply(clean_cookies)
df['clean_url'] = df['full_url'].apply(clean_text)


#creating a new column that combines the cleaned fields for a single nlp input:

df['nlp_text'] = (
    df['clean_path'] + " " +
    df['clean_query'] + " " +
    df['clean_body'] + " " +
    df['clean_user_agent'] + " "+
    df['clean_referer']+ " "+
    df['clean_cookies']
)
#add a token count column (useful later):
df['token_count'] = df['nlp_text'].apply(lambda x: len(str(x).split()))

#Rename malicious column to label and map the values to malicious and benign: 
df['label']=df['malicious'].map({True:'malicious', False:'benign'})
df.drop(columns=['malicious'], inplace=True)

#removing the original columns that we cleaned: 
columns_to_remove= ['file_data', 'query_parameters', 'user_agent', 'url_path', 'referer', 'cookies',"auth_header","accept_language","tld",'content_type','headers','full_url']
df.drop(columns=columns_to_remove,inplace=True,errors='ignore')

df.to_csv("outpout_data/cleaned_http_data.csv", index=False)
print("cleaned data saved successefully.")
print('Label distribution:')
print(df['label'].value_counts())
