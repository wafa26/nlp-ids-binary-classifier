from urllib.parse import urlparse, parse_qs, unquote
import os
import pandas as pd
import pyshark
import json
import base64
import re
import ipaddress
#config:
os.makedirs("outpout_data", exist_ok=True)

def decode_hex_string(hex_string):
  try:
    bytes_object= bytes.fromhex(hex_string.replace(":",""))
    return bytes_object.decode('utf-8',errors='ignore')
  except:
    return hex_string

pcap_files=["data/extracted_2301.pcap","data/extracted_2201.pcap"]

#storing the http data: 
http_data= []

#extracting http features from packets that are useful for an NLP model:
def extract_http_features(packet):
  try:
    if "HTTP" in packet:
      http_layer= packet.http 

      #extract http method:
      http_method=getattr(http_layer, 'request_method', 'UNKNOWN')

      #extract full URL:
      full_url= getattr(http_layer, 'request_full_uri', '')
      parsed_url= urlparse(full_url)
      url_path= parsed_url.path
      hostname= parsed_url.hostname
      try:
         ipaddress.ip_address(hostname)
         tld= "IP_ADDRESS"
      except:
         tld= hostname.split(".")[-1] if hostname else "UNKNOWN"
      

      #extracting headers :
      #headers= http_layer._all_fields

      #extracting features from headers:
      referer = str(getattr(http_layer, 'referer', 'UNKNOWN')) or 'UNKNOWN'
      user_agent = str(getattr(http_layer, 'user_agent', 'UNKNOWN')) or 'UNKNOWN'
      cookies = str(getattr(http_layer, 'cookie', 'UNKNOWN')) or 'UNKNOWN'
      auth_header = str(getattr(http_layer, 'authorization', 'UNKNOWN')) or 'UNKNOWN'
      content_type = str(getattr(http_layer, 'content_type', 'UNKNOWN')) or 'UNKNOWN'
      accept_encoding = str(getattr(http_layer, 'accept_encoding', 'UNKNOWN')) or 'UNKNOWN'
      accept_language = str(getattr(http_layer, 'accept_language', 'UNKNOWN')) or 'UNKNOWN'

      #extracting body request for POSTs: 
      body=''
      if http_method.upper() == "POST":
        body = getattr(http_layer, 'file_data','') or getattr(http_layer,'data','') or ''
        body=decode_hex_string(body)

        #query params:
       
      query_parameters= json.dumps(parse_qs(parsed_url.query))
      if http_method.upper()=='POST' and not parsed_url.query:
        if 'application/x-www-form-urlencoded' in content_type:
          body_query= parse_qs(body)
          if body_query:
            query_parameters=json.dumps(body_query)

      #checking for encoded data in body : used in some attacks
      match_base64= bool(re.search(r'([A-Za-z0-9+/=]{20,})',body))
      match_hex= bool(re.search(r'([0-9A-Fa-f]{10,})',body))

      #combine all potential malicious sources: 
      combined_payload= "".join([
        body,
        parsed_url.query or '',
        cookies,
        user_agent,
        referer,
        auth_header
      ])
      decoded_payload= unquote(combined_payload).lower()
      #checking for patterns used in sql injection:
      sql_patterns= [ r"\bselect\b", r"\binsert\b", r"\bupdate\b", r"\bdelete\b", r"\bdrop\b", r"\bunion\b",
                r"\b(and|or)\b\s+[^\s]+\s*=\s*[^\s]+",         
                r"['\"]\s*or\s*['\"]?\d+=\d+",                
                r"\b\d+\s*=\s*\d+\b" ]
      sql_matches= [re.search(p,decoded_payload) for p in sql_patterns if re.search(p,decoded_payload)]
      sql_keywords=[m.group(0) for m in sql_matches if m] if sql_matches else []

      #checking for patterns used in shell injection:
      shell_patterns=[
    # Common tools used in shell attacks
    r"(curl|wget|bash|sh|nc|netcat|python|perl|powershell|cmd|scp|ftp)",  # tools
    r"(cmd(\.exe)?|powershell(\.exe)?)",                                  # Windows shells
    r"/bin/(sh|bash|nc|cat)",                                             # Unix shell paths
    r"(bash|sh)\s+-i",                                                    # Reverse shell pattern
    r"nc\s+-e\s+/bin/sh",                                                 # Netcat reverse shell
    r"exec\s+/bin/sh",                                                    # Exec shell
    r"(bash|sh)\s+-c\s+['\"].+?['\"]",                                     # Inline shell command
    r"powershell\s+-[eE]ncode[d]?",                                       # Encoded PowerShell
    r"(?:wget|curl)\s+http[s]?://",                                       # Downloading tools
    r"rm\s+-rf\s+/",                                                      # Dangerous delete
    r"scp\s+\S+\s+\S+",                                                   # File copy over SSH
    r"\$\((.*?)\)",                                                       # Subshell: $(...)
    r"`.*?`",                                                             # Backtick execution
    r"base64\s+-d",                                                       # Base64 decoding in shell

    # Chaining only if following suspicious commands — avoids false positives
    r"(?:(?:curl|wget|bash|sh|nc|netcat|python|perl|powershell|cmd|scp|ftp)[^;|&]{0,40})(\||;|&&)",  
]
      shell_matches= [re.search(p,decoded_payload) for p in shell_patterns if re.search(p,decoded_payload)]
      shell_keywords= [m.group(0) for m in shell_matches if m] if shell_matches else []


      #XSS patterns
      xss_patterns = [
            r"<script.*?>.*?</script>",  
            r"(on\w+\s*=)",  
            r"(document\.cookie)",
            r"(alert\s*\()",
            r"(eval\s*\()",
            r"(<img\s+[^>]*onerror\s*=)",  
            r"(<svg\s+[^>]*onload\s*=)"    
        ]
      xss_matches =[re.search(p, decoded_payload) for p in xss_patterns if re.search(p, decoded_payload)]
      xss_keywords =[m.group(0) for m in xss_matches if m] if xss_matches else []
    
    #trying to label the data:
      is_malicious=(
      bool(sql_keywords or shell_keywords or xss_keywords)
        or (match_base64 and len(body)> 500) or (match_hex and len(body)>500)
    )

      #clean headers dict:
      headers_dict= http_layer._all_fields.copy()
      headers_dict.pop('', None)

      #now store all this in the http_data:
      http_data.append({
          "method": http_method,
          "full_url": full_url,
          "url_path":url_path,
          "query_parameters":query_parameters,
          "tld": tld,
          "headers": json.dumps(headers_dict),
          "referer": referer,
          "user_agent": user_agent,
          "cookies": cookies,
          "auth_header": auth_header,
          "content_type": content_type,
          "accept_encoding": accept_encoding,
          "accept_language": accept_language,
          "request_length": len(body),
          "file_data": body,
          "base64_payload": match_base64,
          "hex_encoded": match_hex,
          "sql_keywords": json.dumps(sql_keywords),
          "shell_keywords": json.dumps(shell_keywords),
          "xss_keywords": json.dumps(xss_keywords),
          "malicious": is_malicious

        })
      #if is_malicious:
        #print(f"[!] Suspicious : {full_url}\n SQL/ {sql_keywords}\n Shell: {shell_keywords}\n XSS: {xss_keywords}\n")
    
  except Exception as e:
    print(f"error occured : {e}")

#Now process the two pcap files:
for file in pcap_files:
  print(f"processing file : {file}")
  capture=pyshark.FileCapture(file,display_filter="http",keep_packets=False)
  for packet in capture:
    extract_http_features(packet)
  capture.close()

#converting the data to a dataframe:
df= pd.DataFrame(http_data)
pd.set_option('display.max_columns', None)
print(f"\n Extracted {len(http_data)} HTTP packets.")
print(df.head())
#save to csv:
df.to_csv("outpout_data/http_features.csv", index=False)
print("extracted features saved to http_features.csv")

