import re
import html
from urllib.parse import unquote
import base64

def is_base64_encoded(st):
    try:
        return base64.b64encode(base64.b64decode(st)).decode()==st
    except Exception:
        return False
    
def decode_base64(st):
    try:
        return base64.b64decode(st).decode("utf-8", errors="ignore")
    except Exception:
        return st
    
def decode_hex(st):
    try:
        st=st.replace(":","")
        return bytes.fromhex(st).decode("utf-8",errors="ignore")
    except Exception:
        return st
    
def remove_fingerprint_patterns(text):
    if not isinstance(text, str):
        return text 
    #normalizing null bytes with semantic nlp token :
    if "\x00" in text:
        text=text.replace("\x00", "<NULL>")
    #normalizing sql injection:
    text=re.sub(r"(?i)(\b\d\s*=\s*\d\b|\bor\b\s+\d\s*=\s*\d|\bselect\b|\bunion\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|--|#|/\*|\*/|exec\b|concat\b|sleep\s*\()"," <SQL_INJECTION> ", text)
    #xss payloads:
    text = re.sub(
    r"(?i)(<script.*?>|</script>|on\w+\s*=\s*['\"]?.*?['\"]?|javascript:|data:text/html|alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|function\s*\(|srcdoc=)",
    " <XSS_PAYLOAD> ",
    text
)
    #shell keywords:
    text=re.sub(r"(?i)(bash|curl|wget|sh|nc|ncat|perl|python|py|netcat|powershell|pwsh|cmd|cmd\.exe|-e|--exec|--data|-X|base64|/bin/sh)", " <SHELL_COMMAND> ", text)
    #path traversal:
    text=re.sub(r"(?i)(\.\./|\.\.\\|%2e%2e/|%2e%2e\\|/etc/passwd|boot\.ini|win\.ini)"
, " <PATH_TRAVERSAL> ", text)
    #file extensions:
    text=re.sub(r"\.(php[3-8]?|jsp|jspx|asp|aspx|exe|sh|py|cgi|bat|jar|dll|pl|cmd|\w+\.(php|exe|sh))"
 , " <FILE_EXTENSION> " , text)
    #ip address:
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP_ADDRESS>", text)

    return text

#removing words that can introduce biais when training the nlp model:
def remove_biaised_words(text):
    if not isinstance(text,str):
        return text
    bias_words=['dvwa', 'hackazon', 'mutillidae', 'testfire', 'phpmyadmin', 'cicids', 'hackme']
    for word in bias_words:
        text= re.sub(rf"(?i)\b{word}\b", "", text)
    return text

#cleaning the cookies keeping the informative parts:
def clean_cookies(cookie):
    if not isinstance(cookie,str):
        return cookie
    
    cookie_pairs=cookie.split(";")
    clean_cookie_parts=[]
    for pair in cookie_pairs:
        if "=" in pair:
            key,value=pair.split("=",1)
            key=key.strip().lower()
            value=value.strip()
            if len(value)>15 or is_base64_encoded(value) or value.isalnum() and len(value)>10:
                clean_cookie_parts.append(f"{key}=<TOKEN>")
            else:
                clean_cookie_parts.append(f"{key}={value}")
        else:
            clean_cookie_parts.append(pair)
    return " ".join(clean_cookie_parts)


    
    
def clean_text(text):
    if not isinstance(text,str):
        return ""
    text= html.unescape(text)
    text= unquote(text)
    if "\x00" in text:
        text=text.replace("\x00", "<NULL>")
    text=text.lower()
    
    if is_base64_encoded(text.strip()):
        text=decode_base64(text)
    if text.count(":")>3:
        text=decode_hex(text)

    text=remove_biaised_words(text)
    text=remove_fingerprint_patterns(text)

    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP_ADDRESS>", text)

    text=text.encode("ascii","ignore").decode("utf-8","ignore")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[^a-z0-9<>_]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text