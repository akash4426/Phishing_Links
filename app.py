import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver
import socket
import whois
from datetime import datetime

# Load model and input scaler
model = joblib.load("phishing_model_updated1.pkl")
scaler = joblib.load("scaler.pkl")
expected_columns = joblib.load("features1.pkl")

# DNS cache
dns_cache = {}

def check_dns(domain, rtype):
    key = (domain, rtype)
    if key in dns_cache:
        return dns_cache[key]
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '8.8.8.8']
        resolver.timeout = 3
        resolver.lifetime = 3
        resolver.resolve(domain, rtype)
        dns_cache[key] = 1
    except Exception:
        dns_cache[key] = 0
    return dns_cache[key]

# Suspicious TLDs list
suspicious_tlds = [
    ".zip", ".review", ".country", ".kim", ".cricket", ".science", ".work", ".party",
    ".gq", ".cf", ".ml", ".tk", ".top", ".fit", ".men", ".loan", ".download", ".racing",
    ".accountant", ".stream", ".mom", ".bar", ".faith", ".date", ".click", ".host", ".link",
    ".pw", ".buzz", ".surf", ".cam", ".uno", ".bid", ".trade", ".webcam", ".lt", ".site"
]

trusted_keywords = ["facebook", "paypal", "microsoft", "google", "apple", "amazon", "netflix", "adobe"]

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return (datetime.now() - creation_date).days
    except:
        pass
    return 0  # Default to newly registered

# Feature extraction for model input
def extract_model_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
    suffix = "." + ext.suffix.lower()

    return {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'digit_count': sum(c.isdigit() for c in url),
        'is_https': int(url.startswith('https')),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'domain_suffix': len(ext.suffix),
        'has_a_record': check_dns(domain, 'A'),
        'has_mx_record': check_dns(domain, 'MX'),
        'subdomain_depth': len(subdomain_parts),
        'suspicious_tld': int(suffix in suspicious_tlds),
        'has_trusted_keyword': int(any(kw in ext.domain.lower() for kw in trusted_keywords)),
    }

# Extra (non-model) features for manual logic
def extract_extra_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    suffix = "." + ext.suffix.lower()

    return {
        'suspicious_tld': int(suffix in suspicious_tlds),
        'whois_age_days': get_domain_age(domain)
    }

# Streamlit App
st.set_page_config(page_title="Phishing URL Detector", page_icon="🚨")
st.title("🚨 Real-Time Phishing URL Detector")
st.write("Enter any URL below to check if it is **Phishing**, **Suspicious**, or **Legitimate**.")

url = st.text_input("🔗 Enter URL here:")

if st.button("Check URL"):
    if url:
        try:
            model_features = extract_model_features(url)
            extra_features = extract_extra_features(url)

            # Convert to DataFrame
            input_df = pd.DataFrame([model_features])
            input_df = input_df.reindex(columns=expected_columns, fill_value=0)
            input_scaled = scaler.transform(input_df)
            phishing_proba = model.predict_proba(input_scaled)[0][1]

            # === Post-prediction rules ===
            if extra_features['suspicious_tld'] == 1:
                phishing_proba = 1.0
                st.warning(f"⚠️ Suspicious TLD detected! (Confidence: {phishing_proba * 100:.2f}%)")
            elif extra_features['whois_age_days'] < 30:
                phishing_proba = max(phishing_proba, 0.85)
                st.warning(f"⚠️ Newly registered domain (<30 days)! (Adjusted Confidence: {phishing_proba * 100:.2f}%)")

            # Final output
            if phishing_proba > 0.7:
                st.error(f"🚨 Phishing Detected! (Confidence: {phishing_proba * 100:.2f}%)")
            elif 0.4 < phishing_proba <= 0.7:
                st.warning(f"⚠️ Suspicious URL! (Confidence: {phishing_proba * 100:.2f}%)")
            else:
                st.success(f"✅ Legitimate Website (Confidence: {(1 - phishing_proba) * 100:.2f}%)")

        except Exception as e:
            st.error(f"❌ Error: {str(e)}")
    else:
        st.warning("⚠️ Please enter a valid URL.")
