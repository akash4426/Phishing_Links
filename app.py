import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver

# Load trained model, scaler, and feature names
model = joblib.load("phishing_model_updated1.pkl")
scaler = joblib.load("scaler.pkl")
expected_columns = joblib.load("features1.pkl")

# DNS Cache to speed up checks
dns_cache = {}

def check_dns(domain, rtype):
    key = (domain, rtype)
    if key in dns_cache:
        return dns_cache[key]
    try:
        dns.resolver.resolve(domain, rtype, lifetime=2)
        dns_cache[key] = 1
    except:
        dns_cache[key] = 0
    return dns_cache[key]

# Trusted brand keywords
trusted_keywords = ["facebook", "paypal", "microsoft", "google", "apple", "amazon", "netflix", "adobe"]

# Suspicious TLDs
suspicious_tlds = ['zip', 'review', 'country', 'kim', 'cricket', 'science', 'work', 'party', 'gq', 'tk', 'ml', 'cf','win','lt']

# Feature extraction function
def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    domain = f"{ext.domain}.{ext.suffix}"
    subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []

    features = {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'digit_count': sum(c.isdigit() for c in url),
        'is_https': int(url.startswith('https')),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'domain_suffix': pd.Series([ext.suffix]).astype("category").cat.codes[0],
        'has_a_record': check_dns(domain, 'A'),
        'has_mx_record': check_dns(domain, 'MX'),
        'subdomain_depth': len(subdomain_parts),
        'suspicious_tld': int(ext.suffix in suspicious_tlds),
        'has_trusted_keyword': int(any(kw in ext.domain.lower() for kw in trusted_keywords))
    }

    return features

# Streamlit UI
st.title("🚨 Real-Time Phishing URL Detector")
st.write("Enter any URL below to check if it is **Phishing**, **Suspicious**, or **Legitimate**.")

url = st.text_input("🔗 Enter URL here:")

if st.button("Check URL"):
    if url:
        # Extract features
        features = extract_features(url)
        input_df = pd.DataFrame([features])

        # Reorder features to match training
        input_df = input_df.reindex(columns=expected_columns, fill_value=0)

        # Scale features
        input_scaled = scaler.transform(input_df)

        # Predict
        phishing_proba = model.predict_proba(input_scaled)[0][1]

        if phishing_proba > 0.6:
            st.error(f"🚨 Phishing Detected! (Confidence: {phishing_proba*100:.2f}%)")
        elif 0.4 < phishing_proba <= 0.6:
            st.warning(f"⚠️ Suspicious URL! (Confidence: {phishing_proba*100:.2f}%)")
        else:
            st.success(f"✅ Legitimate Website (Confidence: {(1-phishing_proba)*100:.2f}%)")
    else:
        st.warning("⚠️ Please enter a valid URL.")
