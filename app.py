import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver
import socket

# Load trained model, scaler, and expected feature names
model = joblib.load("phishing_model_updated1.pkl")
scaler = joblib.load("scaler.pkl")
expected_columns = joblib.load("features1.pkl")

# DNS Cache to reduce repeated queries
dns_cache = {}

def check_dns(domain, rtype):
    key = (domain, rtype)
    if key in dns_cache:
        return dns_cache[key]
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '8.8.8.8']  # Cloudflare and Google DNS
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, rtype)
        dns_cache[key] = 1 if answers else 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout,
            dns.resolver.NoNameservers, socket.gaierror, Exception):
        dns_cache[key] = 0
    return dns_cache[key]

# Trusted brand keywords to detect brand obfuscation
trusted_keywords = ["facebook", "paypal", "microsoft", "google", "apple", "amazon", "netflix", "adobe"]

# Known suspicious TLDs
suspicious_tlds = [
    ".zip", ".review", ".country", ".kim", ".cricket", ".science", ".work", ".party",
    ".gq", ".cf", ".ml", ".tk", ".top", ".fit", ".men", ".loan", ".download", ".racing",
    ".accountant", ".stream", ".mom", ".bar", ".faith", ".date", ".click", ".host", ".link",
    ".pw", ".xn--p1ai", ".buzz", ".surf", ".mls", ".rest", ".xn--80asehdb", ".cam", ".uno",
    ".vegas", ".bid", ".trade", ".webcam", ".lt"
]

# Feature extraction function
def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    domain = f"{ext.domain}.{ext.suffix}"
    subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
    suffix = "." + ext.suffix.lower()

    features = {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'digit_count': sum(c.isdigit() for c in url),
        'is_https': int(url.startswith('https')),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'domain_suffix': len(ext.suffix),  # Suffix encoded as length
        'has_a_record': check_dns(domain, 'A'),
        'has_mx_record': check_dns(domain, 'MX'),
        'subdomain_depth': len(subdomain_parts),
        'suspicious_tld': int(suffix in suspicious_tlds),
        'has_trusted_keyword': int(any(kw in ext.domain.lower() for kw in trusted_keywords))
    }

    return features

# Streamlit UI setup
st.set_page_config(page_title="Phishing URL Detector", page_icon="🚨")
st.title("🚨 Real-Time Phishing URL Detector")
st.write("Enter any URL below to check if it is **Phishing**, **Suspicious**, or **Legitimate**.")

url = st.text_input("🔗 Enter URL here:")

if st.button("Check URL"):
    if url:
        try:
            # Extract and transform features
            features = extract_features(url)
            input_df = pd.DataFrame([features])
            input_df = input_df.reindex(columns=expected_columns, fill_value=0)
            input_scaled = scaler.transform(input_df)

            # Predict probability
            phishing_proba = model.predict_proba(input_scaled)[0][1]

            # Display prediction with special condition for suspicious TLDs
            if features['suspicious_tld'] == 1:
                phishing_proba = 1.0
                st.warning(f"⚠️ Suspicious URL due to TLD! (Confidence: {phishing_proba * 100:.2f}%)")
            elif phishing_proba > 0.7:
                st.error(f"🚨 Phishing Detected! (Confidence: {phishing_proba * 100:.2f}%)")
            elif 0.4 < phishing_proba <= 0.7:
                st.warning(f"⚠️ Suspicious URL! (Confidence: {phishing_proba * 100:.2f}%)")
            else:
                st.success(f"✅ Legitimate Website (Confidence: {(1 - phishing_proba) * 100:.2f}%)")
        
        except Exception as e:
            st.error(f"❌ Error processing the URL: {str(e)}")

    else:
        st.warning("⚠️ Please enter a valid URL.")
