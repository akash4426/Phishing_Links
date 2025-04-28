import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import dns.resolver

# Load trained model, scaler, and expected feature names
model = joblib.load("phishing_model_updated1.pkl")
scaler = joblib.load("scaler.pkl")
expected_columns = joblib.load("features1.pkl")

# DNS Cache to speed up DNS checks
dns_cache = {}

def check_dns(domain, rtype):
    key = (domain, rtype)
    if key in dns_cache:
        return dns_cache[key]
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']  # Use Cloudflare DNS for fast and reliable results
        resolver.resolve(domain, rtype, lifetime=2)
        dns_cache[key] = 1
    except:
        dns_cache[key] = 0
    return dns_cache[key]

# Trusted brand keywords
trusted_keywords = ["facebook", "paypal", "microsoft", "google", "apple", "amazon", "netflix", "adobe"]

# Suspicious TLDs
suspicious_tlds = [
    ".zip", ".review", ".country", ".kim", ".cricket", ".science", ".work", ".party",
    ".gq", ".cf", ".ml", ".tk", ".top", ".fit", ".men", ".loan", ".download", ".racing",
    ".accountant", ".stream", ".mom", ".bar", ".faith", ".date", ".click", ".host", ".link",
    ".pw", ".xn--p1ai", ".buzz", ".surf", ".mls", ".rest", ".xn--80asehdb", ".cam", ".uno",
    ".vegas", ".bid", ".trade", ".webcam", ".lt"
]

# Feature extraction
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
        'domain_suffix': len(ext.suffix),  # encoding suffix safely by its length
        'has_a_record': check_dns(domain, 'A'),
        'has_mx_record': check_dns(domain, 'MX'),
        'subdomain_depth': len(subdomain_parts),
        'suspicious_tld': int(suffix in suspicious_tlds),
        'has_trusted_keyword': int(any(kw in ext.domain.lower() for kw in trusted_keywords))
    }

    return features

# Streamlit UI
st.set_page_config(page_title="Phishing URL Detector", page_icon="🚨")
st.title("🚨 Real-Time Phishing URL Detector")
st.write("Enter any URL below to check if it is **Phishing**, **Suspicious**, or **Legitimate**.")

url = st.text_input("🔗 Enter URL here:")

if st.button("Check URL"):
    if url:
        # Extract features
        features = extract_features(url)
        input_df = pd.DataFrame([features])

        # Reorder to match model's training features
        input_df = input_df.reindex(columns=expected_columns, fill_value=0)

        # Scale input features
        input_scaled = scaler.transform(input_df)

        # Predict
        phishing_proba = model.predict_proba(input_scaled)[0][1]

        # Result display
        if phishing_proba > 0.7:
            st.error(f"🚨 Phishing Detected! (Confidence: {phishing_proba*100:.2f}%)")
        elif 0.4 < phishing_proba <= 0.7:
            st.warning(f"⚠️ Suspicious URL! (Confidence: {phishing_proba*100:.2f}%)")
        else:
            st.success(f"✅ Legitimate Website (Confidence: {(1-phishing_proba)*100:.2f}%)")

        # Show extracted features
        st.subheader("🔍 Extracted Features:")
        st.json(features)

    else:
        st.warning("⚠️ Please enter a valid URL.")
