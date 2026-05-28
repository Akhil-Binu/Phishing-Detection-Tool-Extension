import os
import re
import numpy as np
import pandas as pd
import joblib
import tldextract
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

# Ensure the output directories exist
os.makedirs(os.path.dirname(os.path.abspath(__file__)), exist_ok=True)

# ---------------------------------------------------------
# 1. URL FEATURE EXTRACTION & DATASET SYNTHESIS
# ---------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    'login', 'bank', 'secure', 'update', 'verify', 'signin', 
    'account', 'pay', 'support', 'webscr', 'cmd', 'service', 
    'billing', 'credential', 'recovery', 'confirm', 'netflix',
    'paypal', 'microsoft', 'google', 'apple', 'chase', 'wellsfargo'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 
    'adf.ly', 'bit.do', 'ow.ly', 'rebrand.ly', 'tiny.cc'
]

def is_ip_address(hostname):
    # Regex to match IPv4
    ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ipv4_pattern, hostname):
        return 1
    # Check for IPv6
    if ":" in hostname and len(hostname) > 4:
        return 1
    return 0

def extract_url_features(url):
    features = {}
    
    # Parse URL
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    hostname = f"{subdomain}.{domain}.{suffix}" if subdomain else f"{domain}.{suffix}"
    
    # Raw features
    features['url_len'] = len(url)
    features['host_len'] = len(hostname)
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['slash_count'] = url.count('/')
    features['subdomain_count'] = len(subdomain.split('.')) if subdomain else 0
    features['has_at'] = 1 if '@' in url else 0
    
    # Double slash check (after http:// or https://)
    has_double_slash = 0
    if '//' in url:
        idx = url.find('//')
        if idx > 6: # if it occurs somewhere else in the URL
            has_double_slash = 1
    features['has_double_slash'] = has_double_slash
    
    # Suspicious keywords count
    kw_count = 0
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            kw_count += 1
    features['keyword_count'] = kw_count
    
    # IP Address check
    features['is_ip'] = is_ip_address(domain)
    
    # Numeric character count
    features['numeric_count'] = sum(c.isdigit() for c in url)
    
    # Shortener check
    is_shortened = 0
    for sh in SHORTENERS:
        if sh in url_lower:
            is_shortened = 1
            break
    features['is_shortened'] = is_shortened
    
    return features

def generate_url_dataset():
    # Base lists of domain/path strings
    safe_roots = [
        "google.com", "youtube.com", "facebook.com", "wikipedia.org", 
        "yahoo.com", "amazon.com", "apple.com", "microsoft.com", 
        "linkedin.com", "netflix.com", "github.com", "reddit.com", 
        "stackoverflow.com", "zoom.us", "cloudflare.com", "medium.com",
        "nytimes.com", "bbc.com", "cnn.com", "spotify.com"
    ]
    
    safe_paths = [
        "", "/search?q=machine+learning", "/feed", "/wiki/Phishing",
        "/about", "/contact", "/pricing", "/docs/api/v1", "/profile/settings",
        "/watch?v=dQw4w9WgXcQ", "/dp/B08N5WRWNW", "/products/office365",
        "/users/login-history", "/issues/404", "/articles/latest"
    ]
    
    phishing_domains = [
        "login-paypal-security-update.com", "verify-bankofamerica.net",
        "micros0ft-office-secure.xyz", "update-account-verification.info",
        "secure-login-wellsfargo-bank.com", "chase-bank-verify-identity-alert.net",
        "netflix-billing-update-support.xyz", "apple-icloud-findmyphone-login.info",
        "secure-signin-ebayisapi.cc", "support-google-account-recovery.cf",
        "webscr-cmd-signin.co.cc", "irs-tax-refund-portal.gov-online.top",
        "blockchain-wallet-verification.net", "coinbase-login-protection.club",
        "steam-community-tradeoffer.su", "adobe-document-verify-login.work",
        "dhl-parcel-tracking-receive.xyz", "fedex-delivery-address-update.xyz",
        "facebook-security-checkpoints.com", "instagram-bluebadge-verify.top"
    ]
    
    phishing_paths = [
        "/login.php", "/signin/index.html", "/verify-account", "/secure/update",
        "/webscr?cmd=_login-run", "/billing-information/change", "/reset-password",
        "/recovery/confirm.html", "/auth/login", "/signin/credentials",
        "/account-verification", "/wallet/import", "/trade/accept"
    ]
    
    data = []
    
    # 1. Generate Safe URLs
    for root in safe_roots:
        for path in safe_paths:
            url = f"https://{root}{path}"
            data.append((url, 0)) # 0 = Safe
            # Add some subdomain variations
            url_sub = f"https://support.{root}{path}"
            data.append((url_sub, 0))
            url_blog = f"https://blog.{root}{path}"
            data.append((url_blog, 0))

    # 2. Generate Phishing URLs
    for pdom in phishing_domains:
        for ppath in phishing_paths:
            url = f"http://{pdom}{ppath}"
            data.append((url, 1)) # 1 = Phishing
            # Add subdomains to phishing
            url_sub = f"http://secure.login.{pdom}{ppath}"
            data.append((url_sub, 1))
            url_ssl = f"https://verify.identity.{pdom}{ppath}"
            data.append((url_ssl, 1))
            
    # 3. Add IP address URLs (phishing indicators)
    ips = ["192.168.1.105", "104.244.42.1", "172.217.16.14", "8.8.8.8"]
    for ip in ips:
        for ppath in phishing_paths:
            data.append((f"http://{ip}{ppath}", 1))
            
    # 4. Add shortened URLs
    shortened_urls = [
        "https://bit.ly/3jKls89", "https://tinyurl.com/y6yxyz12", 
        "https://t.co/ab12cd34", "http://goo.gl/xyz789", "https://is.gd/verify12"
    ]
    for surl in shortened_urls:
        data.append((surl, 1))
        
    return pd.DataFrame(data, columns=['url', 'label'])


# ---------------------------------------------------------
# 2. EMAIL TEXT FEATURE EXTRACTION & DATASET SYNTHESIS
# ---------------------------------------------------------

def generate_email_dataset():
    # Templates for synthesising emails
    phishing_greetings = ["Dear Customer,", "Dear Valued User,", "Attention Account Holder,", "Dear Member,", "URGENT NOTICE:", "Hello,"]
    phishing_urgency = [
        "Your account has been temporarily suspended due to suspicious login attempts.",
        "We detected an unauthorized transaction of $499.99 on your debit card.",
        "Your subscription billing information has expired and must be updated immediately.",
        "Important tax documents require your immediate signature to avoid penalties.",
        "Your security questions have been changed. If this wasn't you, click below."
    ]
    phishing_call_to_action = [
        "Please click the link below to verify your identity and restore access.",
        "Login immediately to confirm you authorized this transfer.",
        "Click here to update your payment details: http://billing-update-net.xyz/login",
        "Verify your credentials within 24 hours to prevent account closure.",
        "Download the attached secure form to claim your refund."
    ]
    phishing_signoffs = ["Sincerely, Security Department", "Regards, Billing Support", "Thanks, Helpdesk Team", "Customer Operations"]

    safe_greetings = ["Hi Akhil,", "Hey Akhil,", "Good morning Akhil,", "Hello team,", "Dear Akhil Binu,", "Hi everyone,"]
    safe_bodies = [
        "Here is the weekly update on the Phishing Detection Tool project. The backend is running smoothly.",
        "I was thinking we could meet tomorrow for lunch at 12:30 PM to discuss the new extension UI.",
        "Your payment for the subscription was processed successfully. The invoice is attached for your records.",
        "Thank you for registering for the cybersecurity webinar next Tuesday. Here is your access link.",
        "Can you review the pull request I opened? It contains the Scikit-learn training script.",
        "I wanted to share this article about domain typosquatting heuristics. Let me know what you think."
    ]
    safe_signoffs = ["Best regards, Sarah", "Thanks, John", "Cheers, Dave", "Talk soon, Michael", "Best, Operations Team"]

    emails = []

    # Synthesize Phishing emails (500 variations)
    np.random.seed(42)
    for _ in range(500):
        gr = np.random.choice(phishing_greetings)
        urg = np.random.choice(phishing_urgency)
        cta = np.random.choice(phishing_call_to_action)
        so = np.random.choice(phishing_signoffs)
        text = f"{gr}\n\n{urg}\n\n{cta}\n\n{so}"
        emails.append((text, 1))

    # Synthesize Safe emails (500 variations)
    for _ in range(500):
        gr = np.random.choice(safe_greetings)
        body = np.random.choice(safe_bodies)
        so = np.random.choice(safe_signoffs)
        text = f"{gr}\n\n{body}\n\n{so}"
        emails.append((text, 0))

    return pd.DataFrame(emails, columns=['text', 'label'])


# ---------------------------------------------------------
# 3. TRAINING AND SERIALIZATION PIPELINE
# ---------------------------------------------------------

def main():
    print("=== Phishing Detection Tool - Training ML Models ===")
    
    # 1. Train URL Classifier
    print("\n[1/2] Training URL Classifier...")
    df_url = generate_url_dataset()
    print(f"Generated URL dataset with {len(df_url)} items.")
    
    # Extract features
    features_list = []
    for url in df_url['url']:
        features_list.append(extract_url_features(url))
        
    X_url = pd.DataFrame(features_list)
    y_url = df_url['label']
    
    # Split
    X_train_u, X_test_u, y_train_u, y_test_u = train_test_split(X_url, y_url, test_size=0.2, random_state=42)
    
    # Train
    clf_url = RandomForestClassifier(n_estimators=100, random_state=42)
    clf_url.fit(X_train_u, y_train_u)
    
    # Evaluate
    y_pred_u = clf_url.predict(X_test_u)
    acc_u = accuracy_score(y_test_u, y_pred_u)
    print(f"URL Classifier Accuracy: {acc_u:.4f}")
    print(classification_report(y_test_u, y_pred_u))
    
    # Save URL model
    url_model_path = os.path.join(os.path.dirname(__file__), 'url_model.joblib')
    joblib.dump(clf_url, url_model_path)
    print(f"Saved URL classifier to: {url_model_path}")
    
    # 2. Train Email Classifier
    print("\n[2/2] Training Email Classifier...")
    df_email = generate_email_dataset()
    print(f"Generated Email dataset with {len(df_email)} items.")
    
    # We will build a TF-IDF + Logistic Regression pipeline
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english', max_features=2000, ngram_range=(1, 2))),
        ('clf', LogisticRegression(random_state=42))
    ])
    
    X_email = df_email['text']
    y_email = df_email['label']
    
    # Split
    X_train_e, X_test_e, y_train_e, y_test_e = train_test_split(X_email, y_email, test_size=0.2, random_state=42)
    
    # Train
    pipeline.fit(X_train_e, y_train_e)
    
    # Evaluate
    y_pred_e = pipeline.predict(X_test_e)
    acc_e = accuracy_score(y_test_e, y_pred_e)
    print(f"Email Classifier Accuracy: {acc_e:.4f}")
    print(classification_report(y_test_e, y_pred_e))
    
    # Save Email pipeline
    email_model_path = os.path.join(os.path.dirname(__file__), 'email_model.joblib')
    joblib.dump(pipeline, email_model_path)
    print(f"Saved Email classifier pipeline to: {email_model_path}")
    
    print("\nTraining completed successfully!")

if __name__ == '__main__':
    main()
