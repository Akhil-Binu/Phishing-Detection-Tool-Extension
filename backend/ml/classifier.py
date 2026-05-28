import os
import sys
import joblib

# Ensure path includes current directory for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from train import extract_url_features, SUSPICIOUS_KEYWORDS, SHORTENERS

# Paths to models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_MODEL_PATH = os.path.join(BASE_DIR, 'url_model.joblib')
EMAIL_MODEL_PATH = os.path.join(BASE_DIR, 'email_model.joblib')

class PhishingClassifier:
    def __init__(self):
        self.url_model = None
        self.email_model = None
        self.load_models()

    def load_models(self):
        # Trigger training if models do not exist
        if not os.path.exists(URL_MODEL_PATH) or not os.path.exists(EMAIL_MODEL_PATH):
            print("Models not found. Training models first...")
            from train import main as train_models
            train_models()

        try:
            self.url_model = joblib.load(URL_MODEL_PATH)
            self.email_model = joblib.load(EMAIL_MODEL_PATH)
            print("Successfully loaded ML models.")
        except Exception as e:
            print(f"Error loading models: {e}")
            # Try retraining
            from train import main as train_models
            train_models()
            self.url_model = joblib.load(URL_MODEL_PATH)
            self.email_model = joblib.load(EMAIL_MODEL_PATH)

    def analyze_url(self, url: str):
        if not self.url_model:
            self.load_models()

        features = extract_url_features(url)
        # Convert feature dict to list in correct order
        # Feature list matches the keys returned by extract_url_features
        feature_keys = [
            'url_len', 'host_len', 'dot_count', 'hyphen_count', 'slash_count',
            'subdomain_count', 'has_at', 'has_double_slash', 'keyword_count',
            'is_ip', 'numeric_count', 'is_shortened'
        ]
        
        feature_vector = [features[k] for k in feature_keys]
        
        # Predict probability
        # [0] represents Safe class, [1] represents Phishing class
        prob = self.url_model.predict_proba([feature_vector])[0]
        phishing_score = float(prob[1]) # Probability of being phishing
        
        # Build explanation triggers
        triggers = []
        if features['is_ip'] == 1:
            triggers.append("Direct IP address used (common in phishing bypasses).")
        if features['has_at'] == 1:
            triggers.append("Contains '@' symbol (often hides actual destination domain).")
        if features['has_double_slash'] == 1:
            triggers.append("Contains double slashes '//' in path (sign of redirection).")
        if features['is_shortened'] == 1:
            triggers.append("Uses a URL shortener service (masks final URL path).")
        if features['keyword_count'] >= 1:
            triggers.append(f"Contains phishing keywords (e.g. login, verify, update).")
        if features['subdomain_count'] >= 3:
            triggers.append("High number of subdomains (common in spoofing schemes).")
        if features['numeric_count'] >= 15:
            triggers.append("High number of numeric characters in URL path.")
        
        # Heuristics based warning level
        risk_level = "safe"
        if phishing_score >= 0.75:
            risk_level = "danger"
        elif phishing_score >= 0.4:
            risk_level = "suspicious"
            
        return {
            "score": phishing_score,
            "risk_level": risk_level,
            "triggers": triggers,
            "features": features
        }

    def analyze_email(self, text: str):
        if not self.email_model:
            self.load_models()

        # Predict probability using vectorizer + model pipeline
        prob = self.email_model.predict_proba([text])[0]
        phishing_score = float(prob[1])
        
        # Build dynamic explanation triggers using simple text scanning
        triggers = []
        text_lower = text.lower()
        
        # Custom keywords scans for explanation
        urgency_terms = ['urgent', 'immediate', 'suspend', 'threat', 'cancel', 'restrict', 'unauthorized', 'locked']
        credential_terms = ['verify', 'password', 'login', 'social security', 'bank account', 'credential', 'ssn', 'pin']
        monetary_terms = ['refund', 'invoice', 'credit card', 'bitcoin', 'payment', 'transfer', 'amount', '$']
        
        found_urg = [t for t in urgency_terms if t in text_lower]
        found_cred = [t for t in credential_terms if t in text_lower]
        found_mon = [t for t in monetary_terms if t in text_lower]
        
        if found_urg:
            triggers.append(f"Urgency cues detected (terms: {', '.join(found_urg[:3])}).")
        if found_cred:
            triggers.append(f"Credential requests detected (terms: {', '.join(found_cred[:3])}).")
        if found_mon:
            triggers.append(f"Financial transaction triggers detected (terms: {', '.join(found_mon[:3])}).")
        if len(text) < 50:
            triggers.append("Email text is unusually short (often seen in quick-bait link requests).")
            
        risk_level = "safe"
        if phishing_score >= 0.7:
            risk_level = "danger"
        elif phishing_score >= 0.35:
            risk_level = "suspicious"
            
        return {
            "score": phishing_score,
            "risk_level": risk_level,
            "triggers": triggers
        }

# Singleton instance
classifier = PhishingClassifier()
