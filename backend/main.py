import sys
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import tldextract

# Ensure the backend directory is in the Python search path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import local modules
from ml.classifier import classifier
from utils.heuristics import analyze_domain_reputation

app = FastAPI(
    title="Phishing Detection API",
    description="AI + Cybersecurity phishing classification API using Machine Learning and Domain Heuristics.",
    version="1.0.0"
)

# CORS Configuration
# Allow all origins to let browser extensions communicate without restriction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models for Requests & Responses ---

class URLScanRequest(BaseModel):
    url: str = Field(..., description="The full URL to scan for phishing indicators.", example="http://login-paypal-security-update.com/signin")

class EmailScanRequest(BaseModel):
    text: str = Field(..., description="The body text of the email to analyze.", example="Dear user, verify your account details immediately.")

# --- Endpoints ---

@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend is up and models are loaded."""
    models_loaded = classifier.url_model is not None and classifier.email_model is not None
    return {
        "status": "healthy",
        "models_loaded": models_loaded
    }

@app.post("/api/scan/url")
def scan_url(request: URLScanRequest):
    """
    Scans a URL using both Machine Learning classification and domain reputation heuristics.
    Combines the results to determine the overall risk status.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    # Standardize URL prefix for domain parsing
    if not url.startswith(('http://', 'https://')):
        parsed_url = "http://" + url
    else:
        parsed_url = url
        
    # Extract domain
    extracted = tldextract.extract(parsed_url)
    domain_name = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    if not domain_name:
        raise HTTPException(status_code=400, detail="Invalid URL format or unable to extract domain")

    # Run checks
    ml_result = classifier.analyze_url(parsed_url)
    domain_result = analyze_domain_reputation(domain_name)
    
    # Blend scores
    # ml_score is 0-1 (higher is phishing)
    # reputation_score is 0-1 (higher is safe, so 1.0 - reputation_score is threat)
    ml_score = ml_result["score"]
    domain_threat = 1.0 - domain_result["reputation_score"]
    
    # Typosquatting acts as a strong multiplier
    has_typosquatting = any("Typosquatting" in f for f in domain_result["flags"])
    
    # Combined Threat Score calculation
    if has_typosquatting:
        # Give more weight to domain typosquatting since it is a highly explicit indicator
        combined_score = max(ml_score, 0.8) * 0.5 + domain_threat * 0.5
    else:
        # Balanced average
        combined_score = (ml_score * 0.6) + (domain_threat * 0.4)
        
    # Classify overall risk level
    risk_level = "safe"
    if combined_score >= 0.70 or has_typosquatting:
        risk_level = "danger"
    elif combined_score >= 0.35:
        risk_level = "suspicious"
        
    # Aggregate all explanation triggers
    all_triggers = list(set(ml_result["triggers"] + domain_result["flags"]))
    if not all_triggers:
        if risk_level == "safe":
            all_triggers.append("URL passed all ML checks and heuristic filters.")
        else:
            all_triggers.append("Subtle indicator patterns identified in lexical structure.")

    return {
        "url": url,
        "domain": domain_name,
        "threat_score": round(combined_score, 4),
        "risk_level": risk_level,
        "is_phishing": risk_level == "danger",
        "ml_analysis": {
            "score": round(ml_score, 4),
            "risk_level": ml_result["risk_level"],
            "triggers": ml_result["triggers"]
        },
        "domain_analysis": {
            "reputation_score": round(domain_result["reputation_score"], 4),
            "status": domain_result["status"],
            "flags": domain_result["flags"],
            "dns": domain_result["dns"]
        },
        "all_triggers": all_triggers
    }

@app.post("/api/scan/email")
def scan_email(request: EmailScanRequest):
    """
    Analyzes an email's body text using the TF-IDF ML classifier
    and NLP keyword-based heuristic warnings.
    """
    text = request.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Email body text cannot be empty")
        
    # Run analysis
    result = classifier.analyze_email(text)
    
    return {
        "text_preview": text[:100] + ("..." if len(text) > 100 else ""),
        "threat_score": round(result["score"], 4),
        "risk_level": result["risk_level"],
        "is_phishing": result["risk_level"] == "danger",
        "triggers": result["triggers"] if result["triggers"] else ["No obvious phishing language triggers matched."]
    }

@app.get("/api/scan/domain/{domain}")
def scan_domain(domain: str):
    """
    Dedicated endpoint to run detailed reputation check on a standalone domain.
    """
    domain = domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter cannot be empty")
        
    result = analyze_domain_reputation(domain)
    return result

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
