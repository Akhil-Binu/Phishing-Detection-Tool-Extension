import tldextract
import dns.resolver

# Popular brand list to check typosquatting against
POPULAR_BRANDS = [
    'google', 'paypal', 'microsoft', 'apple', 'amazon', 'facebook', 
    'netflix', 'chase', 'wellsfargo', 'github', 'instagram', 'linkedin', 
    'twitter', 'yahoo', 'coinbase', 'steamcommunity', 'fedex', 'dhl'
]

# TLDs highly associated with spam/phishing (low cost or unregulated)
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'work', 'su', 'space', 'fit', 'tk', 'cf', 
    'gq', 'ga', 'ml', 'date', 'faith', 'science', 'party', 'zip', 'kim'
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_typosquatting(domain_name: str) -> dict:
    """Checks if a domain is a typosquatting attempt of a famous brand."""
    domain_name = domain_name.lower()
    
    # If the domain is exactly a popular brand, it's safe (e.g. google.com)
    if domain_name in POPULAR_BRANDS:
        return {"is_typosquatted": False, "brand": None, "distance": 0}
        
    for brand in POPULAR_BRANDS:
        dist = levenshtein_distance(domain_name, brand)
        # Distance of 1 or 2 characters indicates a typo variant
        # Ignore extremely short brand names to avoid false positives (e.g., if domain name is 2 chars)
        if dist in [1, 2] and len(domain_name) >= 4:
            # Check if brand is a substring or close match
            # e.g., 'paypa1' vs 'paypal' is distance 1
            return {
                "is_typosquatted": True,
                "brand": brand,
                "distance": dist
            }
            
    # Also check if popular brand is embedded suspiciously inside a longer domain
    # e.g. paypal-security-update.com
    for brand in POPULAR_BRANDS:
        if brand in domain_name and domain_name != brand:
            # If the domain has extra hyphens/words around the brand, flag it
            return {
                "is_typosquatted": True,
                "brand": brand,
                "distance": -1 # Special flag for embedding
            }
            
    # Tokenize compound domains by hyphens/dots/underscores
    tokens = [t for t in domain_name.replace('_', '-').replace('.', '-').split('-') if t]
    for token in tokens:
        if token in POPULAR_BRANDS:
            return {
                "is_typosquatted": True,
                "brand": token,
                "distance": -1 # Embedded brand (e.g. chase-security)
            }
        for brand in POPULAR_BRANDS:
            dist = levenshtein_distance(token, brand)
            if dist in [1, 2] and len(token) >= 4:
                return {
                    "is_typosquatted": True,
                    "brand": brand,
                    "distance": dist # Typosquatted and embedded (e.g. paypa1-security)
                }

    return {"is_typosquatted": False, "brand": None, "distance": 0}

def check_dns_records(domain: str) -> dict:
    """Verifies live DNS records for a domain (MX, NS, A)."""
    dns_info = {
        "has_mx": False,
        "has_ns": False,
        "has_a": False,
        "resolves": False,
        "error": None
    }
    
    try:
        # Check A record (IP resolution)
        a_records = dns.resolver.resolve(domain, 'A')
        dns_info["has_a"] = len(a_records) > 0
        dns_info["resolves"] = True
    except Exception as e:
        dns_info["error"] = str(e)
        # If it doesn't resolve, it could be inactive or offline
        return dns_info

    try:
        # Check MX record (mail exchanger - phishing sites often skip this)
        mx_records = dns.resolver.resolve(domain, 'MX')
        dns_info["has_mx"] = len(mx_records) > 0
    except Exception:
        dns_info["has_mx"] = False

    try:
        # Check NS record (nameserver)
        ns_records = dns.resolver.resolve(domain, 'NS')
        dns_info["has_ns"] = len(ns_records) > 0
    except Exception:
        dns_info["has_ns"] = False
        
    return dns_info

def analyze_domain_reputation(domain: str) -> dict:
    """Compiles heuristics reports for a given domain name."""
    # Extract structural details using tldextract
    extracted = tldextract.extract(f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain)
    domain_body = extracted.domain
    tld = extracted.suffix
    full_domain = f"{domain_body}.{tld}" if tld else domain_body
    
    reputation_score = 1.0 # Starts at perfect 1.0, drops with suspicious indicators
    flags = []
    
    # 1. Typosquatting Check
    typo_check = check_typosquatting(domain_body)
    if typo_check["is_typosquatted"]:
        if typo_check["distance"] == -1:
            reputation_score -= 0.5
            flags.append(f"Typosquatting: Domain embeds trademarked brand '{typo_check['brand']}' suspiciously.")
        else:
            reputation_score -= 0.6
            flags.append(f"Typosquatting: Domain '{full_domain}' is extremely similar to trademarked brand '{typo_check['brand']}' (Levenshtein distance {typo_check['distance']}).")

    # 2. Suspicious TLD Check
    if tld in SUSPICIOUS_TLDS:
        reputation_score -= 0.25
        flags.append(f"Suspicious TLD: Top-level domain '.{tld}' is commonly used for spam/phishing campaigns.")
        
    # 3. DNS Verification
    dns_check = check_dns_records(full_domain)
    if dns_check["resolves"]:
        if not dns_check["has_mx"]:
            # Drop score slightly, legitimate domains usually have mail servers
            reputation_score -= 0.15
            flags.append("DNS Check: Domain has no mail server (MX record) configured.")
    else:
        # If domain doesn't resolve at all
        reputation_score -= 0.1
        flags.append("DNS Check: Domain could not be resolved (NXDOMAIN or DNS timeout).")

    # Bound reputation score between 0.0 and 1.0
    reputation_score = max(0.0, min(1.0, reputation_score))
    
    status = "safe"
    if reputation_score <= 0.4:
        status = "danger"
    elif reputation_score <= 0.75:
        status = "suspicious"
        
    return {
        "domain": full_domain,
        "reputation_score": reputation_score,
        "status": status,
        "flags": flags,
        "dns": {
            "resolves": dns_check["resolves"],
            "has_mx": dns_check["has_mx"],
            "has_ns": dns_check["has_ns"],
            "has_a": dns_check["has_a"]
        }
    }
