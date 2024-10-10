import re
import requests
from urllib.parse import urlparse

# Regular Expression for URL Validation
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'  # http:// or https://
        r'([a-zA-Z0-9\-_]+\.[a-zA-Z]{2,6}\.?)+',  # domain name
        re.IGNORECASE
    )
    return re.match(regex, url) is not None

# List of suspicious keywords commonly used in phishing URLs
suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank']

def check_suspicious_patterns(url):
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return True
    return False

# Check if the domain is in a known list of phishing domains (you can maintain a list or use external services)
known_phishing_domains = [
    'examplephishing.com',  # Replace with actual known phishing domains
    'malicious-site.net'
]

def check_known_phishing_domains(url):
    domain = urlparse(url).netloc
    return domain in known_phishing_domains

# Optional: Google Safe Browsing API Check (requires API key)
def check_google_safe_browsing(api_key, url):
    safe_browsing_url = "https://safebrowsing.googleapis.comy/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "your-client-id",  # Use any arbitrary string
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": api_key}
    response = requests.post(safe_browsing_url, json=payload, params=params)
    return response.json()

# Main Phishing Scanner Function
def phishing_link_scanner(url, google_api_key=None):
    if not is_valid_url(url):
        return "Invalid URL format."

    # Check for suspicious patterns in the URL
    if check_suspicious_patterns(url):
        return "Suspicious keywords detected in URL."

    # Check if domain is in known phishing domains list
    if check_known_phishing_domains(url):
        return "Known phishing domain detected."

    # Optional: Google Safe Browsing API check
    if google_api_key:
        result = check_google_safe_browsing(google_api_key, url)
        if result.get('matches'):
            return "URL flagged by Google Safe Browsing."

    return "URL appears to be safe."

# Example Usage
url_to_check = "http://examplephishing.com/login"
google_api_key = "your-google-api-key"  # Optional: Set this if you want to use Google's Safe Browsing API
result = phishing_link_scanner(url_to_check, google_api_key)
print(result)
