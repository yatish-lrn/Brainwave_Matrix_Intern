import re
import requests

# List of suspicious keywords often used in phishing URLs
suspicious_keywords = ['login', 'secure', 'signin', 'verify', 'update', 'account']

def check_url(url):
    # Check if URL uses HTTPS
    if not url.startswith("https://"):
        print(f"Warning: {url} does not use HTTPS.")

    # Check for suspicious keywords in the URL
    for keyword in suspicious_keywords:
        if keyword in url:
            print(f"Alert: URL contains suspicious keyword: '{keyword}'.")

    # Check the domain name for potential phishing indicators (typos, long names)
    domain = re.findall(r'https?://([A-Za-z_0-9.-]+).*', url)
    if domain:
        domain_name = domain[0]
        # Heuristic: If the domain name is unusually long
        if len(domain_name) > 20:
            print(f"Warning: Domain '{domain_name}' is unusually long, might be suspicious.")

    # Send request to the website
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"URL is reachable: {url}")
        else:
            print(f"URL responded with status code: {response.status_code}")
    except requests.RequestException:
        print(f"Failed to connect to {url}, it might be down or malicious.")

# Test the function with a URL
url_to_test1= "https://play.google.com"
url_to_test2="https://instagram.com"
check_url(url_to_test1)
check_url(url_to_test2)
