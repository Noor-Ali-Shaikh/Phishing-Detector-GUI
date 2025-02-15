import whois
from urllib.parse import urlparse

def is_suspicious_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc  

    print("\nChecking URL:", url)

    # Check if domain is very new (possible phishing)
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            print(f"Domain Created On: {domain_info.creation_date[0]}")
            if (2025 - domain_info.creation_date[0].year) < 1:
                print("Warning: This domain is very new. Possible phishing!")
    except:
        print("Unable to fetch WHOIS data.")

    # Check for common phishing patterns
    suspicious_keywords = ["login", "verify", "secure", "update", "bank"]
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        print("Alert: URL contains phishing-related words!")

    # Shortened URL check
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
    if parsed_url.netloc in shorteners:
        print("Warning: This is a shortened URL. Might be phishing!")

    print("URL scan completed!\n")

url = input("Enter a URL to check: ")
is_suspicious_url(url)
