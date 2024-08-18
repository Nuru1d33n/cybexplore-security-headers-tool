import requests
from bs4 import BeautifulSoup
import os
from datetime import datetime
import sys
import argparse
# from pyuseragents import useragents
import pyuseragents

def get_http_headers(url, user_agent=pyuseragents.random()):
    try:
        headers = {'User-Agent': user_agent}
        response = requests.get(url, headers=headers)
        return response.headers
    except requests.RequestException as e:
        print(f"Error fetching headers from {url}: {e}")
        return {}

def get_server_info(headers):
    return headers.get('Server', '')

def detect_cms(soup):
    cms_indicators = {
        'WordPress': '<meta name="generator" content="WordPress"',
        'Joomla': '<meta name="generator" content="Joomla!',
        'Drupal': '<meta name="generator" content="Drupal',
        'Magento': '<meta name="generator" content="Magento',
        'Shopify': '<meta name="generator" content="Shopify'
    }
    
    cms_detected = []
    for cms, tag in cms_indicators.items():
        if soup.find('meta', attrs={'name': 'generator', 'content': True}):
            if tag in str(soup):
                cms_detected.append(cms)
    
    return cms_detected

def detect_frameworks(html):
    patterns = {
        'React': 'react.development.js',
        'Angular': 'angular.min.js',
        'Vue.js': 'vue.js',
        'Ember': 'ember-template-compiler.js'
    }
    
    frameworks_detected = []
    for framework, pattern in patterns.items():
        if pattern in html:
            frameworks_detected.append(framework)
    
    return frameworks_detected

def check_ssl_certificate(url):
    try:
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0]
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
        return cert
    except Exception as e:
        print(f"Error checking SSL certificate for {url}: {e}")


def check_security_headers(headers):
    vulnerabilities = []
    
    # Check for X-Frame-Options
    if 'X-Frame-Options' not in headers:
        vulnerabilities.append("Missing X-Frame-Options header. Vulnerable to Clickjacking attacks.")
    
    # Check for X-XSS-Protection
    if headers.get('X-XSS-Protection', '') != '1; mode=block':
        vulnerabilities.append("Missing or misconfigured X-XSS-Protection header. Vulnerable to XSS attacks.")
    
    # Check for X-Content-Type-Options
    if 'X-Content-Type-Options' not in headers:
        vulnerabilities.append("Missing X-Content-Type-Options header. Vulnerable to MIME-type sniffing attacks.")
    
    # Check for Content-Security-Policy
    if 'Content-Security-Policy' not in headers:
        vulnerabilities.append("Missing Content-Security-Policy header. Vulnerable to content injection attacks.")
    
    # Check for Strict-Transport-Security (HSTS)
    if 'Strict-Transport-Security' not in headers and 'https://' in headers.get('Location', ''):
        vulnerabilities.append("Missing Strict-Transport-Security header. Vulnerable to downgrade attacks.")
    
    # Check for Referrer-Policy
    if 'Referrer-Policy' not in headers:
        vulnerabilities.append("Missing Referrer-Policy header. May expose referrer information.")
    
    return vulnerabilities

def exploit_vulnerability(url, vulnerability):
    print(f"Attempting to exploit {vulnerability} on {url}...")
    
    if vulnerability == "Missing X-Frame-Options header. Vulnerable to Clickjacking attacks.":
        # Example exploitation: Check if Clickjacking is possible
        exploit_html = f'<iframe src="{url}" style="height: 500px; width: 500px;"></iframe>'
        with open('clickjacking_exploit.html', 'w') as file:
            file.write(exploit_html)
        print("Clickjacking exploit saved to clickjacking_exploit.html")
    
    elif vulnerability == "Missing or misconfigured X-XSS-Protection header. Vulnerable to XSS attacks.":
        # Example exploitation: Attempt to inject XSS
        payload = '<script>alert("XSS")</script>'
        try:
            response = requests.get(f"{url}/?q={payload}")
            if payload in response.text:
                print("XSS successful! Payload executed.")
            else:
                print("XSS attempt failed.")
        except requests.RequestException as e:
            print(f"Error attempting XSS: {e}")
    
    elif vulnerability == "Missing X-Content-Type-Options header. Vulnerable to MIME-type sniffing attacks.":
        # Example exploitation: MIME Sniffing attack simulation (pseudo-code)
        print("MIME Sniffing attack not directly exploitable in this context.")
    
    elif vulnerability == "Missing Content-Security-Policy header. Vulnerable to content injection attacks.":
        # Example exploitation: Injecting a script (pseudo-code)
        print("Content Injection attempted (result depends on site context).")
    
    elif vulnerability == "Missing Strict-Transport-Security header. Vulnerable to downgrade attacks.":
        # Example exploitation: Downgrade attack (pseudo-code)
        print("Downgrade attack requires more advanced setup (out of scope).")
    
    elif vulnerability == "Missing Referrer-Policy header. May expose referrer information.":
        # Example exploitation: Referrer leakage (pseudo-code)
        print("Referrer Policy exploit depends on site behavior.")
    
    else:
        print(f"No known exploit available for {vulnerability}.")

def mitigate_vulnerability(url, vulnerability):
    print(f"Attempting to mitigate {vulnerability} on {url}...")
    
    if vulnerability == "Missing X-Frame-Options header. Vulnerable to Clickjacking attacks.":
        # Suggest mitigation
        print(f"Mitigation: Add 'X-Frame-Options: DENY' header to prevent Clickjacking.")
    
    elif vulnerability == "Missing or misconfigured X-XSS-Protection header. Vulnerable to XSS attacks.":
        # Suggest mitigation
        print(f"Mitigation: Add 'X-XSS-Protection: 1; mode=block' header to protect against XSS.")
    
    elif vulnerability == "Missing X-Content-Type-Options header. Vulnerable to MIME-type sniffing attacks.":
        # Suggest mitigation
        print(f"Mitigation: Add 'X-Content-Type-Options: nosniff' header to prevent MIME-type sniffing.")
    
    elif vulnerability == "Missing Content-Security-Policy header. Vulnerable to content injection attacks.":
        # Suggest mitigation
        print(f"Mitigation: Implement a 'Content-Security-Policy' header to control resources the user agent is allowed to load.")
    
    elif vulnerability == "Missing Strict-Transport-Security header. Vulnerable to downgrade attacks.":
        # Suggest mitigation
        print(f"Mitigation: Add 'Strict-Transport-Security' header to enforce HTTPS and prevent downgrade attacks.")
    
    elif vulnerability == "Missing Referrer-Policy header. May expose referrer information.":
        # Suggest mitigation
        print(f"Mitigation: Add 'Referrer-Policy' header to control how much referrer information is sent with requests.")
    
    else:
        print(f"No known mitigation steps available for {vulnerability}.")

def scan_url(url):
    print(f"Scanning {url}...\n")
    headers = get_http_headers(url)
    server_info = get_server_info(headers)
    
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        html = response.text
    except requests.RequestException as e:
        print(f"Error fetching content from {url}: {e}")
        return
    
    cms_detected = detect_cms(soup)
    frameworks_detected = detect_frameworks(html)
    vulnerabilities = check_security_headers(headers)
    
    result = []
    
    # HTTP Headers
    if headers:
        result.append("HTTP Headers:")
        for key, value in headers.items():
            result.append(f"{key}: {value}")
    
    # Server Information
    if server_info:
        result.append(f"\nServer Information: {server_info}")
    
    # CMS Detected
    if cms_detected:
        result.append(f"\nCMS Detected: {', '.join(cms_detected)}")
    
    # Frameworks Detected
    if frameworks_detected:
        result.append(f"\nFrameworks Detected: {', '.join(frameworks_detected)}")
    
    # Vulnerabilities
    if vulnerabilities:
        result.append("\nPotential Vulnerabilities Detected:")
        for vulnerability in vulnerabilities:
            result.append(f"- {vulnerability}")
            exploit_vulnerability(url, vulnerability)  # Attempt to exploit the detected vulnerability
            mitigate_vulnerability(url, vulnerability)  # Provide mitigation steps for the detected vulnerability
    else:
        result.append("\nNo obvious vulnerabilities detected from headers.")
    
    result.append("\n" + "-"*50 + "\n")
    
    return "\n".join(result)

def log_scan_results(urls, scan_results):
    log_dir = "scan_logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"scan_log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
    
    with open(log_file, 'w') as file:
        file.write(f"Scan Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write("\n".join(scan_results))
    
    print(f"Scan results saved to {log_file}")

def main():
    parser = argparse.ArgumentParser(description="URL/IP Scanner with CMS and Framework Detection")
    parser.add_argument('input', help="URL/IP, multiple URLs/IPs separated by commas, or path to file")
    args = parser.parse_args()
    
    user_input = args.input
    
    if os.path.isfile(user_input):
        with open(user_input, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
    else:
        urls = [url.strip() for url in user_input.split(',') if url.strip()]
    
    scan_results = []
    
    for url in urls:
        print(f"Scanning {url}...")
        result = scan_url(url)
        if result:
            scan_results.append(f"\nScanning Results for {url}:\n{result}")
    
    if scan_results:
        log_scan_results(urls, scan_results)
    else:
        print("No scan results available.")

if __name__ == "__main__":
    main()
