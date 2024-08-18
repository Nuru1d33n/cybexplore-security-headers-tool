import requests
from bs4 import BeautifulSoup
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader

import pdfkit

def check_security_headers(url):
    # Make a request to the URL
    response = requests.get(url)
    
    headers = response.headers
    vulnerabilities = []
    recommendations = {
        "X-Frame-Options": {
            "Purpose": "Prevents clickjacking by controlling whether a browser should be allowed to render a page in a frame or iframe.",
            "Overview": "Can be set to 'DENY' or 'SAMEORIGIN'. 'DENY' blocks all framing, while 'SAMEORIGIN' allows framing from the same origin.",
            "Recommendation": "Use 'DENY' or 'SAMEORIGIN'. Prefer using CSP with 'frame-ancestors' directive."
        },
        "X-XSS-Protection": {
            "Purpose": "Provides basic protection against XSS attacks by enabling browser's XSS filters.",
            "Overview": "Can be set to '1; mode=block' to block pages when an XSS attack is detected, or '0' to disable XSS filtering.",
            "Recommendation": "Do not rely on this header. Use CSP for stronger XSS protection."
        },
        "X-Content-Type-Options": {
            "Purpose": "Prevents browsers from interpreting files as a different MIME type than specified.",
            "Overview": "Setting this to 'nosniff' ensures the browser respects the specified Content-Type header.",
            "Recommendation": "Set to 'nosniff' to avoid MIME type sniffing attacks."
        },
        "Referrer-Policy": {
            "Purpose": "Controls the amount of referrer information sent with requests.",
            "Overview": "Various policies such as 'no-referrer' or 'strict-origin-when-cross-origin' limit referrer data exposure.",
            "Recommendation": "Use 'no-referrer' or a similar restrictive policy to protect user privacy."
        },
        "Content-Type": {
            "Purpose": "Specifies the MIME type of the content being sent, guiding proper interpretation by the browser.",
            "Overview": "Ensures the content is interpreted correctly, avoiding MIME type confusion attacks.",
            "Recommendation": "Ensure this header is set correctly to avoid MIME type confusion."
        },
        "Set-Cookie": {
            "Purpose": "Manages cookie security attributes to prevent attacks.",
            "Overview": "Attributes like 'Secure', 'HttpOnly', and 'SameSite' enhance cookie security.",
            "Recommendation": "Use 'Secure', 'HttpOnly', and 'SameSite' attributes to protect cookies."
        },
        "Strict-Transport-Security (HSTS)": {
            "Purpose": "Enforces HTTPS connections to prevent downgrade attacks.",
            "Overview": "Directs browsers to only connect over HTTPS, ensuring secure connections.",
            "Recommendation": "Set HSTS with a long max-age value to enforce HTTPS and prevent downgrade attacks."
        },
        "Expect-CT": {
            "Purpose": "Enforces Certificate Transparency to prevent fraudulent certificates.",
            "Overview": "Requires certificates to be logged in public CT logs to detect misissued certificates.",
            "Recommendation": "Add this header to enforce Certificate Transparency and improve certificate security."
        },
        "Content-Security-Policy (CSP)": {
            "Purpose": "Mitigates various attacks by controlling the sources of content that a page can load.",
            "Overview": "Specifies allowed sources for content, reducing risks of XSS and other content injection attacks.",
            "Recommendation": "Implement a robust CSP to control content sources and mitigate code injection attacks."
        },
        "Access-Control-Allow-Origin": {
            "Purpose": "Controls which domains are allowed to access resources on the server.",
            "Overview": "Manages cross-origin resource sharing (CORS) by specifying allowed origins.",
            "Recommendation": "Configure this header to restrict access and prevent unauthorized cross-origin requests."
        },
        "Cross-Origin-Opener-Policy (COOP)": {
            "Purpose": "Isolates browsing contexts to prevent potential cross-origin attacks.",
            "Overview": "COOP ensures content is isolated from other origins, reducing attack vectors.",
            "Recommendation": "Use COOP to enhance security and isolate your browsing context."
        },
        "Cross-Origin-Embedder-Policy (COEP)": {
            "Purpose": "Prevents embedding of your content by third-party sites.",
            "Overview": "Protects your content from being embedded by unauthorized parties.",
            "Recommendation": "Implement COEP to prevent unauthorized embedding and enhance security."
        },
        "Cross-Origin-Resource-Policy (CORP)": {
            "Purpose": "Controls which origins can access resources from your site.",
            "Overview": "Manages access to your resources by different origins.",
            "Recommendation": "Use CORP to restrict access to your resources and prevent unauthorized access."
        },
        "Permissions-Policy": {
            "Purpose": "Controls which features and APIs can be used by a site or its subframes.",
            "Overview": "Restricts access to sensitive features and APIs based on origin.",
            "Recommendation": "Use Permissions-Policy to manage feature access and enhance security."
        },
        "FLoC (Federated Learning of Cohorts)": {
            "Purpose": "Controls whether FLoC is used for interest-based advertising.",
            "Overview": "Disabling FLoC helps protect user privacy by avoiding interest-based tracking.",
            "Recommendation": "Ensure FLoC is disabled to enhance privacy."
        },
        "Server": {
            "Purpose": "Reveals information about the server software used.",
            "Overview": "Exposing server details can assist attackers in identifying potential vulnerabilities.",
            "Recommendation": "Hide or obscure this header to prevent revealing server software details."
        },
        "X-Powered-By": {
            "Purpose": "Indicates the technologies used by the server.",
            "Overview": "Revealing technology stack details can aid attackers in targeting specific vulnerabilities.",
            "Recommendation": "Remove or obscure this header to prevent technology stack disclosure."
        },
        "X-AspNet-Version": {
            "Purpose": "Reveals the version of ASP.NET used by the server.",
            "Overview": "Exposing ASP.NET version details can help attackers target known vulnerabilities.",
            "Recommendation": "Remove or obscure this header to avoid version disclosure."
        },
        "X-AspNetMvc-Version": {
            "Purpose": "Indicates the version of ASP.NET MVC used by the server.",
            "Overview": "Revealing ASP.NET MVC version details can aid attackers in targeting vulnerabilities.",
            "Recommendation": "Remove or obscure this header to prevent version disclosure."
        },
        "X-DNS-Prefetch-Control": {
            "Purpose": "Controls DNS prefetching behavior in browsers.",
            "Overview": "Disabling DNS prefetching can prevent some privacy concerns related to DNS lookups.",
            "Recommendation": "Set this header to 'off' if DNS prefetching is not needed."
        },
        "Public-Key-Pins (HPKP)": {
            "Purpose": "Enforces public key pinning to prevent man-in-the-middle (MITM) attacks using fraudulent certificates.",
            "Overview": "HPKP is deprecated but was used to pin server public keys to prevent MITM attacks.",
            "Recommendation": "Be cautious with HPKP due to its deprecation and potential issues if not implemented correctly."
        },
        "X-Permitted-Cross-Domain-Policies": {
            "Purpose": "Controls cross-domain requests from Adobe Flash and other plugins.",
            "Overview": "Helps manage permissions for cross-domain requests to prevent unauthorized access.",
            "Recommendation": "Set to 'none' or 'master-only' to limit cross-domain permissions."
        },
        "Clear-Site-Data": {
            "Purpose": "Clears site data (cookies, cache, storage) for a given site.",
            "Overview": "Useful for clearing sensitive data when security breaches are suspected.",
            "Recommendation": "Use this header with caution, as it can impact user experience by clearing data."
        }
    }

    # Check for each header and assess its configuration
    header_info = {}
    for header, info in recommendations.items():
        if header in headers:
            header_info[header] = {
                "Purpose": info["Purpose"],
                "Overview": info["Overview"],
                "Present": True,
                "Value": headers[header],
                "Recommendation": info["Recommendation"],
                "Vulnerable": "No",
            }
        else:
            header_info[header] = {
                "Purpose": info["Purpose"],
                "Overview": info["Overview"],
                "Present": False,
                "Value": "N/A",
                "Recommendation": info["Recommendation"],
                "Vulnerable": "Yes",
            }

    # Add technology detection
    tech_stack = detect_technology(response)

    # Generate PDF report
    generate_pdf_report(url, header_info, tech_stack)

def detect_technology(response):
    tech_stack = {
        "Technology": "Unknown",
        "Details": []
    }

    # Detecting Content Management Systems (CMS)
    if "WordPress" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "WordPress"
        tech_stack["Details"].append("WordPress detected from X-Powered-By header.")
    elif "Drupal" in response.headers.get("X-Generator", ""):
        tech_stack["Technology"] = "Drupal"
        tech_stack["Details"].append("Drupal detected from X-Generator header.")
    elif "Joomla" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "Joomla"
        tech_stack["Details"].append("Joomla detected from X-Powered-By header.")
    elif "Magento" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "Magento"
        tech_stack["Details"].append("Magento detected from X-Powered-By header.")

    # Detecting Web Servers
    if "Apache" in response.headers.get("Server", ""):
        tech_stack["Technology"] = "Apache"
        tech_stack["Details"].append("Apache server detected from Server header.")
    elif "nginx" in response.headers.get("Server", ""):
        tech_stack["Technology"] = "nginx"
        tech_stack["Details"].append("nginx server detected from Server header.")
    elif "Microsoft-IIS" in response.headers.get("Server", ""):
        tech_stack["Technology"] = "Microsoft IIS"
        tech_stack["Details"].append("Microsoft IIS detected from Server header.")
    elif "LiteSpeed" in response.headers.get("Server", ""):
        tech_stack["Technology"] = "LiteSpeed"
        tech_stack["Details"].append("LiteSpeed server detected from Server header.")



    # Detecting Programming Languages
    if "PHP" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "PHP"
        tech_stack["Details"].append("PHP detected from X-Powered-By header.")
    elif "ASP.NET" in response.headers.get("X-AspNet-Version", ""):
        tech_stack["Technology"] = "ASP.NET"
        tech_stack["Details"].append("ASP.NET detected from X-AspNet-Version header.")
    elif "Python" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "Python"
        tech_stack["Details"].append("Python detected from X-Powered-By header.")
    elif "Ruby" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "Ruby"
        tech_stack["Details"].append("Ruby detected from X-Powered-By header.")
    elif "Java" in response.headers.get("X-Powered-By", ""):
        tech_stack["Technology"] = "Java"
        tech_stack["Details"].append("Java detected from X-Powered-By header.")


    # Detecting JavaScript Frameworks
    if "React" in response.headers.get("X-Framework", ""):
        tech_stack["Technology"] = "React"
        tech_stack["Details"].append("React detected from X-Framework header.")
    elif "Angular" in response.headers.get("X-Framework", ""):
        tech_stack["Technology"] = "Angular"
        tech_stack["Details"].append("Angular detected from X-Framework header.")
    elif "Vue.js" in response.headers.get("X-Framework", ""):
        tech_stack["Technology"] = "Vue.js"
        tech_stack["Details"].append("Vue.js detected from X-Framework header.")
    elif "Ember" in response.headers.get("X-Framework", ""):
        tech_stack["Technology"] = "Ember.js"
        tech_stack["Details"].append("Ember.js detected from X-Framework header.")


    # Detecting CDN Providers
    if "Cloudflare" in response.headers.get("Server", ""):
        tech_stack["Technology"] = "Cloudflare"
        tech_stack["Details"].append("Cloudflare detected from Server header.")
    elif "Amazon CloudFront" in response.headers.get("Via", ""):
        tech_stack["Technology"] = "Amazon CloudFront"
        tech_stack["Details"].append("Amazon CloudFront detected from Via header.")
    elif "Akamai" in response.headers.get("Server", ""):
        tech_stack["Technology"] = "Akamai"
        tech_stack["Details"].append("Akamai detected from Server header.")
    elif "Fastly" in response.headers.get("Via", ""):
        tech_stack["Technology"] = "Fastly"
        tech_stack["Details"].append("Fastly detected from Via header.")


    # Detecting Security Headers
    if "Content-Security-Policy" in response.headers:
        tech_stack["Technology"] = "Content Security Policy"
        tech_stack["Details"].append("Content Security Policy header detected.")
    if "X-XSS-Protection" in response.headers:
        tech_stack["Technology"] = "X-XSS-Protection"
        tech_stack["Details"].append("X-XSS-Protection header detected.")
    if "X-Content-Type-Options" in response.headers:
        tech_stack["Technology"] = "X-Content-Type-Options"
        tech_stack["Details"].append("X-Content-Type-Options header detected.")
    if "Strict-Transport-Security" in response.headers:
        tech_stack["Technology"] = "Strict-Transport-Security"
        tech_stack["Details"].append("Strict-Transport-Security (HSTS) header detected.")
    if "Referrer-Policy" in response.headers:
        tech_stack["Technology"] = "Referrer-Policy"
        tech_stack["Details"].append("Referrer-Policy header detected.")
    if "X-Frame-Options" in response.headers:
        tech_stack["Technology"] = "X-Frame-Options"
        tech_stack["Details"].append("X-Frame-Options header detected.")

    # Detecting Caching Mechanisms
    if "Cache-Control" in response.headers:
        tech_stack["Technology"] = "Caching"
        tech_stack["Details"].append("Cache-Control header detected.")
    if "Expires" in response.headers:
        tech_stack["Technology"] = "Caching"
        tech_stack["Details"].append("Expires header detected.")
    if "Pragma" in response.headers:
        tech_stack["Technology"] = "Caching"
        tech_stack["Details"].append("Pragma header detected.")


    # Cross-Origin Resource Sharing (CORS)
    if "Access-Control-Allow-Origin" in response.headers:
        tech_stack["Technology"] = "CORS"
        tech_stack["Details"].append("Access-Control-Allow-Origin header detected.")
    if "Access-Control-Allow-Methods" in response.headers:
        tech_stack["Technology"] = "CORS"
        tech_stack["Details"].append("Access-Control-Allow-Methods header detected.")
    if "Access-Control-Allow-Headers" in response.headers:
        tech_stack["Technology"] = "CORS"
        tech_stack["Details"].append("Access-Control-Allow-Headers header detected.")


    # Security-related headers
    if "Cross-Origin-Opener-Policy" in response.headers:
        tech_stack["Technology"] = "Cross-Origin-Opener-Policy (COOP)"
        tech_stack["Details"].append("Cross-Origin-Opener-Policy header detected.")
    if "Cross-Origin-Embedder-Policy" in response.headers:
        tech_stack["Technology"] = "Cross-Origin-Embedder-Policy (COEP)"
        tech_stack["Details"].append("Cross-Origin-Embedder-Policy header detected.")
    if "Cross-Origin-Resource-Policy" in response.headers:
        tech_stack["Technology"] = "Cross-Origin-Resource-Policy (CORP)"
        tech_stack["Details"].append("Cross-Origin-Resource-Policy header detected.")
    if "Permissions-Policy" in response.headers:
        tech_stack["Technology"] = "Permissions-Policy"
        tech_stack["Details"].append("Permissions-Policy header detected.")

    # Additional Headers
    if "X-Permitted-Cross-Domain-Policies" in response.headers:
        tech_stack["Technology"] = "Permitted Cross-Domain Policies"
        tech_stack["Details"].append("X-Permitted-Cross-Domain-Policies header detected.")
    if "Public-Key-Pins" in response.headers:
        tech_stack["Technology"] = "Public Key Pinning (HPKP)"
        tech_stack["Details"].append("Public-Key-Pins header detected.")
    if "X-Content-Duration" in response.headers:
        tech_stack["Technology"] = "Content Duration"
        tech_stack["Details"].append("X-Content-Duration header detected.")
    if "X-Download-Options" in response.headers:
        tech_stack["Technology"] = "X-Download-Options"
        tech_stack["Details"].append("X-Download-Options header detected.")
    if "X-Content-Security-Policy" in response.headers:
        tech_stack["Technology"] = "X-Content-Security-Policy"
        tech_stack["Details"].append("X-Content-Security-Policy header detected.")
    if "X-Frame-Options" in response.headers:
        tech_stack["Technology"] = "X-Frame-Options"
        tech_stack["Details"].append("X-Frame-Options header detected.")

    return tech_stack

def generate_pdf_report(url, header_info, tech_stack):
    # Set up Jinja2 environment
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('report.html')

    # Render the template with data
    html_content = template.render(url=url, header_info=header_info, tech_stack=tech_stack)

    # Generate PDF from HTML content
    pdf = HTML(string=html_content).write_pdf()

    # Save the PDF
    with open(f'report_{url.replace("https://", "").replace("http://", "").replace("/", "_")}.pdf', 'wb') as f:
        f.write(pdf)


if __name__ == "__main__":
    url = "http://192.168.0.156"
    check_security_headers(url)

