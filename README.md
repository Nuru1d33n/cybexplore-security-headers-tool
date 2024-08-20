# CybExplore Security Headers Tool

![CybExplore Logo](assets/cybexplore-logo.png)

## Overview

The **CybExplore Security Headers Tool** is a comprehensive, automated web application scanner designed to help developers and security professionals identify security vulnerabilities in web applications. The tool inspects HTTP headers, detects CMSs, scans for open ports, checks SSL/TLS certificates, and much more, ensuring your web application is secure against common vulnerabilities.

## Features

* **HTTP Header Analysis** : Fetches and displays HTTP headers from the target website.
* **Server Information Extraction** : Identifies the server software being used.
* **CMS Detection** : Detects common CMS platforms like WordPress, Joomla, Drupal, Magento, and Shopify.
* **Frontend Framework Detection** : Identifies JavaScript frameworks like React, Angular, Vue.js, and Ember.
* **SSL/TLS Certificate Validation** : Validates SSL/TLS certificates and reports on their validity.
* **Security Headers Check** : Identifies missing or misconfigured security headers that could expose the site to vulnerabilities.
* **Open Ports Scan** : Scans for common open ports on the target server.
* **Exploit and Mitigation Suggestions** : Provides basic suggestions on how to exploit and mitigate detected vulnerabilities.
* **Custom User-Agent Support** : Allows the use of a custom User-Agent string for requests.
* **Result Logging** : Saves scan results to a log file with a timestamp.

## Installation

1. **Clone the repository:**

   ```
   git clone https://github.com/Nuru1d33n/cybexplore-security-headers-tool.git
   cd cybexplore-security-headers-tool
   ```

   1. **Install dependencies:**
      Ensure you have Python 3.x installed on your system. Install the required Python libraries using pip:

      ```
      pip install -r requirements.txt
      ```
2. **Run the script:**
   You can now run the web scraping script:

   ```
   python web_scraper.py --user-agent "YourCustomUserAgent" https://example.com
   ```

## Usage

### Command-Line Arguments

* **Targets** : URL(s) to scan. This can be a single URL or a comma-separated list of URLs.
* **User-Agent** : (Optional) Custom User-Agent string. If not provided, it defaults to `'Mozilla/5.0'`.

### Example

To scan a single website:

```
python web_scraper.py https://example.com
```

To scan multiple websites:

```
python web_scraper.py https://example1.com,https://example2.com

```

To scan websites listed in a file:

```
python web_scraper.py targets.txt
```

### Log File

Scan results are automatically saved to a log file in the format `scan_results_YYYYMMDD_HHMMSS.log`.

## Output

The output includes:

* **HTTP Headers** : Displays all HTTP headers returned by the target server.
* **Server Information** : Shows the server software being used.
* **CMS and Framework Detection** : Lists detected CMS platforms and JavaScript frameworks.
* **SSL/TLS Certificate Information** : Details about the SSL certificate, including validity dates.
* **Security Headers Check** : Lists any missing or misconfigured security headers.
* **Open Ports** : Lists any detected open ports on the server.
* **Exploitation and Mitigation Suggestions** : Provides basic exploitation methods and how to mitigate the vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

If you'd like to contribute to this project, please fork the repository, create a new branch, and submit a pull request. We welcome all contributions that can help improve the functionality and security of this tool.

## Contact

For more information or support, please contact:

* **Name** : Nurudeen Oluwaseun Adebileje
* **Email** : [Nuruadebileje@gmail.com]()
* **Website** : [CybExplore](https://cybexplore.org)
