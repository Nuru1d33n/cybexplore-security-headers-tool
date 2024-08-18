# CybExplore Security Headers Tool

![CybExplore Logo](assets/cybexplore-logo.png)

CybExplore Security Headers Tool is a command-line application designed to analyze the HTTP security headers of any given website. This tool checks for missing or improperly configured security headers that could potentially expose the site to vulnerabilities. It also generates detailed reports in PDF format, summarizing the findings and providing recommendations for improving security.

## Features

- **HTTP Headers Analysis**: Scans the security headers of a website to check for vulnerabilities.
- **Report Generation**: Automatically generates a comprehensive PDF report that details the findings.
- **User-Friendly**: Simple and easy to use from the command line.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Report Generation](#report-generation)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Python 3.6 or later
- `pip` (Python package installer)

### Setup

1. Clone the repository:

   ```bash
   git clone git@github.com:Nuru1d33n/cybexplore-security-headers-tool.git
   ```
2. Navigate to the project directory:

   ```bash
   cd cybexplore-security-headers-tool
   ```
3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To analyze a website's security headers, simply run the tool with the following command:

```bash
python security_headers_tool.py --url https://example.com
```


## Generating PDF Report

To generate a PDF report of the analysis, use the `--report` flag:

```
python security_headers_tool.py --url https://example.com --report
```

The report will be saved as `security_report.pdf` in the current directory.


## Example Output

When you run the tool, you can expect output like this:


Analyzing security headers for https://example.com...

Missing Headers:

- Strict-Transport-Security: Enforces secure connections (HTTPS).
- X-Frame-Options: Prevents clickjacking attacks.

Present Headers:

- Content-Security-Policy: default-src 'self';
- X-Content-Type-Options: nosniff

PDF report generated: security_report.pdf

## Report Generation

The PDF report includes:

* A list of all present security headers with their values.
* A list of missing headers along with explanations of potential risks.
* Recommendations for securing the website.

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please fork the repository and submit a pull request. Ensure that your changes include appropriate tests and documentation.

## License

This project is licensed under the MIT License. See the [LICENSE]() file for details.

## Contact

For more information or support, please contact:

* **Name** : Nurudeen Oluwaseun Adebileje
* **Email** : [Nuruadebileje@gmail.com]()
* **Website** : [CybExplore](https://cybexplore.org)
