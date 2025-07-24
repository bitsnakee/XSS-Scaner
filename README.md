# Xss-Scaner
XSSHunterUltimate: Powerful XSS Scanning Tool
The XSSHunterUltimate script is an advanced Python scanner for detecting Cross-Site Scripting (XSS) vulnerabilities in websites. The tool automatically finds XSS vulnerabilities, attempts to bypass Web Application Firewalls (WAFs), and verifies the discovered vulnerabilities with high accuracy to avoid false positives.
Key Features:
* Intelligent Payload Injection: Uses a diverse list of XSS payloads and can modify them to bypass WAFs (such as URL encoding, character swapping, etc.).
* WAF Detection: Attempts to detect the presence of web firewalls to enable bypass techniques if necessary.
* Detailed Response Analysis: Carefully examines server responses to find payload reflections and signs of its execution.
* Automatic Verification: After finding a potential vulnerability, it performs several verification tests to ensure that it is exploitable.
* Comprehensive Reporting: Saves results in both JSON (full report) and TXT (only verified vulnerabilities) formats.
Purpose:
The main purpose of this tool is to help developers and security professionals find and fix XSS vulnerabilities that can lead to data theft, session hijacking, and malicious code execution in users’ browsers.
In simple terms, this script helps you find out if a website is vulnerable to XSS attacks by injecting malicious code into a website and examining its response, and even provides you with the exact exploitable URL.
# Dependencies
```
sudo apt update
```
```
sudo apt install python3
```
```
sudo apt install python3-pip
```
```
pip install requests beautifulsoup4 colorama
```
```
sudo apt install git
```
# Installation
```
git clone https://github.com/bitsnakee/Proxy.git
```
# Usage
```
cd Proxy
```
```
python3 proxy.py
```
![IMG_4940](https://github.com/bitsnakee/XSS-Scaner/blob/main/image/xss.png)
