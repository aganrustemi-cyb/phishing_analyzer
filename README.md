

# PhishGuard — Phishing Email Analyzer (SOC Automation Tool)

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20App-black)
![Threat Intelligence](https://img.shields.io/badge/Threat%20Intel-VirusTotal%20%7C%20AbuseIPDB-orange)
![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Deployment](https://img.shields.io/badge/Deployed-PythonAnywhere-green)

---

# 🎯 Purpose of This Project

**PhishGuard** is a SOC-focused phishing investigation automation tool designed to replicate the **workflow used by Tier 1 and Tier 2 security analysts** during phishing incident triage.

The system parses `.eml` email files and automatically performs **indicator extraction, threat intelligence enrichment, MITRE ATT&CK mapping, and SOC report generation**.

This project demonstrates hands-on experience with:

* phishing analysis
* threat intelligence enrichment
* SOC investigation workflows
* security automation
* Python security tooling
* cloud deployment

The goal is to **reduce manual investigation time** and simulate how phishing alerts are handled in real-world Security Operations Centers.

---

# 🌐 Live Demo

Web application deployed on **PythonAnywhere**

```
https://agancyber.pythonanywhere.com
```

The tool can analyze `.eml` phishing emails directly through the browser.

---


# 🏗 Architecture Overview

```
              Email (.eml)
                   │
                   ▼
            Indicator Extraction
       (headers, IPs, URLs, attachments)
                   │
                   ▼
        Threat Intelligence Enrichment
      ┌───────────────┬───────────────┬───────────────┐
      │ VirusTotal    │ AbuseIPDB     │ Shodan        │
      │ URL/IP/File   │ IP reputation │ Infra intel   │
      └───────────────┴───────────────┴───────────────┘
                   │
                   ▼
             YARA Rule Scanning
                   │
                   ▼
           MITRE ATT&CK Mapping
                   │
                   ▼
         Automated SOC Incident Report
                   │
                   ▼
             Web UI (Flask)
                   │
                   ▼
           PythonAnywhere Deployment
```

---

# 🔎 Features

## Email Header Analysis

Extracts and analyzes:

* Sender
* Recipient
* Reply-To address
* Message ID
* Mailer
* SPF authentication
* DKIM authentication
* DMARC authentication

Security detections include:

* Reply-To spoofing
* Authentication failures
* Header anomalies

These signals contribute to the **overall threat confidence score**.

---

# 🌍 IP Threat Intelligence

IPs extracted from `Received` headers are analyzed using:

* **VirusTotal**
* **AbuseIPDB**
* **Shodan**

Data collected includes:

* malicious detections
* suspicious detections
* ASN ownership
* geolocation
* ISP information
* abuse confidence score
* exposed services
* open ports
* CVE vulnerabilities

This provides infrastructure intelligence around phishing campaigns.

---

# 🔗 URL Analysis

URLs embedded inside emails are analyzed through:

**VirusTotal URL reputation scanning**

Checks include:

* malicious detections
* suspicious detections
* phishing category tags
* URL shortener detection

Shortened URLs are flagged as a **phishing evasion technique**.

---

# 📎 Attachment Analysis

Attachments are inspected for:

* file type
* file size
* MD5 hash
* SHA256 hash

Security checks include:

* suspicious file extensions
* VirusTotal hash lookup
* **YARA rule scanning**

This replicates how SOC teams analyze potentially malicious email attachments.

---

# 🧠 MITRE ATT&CK Mapping

Indicators are mapped to MITRE ATT&CK techniques to provide structured threat intelligence context.

Examples include:

| Technique | Description                 |
| --------- | --------------------------- |
| T1566.001 | Spearphishing Attachment    |
| T1566.002 | Spearphishing Link          |
| T1566.003 | Phishing via Email Spoofing |
| T1656     | Impersonation               |

This allows analysts to quickly understand **attacker tactics and techniques**.

---

# 📄 Automated SOC Report Generation

After analysis completes, the system automatically generates a **SOC-style investigation report** including:

* investigation summary
* indicator findings
* threat intelligence results
* MITRE ATT&CK techniques
* threat verdict
* confidence score

Reports can be downloaded and attached to **SIEM alerts or ticketing systems**.

---

# 📦 Batch Email Analysis

Multiple phishing emails can be analyzed simultaneously.

Batch processing allows analysts to:

* triage phishing campaigns
* identify shared indicators
* compare verdicts across emails

This simulates **large-scale phishing investigations** handled by SOC teams.

---

# 🖥 Web Interface

The analyzer includes a **Flask-based investigation console** for uploading and analyzing phishing emails.

Features include:

* drag & drop `.eml` upload
* batch email processing
* interactive investigation results
* threat verdict scoring
* expandable investigation panels
* downloadable SOC reports

The interface renders dynamic analysis results using Jinja templates. 

The UI acts as a lightweight **SOC phishing investigation dashboard**. 

---

# ☁️ Deployment

The application is deployed on **PythonAnywhere**, demonstrating experience with:

* Flask web applications
* WSGI configuration
* cloud hosting
* security tooling deployment

This transforms the analyzer from a **local script into a usable web-based security tool**.

---

# 🧰 Technology Stack

### Backend

* Python
* Flask
* Requests
* YARA

### Threat Intelligence APIs

* VirusTotal
* AbuseIPDB
* Shodan
* Groq AI

### Frontend

* HTML
* TailwindCSS
* Jinja2 templates

### Deployment

* PythonAnywhere
* WSGI

---

# 📂 Project Structure

```
phishing_analyzer/
│
├── app.py
├── phishing_analyzer.py
│
├── templates/
│   ├── index.html
│   ├── results.html
│   ├── batch_results.html
│   └── settings.html
│
├── rules/
│   └── phishing_basic.yar
│
├── requirements.txt
└── README.md
```

---

# 🧪 Example SOC Workflow

Typical analyst workflow:

1. Receive phishing alert from SIEM or email gateway
2. Export suspicious email as `.eml`
3. Upload email to PhishGuard
4. Tool extracts indicators automatically
5. Indicators enriched via threat intelligence APIs
6. MITRE ATT&CK techniques mapped
7. SOC investigation report generated

This reduces manual investigation steps typically required during **phishing incident triage**.

---

# 🖼 Screenshots


### Upload Console and Investigation Dashbord

![brave_dcktXbKhQB](https://github.com/user-attachments/assets/15a1da2f-3396-41be-858d-ee1f9d54ec6e)


### Api Configuration 

![brave_NktOyqQmhv](https://github.com/user-attachments/assets/d4f688c1-5544-431a-b022-2ab670fd7519)


### Threat Intelligence Results

![sublime_text_zlEWlrc2nD](https://github.com/user-attachments/assets/7b6cfc3c-ae09-4448-9323-c3aaebb9290d)


---

🚀 Setup & Usage (Local CLI)

This tool runs locally as a standalone SOC phishing triage utility. It analyzes exported .eml emails, enriches indicators with threat intelligence, maps findings to MITRE ATT&CK, and generates a SOC incident report.

1. Clone the repo
git clone https://github.com/yourusername/phishing-analyzer.git
cd phishing-analyzer
2. Install dependencies

Minimum required (for IP/URL enrichment and report generation):

pip install requests

Recommended (full feature set):

pip install requests shodan yara-python

✅ Optional integrations (tool still works without these):

shodan → adds infrastructure intelligence (ports, org, CVEs)

yara-python → scans attachments using rules/*.yar

🔑 Configuration (API Keys)

The script uses these API keys (free tiers available):

VirusTotal → IP, URL, and file hash lookups

AbuseIPDB → IP reputation scoring

Groq → auto-generates the SOC incident report (LLaMA 3.1)

Shodan (optional) → host intelligence and CVE visibility

Open phishing_analyzer.py and set the config section:

VT_API_KEY    = ""  # free at virustotal.com
ABUSEIPDB_KEY = ""  # free at abuseipdb.com
GROQ_KEY      = ""  # free at console.groq.com
SHODAN_KEY    = ""  # free at shodan.io → My Account
What happens if keys/modules are missing?

If Shodan is not installed or no key is configured → Shodan lookups are skipped automatically

If YARA is not installed or no rules exist → YARA scanning is skipped automatically

If Groq key is missing/invalid → triage still runs, but report generation fails at the final stage

---

# 🧑‍💻 Author

**Agan Rustemi**
SOC Analyst | Cybersecurity Enthusiast
Skopje, North Macedonia (Open to Remote Roles)

This project demonstrates practical experience with:

* SOC investigation workflows
* phishing analysis
* threat intelligence enrichment
* MITRE ATT&CK mapping
* security automation
* Python security tooling
* cloud deployment

GitHub:

```
https://github.com/aganrustemi-cyb
```

---

# ⚠ Disclaimer

This project is intended for **educational and security research purposes only**.

---

## 💡 Portfolio Note

This project was built as part of a **SOC Analyst portfolio lab** to demonstrate hands-on investigation skills and security automation capabilities.

---


