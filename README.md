# 🔍 Phishing Email Analyzer — SOC Triage Automation Tool

A Python-based CLI tool designed to automate the phishing email triage process that SOC Tier 1 analysts perform manually on every alert. Built as part of my cybersecurity portfolio while studying for CompTIA Security+ and working through the TryHackMe SOC Level 1 path.

---

## 🎯 Why I Built This

During my SOC studies I kept running into the same bottleneck: phishing triage is the most common Tier 1 task, but the process is entirely manual — open the email, copy the IPs, paste them into VirusTotal one by one, check AbuseIPDB, look up URLs, identify the attack technique, then write the incident report. That's 20–40 minutes per alert that could be automated.

This tool compresses that entire workflow into a single command.

---

## ⚙️ What It Does

Given a `.eml` file (a raw exported email), the tool automatically:

- **Parses email headers** — extracts From, To, Reply-To, Message-ID, X-Mailer, and auth results (SPF / DKIM / DMARC)
- **Flags reply-to mismatches** — a common phishing indicator where the reply address differs from the sender
- **Extracts and analyzes all IPs** from `Received:` headers, skipping internal RFC1918 ranges
- **Checks every IP** against VirusTotal (malicious vendor count, country, ASN) and AbuseIPDB (abuse confidence score, ISP, usage type, total reports)
- **Extracts all URLs** from the email body and checks each against VirusTotal
- **Detects URL shorteners** — bit.ly, tinyurl, t.co, etc.
- **Analyzes attachments** — computes MD5 + SHA256 hashes, flags dangerous extensions, and performs VirusTotal hash lookups
- **Maps all findings to MITRE ATT&CK** techniques automatically based on what was detected
- **Generates a complete SOC incident report** using Groq's LLaMA 3.1 API — the same report a Tier 1 analyst would write manually after owning the alert
- **Displays live API quota** after each run so you always know your remaining Groq requests

---

## 🗺️ MITRE ATT&CK Techniques Mapped

The tool automatically identifies and maps relevant techniques based on findings:

| Indicator | Technique ID | Technique Name | Tactic |
| --- | --- | --- | --- |
| Email-based phishing | T1566.001 / T1566.002 | Spearphishing Attachment / Link | Initial Access |
| SPF/DMARC failure | T1566.003 | Email Spoofing | Initial Access |
| Reply-To mismatch | T1656 | Impersonation | Defense Evasion |
| Malicious URLs | T1189 | Drive-by Compromise | Initial Access |
| Malicious IPs | T1071.003 | Application Layer Protocol | Command & Control |
| Executable attachments | T1204.002 | Malicious File Execution | Execution |
| Macro-enabled Office files | T1137 | Office Application Startup | Persistence |
| Script attachments (.vbs/.ps1/.js) | T1059 | Command and Scripting Interpreter | Execution |
| LNK shortcut files | T1547.009 | Shortcut Modification | Persistence |

---

## 📄 Auto-Generated Incident Report

After triage completes, the tool sends all findings to **LLaMA 3.1 via Groq** and generates a professional incident report saved as a timestamped `.txt` file. The report follows the structure used in real SOC environments (ServiceNow / Jira):

```
1. INCIDENT SUMMARY
2. AFFECTED USER / RECIPIENT
3. THREAT ACTOR INDICATORS
4. ATTACK CHAIN ANALYSIS
5. MITRE ATT&CK MAPPING
6. IMPACT ASSESSMENT
7. CONTAINMENT ACTIONS TAKEN
8. RECOMMENDED REMEDIATION
9. ANALYST NOTES
10. DISPOSITION + ESCALATION DECISION
```

---

## 🛠️ Tech Stack

| Component | Tool |
| --- | --- |
| Language | Python 3.8+ |
| IP Reputation | VirusTotal API v3 + AbuseIPDB API v2 |
| URL/Hash Analysis | VirusTotal API v3 |
| Threat Intelligence Framework | MITRE ATT&CK |
| AI Report Generation | Groq API (LLaMA 3.1 8B Instant) |
| Email Parsing | Python `email` stdlib |
| HTTP Requests | `requests` |

---

## 🚀 Setup & Usage

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/phishing-analyzer.git
cd phishing-analyzer
```

### 2. Install dependencies

```bash
pip install requests
```

### 3. Add your API keys

Open `phishing_analyzer.py` and fill in the config section at the top:

```python
VT_API_KEY    = "your_virustotal_key"     # virustotal.com — free
ABUSEIPDB_KEY = "your_abuseipdb_key"      # abuseipdb.com — free
GROQ_KEY      = "your_groq_key"           # console.groq.com — free
```

All three APIs have free tiers — no credit card required.

### 4. Export a suspicious email as .eml

- **Gmail**: Open email → three dots → *Download message*
- **Outlook**: File → Save As → `.eml` format
- **Thunderbird**: Drag email to desktop

### 5. Run the tool

```bash
python phishing_analyzer.py suspicious_email.eml
```

> 💡 **Don't have a test email?** A sample `.eml` file and its expected output are available in the [examples folder](https://github.com/aganrustemi-cyb/phishing_analyzer/tree/main/examples) so you can see the tool in action before using it on real emails.

---

## 📊 Sample Output

```
=======================================================
  PHISHING EMAIL ANALYZER — SOC Triage Tool
  Target: suspicious_email.eml
  Time:   2026-03-03T14:22:11+00:00
=======================================================

=======================================================
  PARSING EMAIL
=======================================================
  From       : "IT Support" <support@ev1l-domain.ru>
  To         : victim@company.com
  Reply-To   : attacker@gmail.com
  Subject    : Urgent: Password Reset Required
  SPF        : fail
  DKIM       : fail
  DMARC      : fail
  ⚠️  FLAG: Reply-To mismatch detected (support@ev1l-domain.ru → attacker@gmail.com)
  ⚠️  FLAG: SPF FAIL
  ⚠️  FLAG: DKIM FAIL

=======================================================
  EXTRACTING IPs
=======================================================
  [IP] 45.33.32.156
       VT  → Malicious: 14 | Suspicious: 3 | Country: RU | ASN: Serverius
       ADB → Abuse Score: 87/100 | Reports: 423 | ISP: Serverius | Type: Hosting

=======================================================
  MITRE ATT&CK MAPPING
=======================================================
  [Initial Access]      T1566.001 — Phishing: Spearphishing Attachment
  [Defense Evasion]     T1656     — Impersonation
  [Command and Control] T1071.003 — Application Layer Protocol: Mail Protocols

=======================================================
  VERDICT
=======================================================
  🔴  MALICIOUS  (Confidence Score: 95/100)

  📊 GROQ API QUOTA
     Requests  : 27/30 remaining  (resets in 43s)
     Tokens    : 13800/14400 remaining  (resets in 43s)

  ✅ Report saved to: SOC_Report_20260303_142214.txt
```

---

## 📁 Project Structure

```
phishing-analyzer/
├── phishing_analyzer.py    # Main tool
├── README.md               # This file
└── samples/
    └── test_email.eml      # Safe sample .eml for testing
```

---

## 🔮 Planned Improvements

- [ ] Add `--batch` flag to process a folder of `.eml` files at once
- [ ] Export report to `.pdf` format
- [ ] Add Shodan lookup for IPs
- [ ] Build a simple web UI with Flask
- [ ] Integrate with TheHive for automated case creation
- [ ] Add YARA rule scanning for attachments

---

## 📚 What I Learned

Building this tool pushed me to go deeper than just studying concepts — I had to understand exactly how phishing attacks work at a technical level to map them correctly to MITRE techniques. Parsing raw email headers, understanding how SPF/DKIM/DMARC authentication failures indicate spoofing, and structuring an incident report the way a real SOC team expects it gave me hands-on exposure to workflows I'll be doing from day one on the job.

---

## 🤝 Acknowledgements

- [MITRE ATT&CK Framework](https://attack.mitre.org/) — technique mapping reference
- [VirusTotal API v3 Docs](https://developers.virustotal.com/reference/overview)
- [AbuseIPDB API Docs](https://docs.abuseipdb.com/)
- [Groq API Docs](https://console.groq.com/docs)
- Claude AI (Anthropic) — assisted with code structure and debugging

---

## ⚠️ Disclaimer

This tool is intended for defensive security research and SOC analyst training only. Only analyze emails you have explicit permission to investigate. Never use against systems you do not own.

---

*Built by a SOC analyst in training | Part of my cybersecurity portfolio*
