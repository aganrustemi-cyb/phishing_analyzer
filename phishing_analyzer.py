#!/usr/bin/env python3
"""
============================================================
  PHISHING EMAIL ANALYZER — SOC Tier 1 Automation Tool
  Author: SOC Analyst Portfolio Project
  Description: Full triage pipeline for phishing alerts.
               Parses .eml files, checks IPs/URLs/hashes
               against VirusTotal & AbuseIPDB, maps findings
               to MITRE ATT&CK, and auto-generates a SOC
               incident report via Claude AI.
============================================================
"""

import email
import re
import json
import hashlib
import base64
import requests
import os
import time
import glob
from datetime import datetime, timezone

try:
    import shodan
except ImportError:
    shodan = None

try:
    import yara
except ImportError:
    yara = None

# ─────────────────────────────────────────────
#  CONFIG — replace with your actual API keys
# ─────────────────────────────────────────────
VT_API_KEY       = ""  # free at virustotal.com
ABUSEIPDB_KEY    = ""  # free at abuseipdb.com
GROQ_KEY         = ""  # free at console.groq.com
SHODAN_KEY       = ""  # free at shodan.io → My Account

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".vbs", ".js", ".bat", ".ps1", ".cmd",
    ".scr", ".hta", ".jar", ".msi", ".dll", ".lnk",
    ".iso", ".img", ".docm", ".xlsm", ".pptm"
]


VT_HEADERS      = {"x-apikey": VT_API_KEY}
ABUSE_HEADERS   = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}


def refresh_headers():
    """Rebuild request headers after API keys are updated."""
    global VT_HEADERS, ABUSE_HEADERS
    VT_HEADERS["x-apikey"] = VT_API_KEY
    ABUSE_HEADERS["Key"] = ABUSEIPDB_KEY

# ─────────────────────────────────────────────
#  FINDINGS COLLECTOR  (used for report + MITRE)
# ─────────────────────────────────────────────
findings = {
    "email_meta": {},
    "ips": [],
    "urls": [],
    "attachments": [],
    "mitre_techniques": [],
    "verdict": "CLEAN",       # CLEAN / SUSPICIOUS / MALICIOUS
    "confidence": 0,          # 0-100
}


# ═══════════════════════════════════════════════
#  1. EMAIL PARSER
# ═══════════════════════════════════════════════

def parse_eml(filepath):
    print(banner("PARSING EMAIL"))
    with open(filepath, "r", errors="ignore") as f:
        msg = email.message_from_file(f)

    meta = {
        "from":       msg.get("From", "N/A"),
        "to":         msg.get("To", "N/A"),
        "reply_to":   msg.get("Reply-To", "N/A"),
        "subject":    msg.get("Subject", "N/A"),
        "date":       msg.get("Date", "N/A"),
        "message_id": msg.get("Message-ID", "N/A"),
        "x_mailer":   msg.get("X-Mailer", "N/A"),
        "spf":        extract_auth_result(msg, "spf"),
        "dkim":       extract_auth_result(msg, "dkim"),
        "dmarc":      extract_auth_result(msg, "dmarc"),
    }
    findings["email_meta"] = meta

    print(f"  From       : {meta['from']}")
    print(f"  To         : {meta['to']}")
    print(f"  Reply-To   : {meta['reply_to']}")
    print(f"  Subject    : {meta['subject']}")
    print(f"  Date       : {meta['date']}")
    print(f"  SPF        : {meta['spf']}")
    print(f"  DKIM       : {meta['dkim']}")
    print(f"  DMARC      : {meta['dmarc']}")

    # Flag reply-to mismatch (common phishing indicator)
    from_addr  = extract_email_address(meta["from"])
    reply_addr = extract_email_address(meta["reply_to"])
    if reply_addr and reply_addr != "N/A" and from_addr != reply_addr:
        flag("Reply-To mismatch detected", f"{from_addr} → {reply_addr}")
        update_confidence(20)

    # Auth failures
    if "fail" in meta["spf"].lower():
        flag("SPF FAIL")
        update_confidence(25)
    if "fail" in meta["dkim"].lower():
        flag("DKIM FAIL")
        update_confidence(25)
    if "fail" in meta["dmarc"].lower():
        flag("DMARC FAIL")
        update_confidence(20)

    # Extract IPs from Received headers
    print(banner("EXTRACTING IPs"))
    received_headers = msg.get_all("Received", [])
    seen_ips = set()
    for header in received_headers:
        found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
        for ip in found:
            if ip not in seen_ips and not ip.startswith(("10.", "192.168.", "172.")):
                seen_ips.add(ip)
                check_ip(ip)

    # Extract URLs from body
    print(banner("EXTRACTING URLs"))
    body = extract_body(msg)
    urls = list(set(re.findall(r'https?://[^\s"<>\]]+', body)))
    for url in urls:
        check_url(url)

    # Check for URL shorteners
    shorteners = ["bit.ly", "tinyurl", "t.co", "ow.ly", "goo.gl", "rebrand.ly"]
    for url in urls:
        if any(s in url for s in shorteners):
            flag(f"URL shortener detected: {url}")
            update_confidence(15)

    # Attachments
    print(banner("CHECKING ATTACHMENTS"))
    check_attachments(msg)

    return msg


# ═══════════════════════════════════════════════
#  2. IP ANALYSIS — VirusTotal + AbuseIPDB
# ═══════════════════════════════════════════════

def check_ip(ip):
    print(f"\n  [IP] {ip}")
    result = {"ip": ip, "vt": {}, "abuse": {}, "malicious": False}

    # VirusTotal
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=VT_HEADERS, timeout=10
        ).json()
        stats = r["data"]["attributes"]["last_analysis_stats"]
        country = r["data"]["attributes"].get("country", "Unknown")
        asn     = r["data"]["attributes"].get("as_owner", "Unknown")
        result["vt"] = {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "country": country,
            "asn": asn
        }
        print(f"       VT  → Malicious: {stats['malicious']} | Suspicious: {stats['suspicious']} | Country: {country} | ASN: {asn}")
        if stats["malicious"] > 0:
            result["malicious"] = True
            update_confidence(30)
    except Exception as e:
        print(f"       VT  → Error: {e}")

    # AbuseIPDB
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=ABUSE_HEADERS,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10
        ).json()
        data  = r.get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        total = data.get("totalReports", 0)
        isp   = data.get("isp", "Unknown")
        usage = data.get("usageType", "Unknown")
        result["abuse"] = {
            "confidence_score": score,
            "total_reports": total,
            "isp": isp,
            "usage_type": usage
        }
        print(f"       ADB → Abuse Score: {score}/100 | Reports: {total} | ISP: {isp} | Type: {usage}")
        if score > 50:
            result["malicious"] = True
            update_confidence(25)
    except Exception as e:
        print(f"       ADB → Error: {e}")

    # Shodan
    check_ip_shodan(ip, result)

    findings["ips"].append(result)


def check_ip_shodan(ip, result):
    """Query Shodan for open ports, services, vulns, and hostnames."""
    result["shodan"] = {}
    if shodan is None:
        print(f"       SHODAN→ Skipped (shodan library not installed)")
        return
    if SHODAN_KEY == "user_will_fill_this" or not SHODAN_KEY:
        print(f"       SHODAN→ Skipped (no API key configured)")
        return
    try:
        api = shodan.Shodan(SHODAN_KEY)
        host = api.host(ip)
        ports     = host.get('ports', [])
        hostnames = host.get('hostnames', [])
        org       = host.get('org', 'Unknown')
        os_info   = host.get('os', 'Unknown')
        vulns     = list(host.get('vulns', {}).keys()) if host.get('vulns') else []
        result["shodan"] = {
            "ports": ports,
            "hostnames": hostnames,
            "org": org,
            "os": os_info,
            "vulns": vulns
        }
        vulns_str = ", ".join(vulns[:5]) if vulns else "None"
        print(f"       SHODAN→ Ports: {ports} | Org: {org} | CVEs: {vulns_str}")
        if vulns:
            update_confidence(15)
    except shodan.APIError as e:
        print(f"       SHODAN→ {e}")
    except Exception as e:
        print(f"       SHODAN→ Error: {e}")


# ═══════════════════════════════════════════════
#  3. URL ANALYSIS — VirusTotal
# ═══════════════════════════════════════════════

def check_url(url):
    print(f"\n  [URL] {url}")
    result = {"url": url, "vt": {}, "malicious": False}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=VT_HEADERS, timeout=10
        ).json()
        stats    = r["data"]["attributes"]["last_analysis_stats"]
        category = r["data"]["attributes"].get("categories", {})
        result["vt"] = {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "categories": list(category.values())[:2]
        }
        print(f"       VT  → Malicious: {stats['malicious']} | Suspicious: {stats['suspicious']} | Categories: {result['vt']['categories']}")
        if stats["malicious"] > 0:
            result["malicious"] = True
            update_confidence(35)
    except Exception as e:
        print(f"       VT  → Error: {e}")

    findings["urls"].append(result)


# ═══════════════════════════════════════════════
#  4. ATTACHMENT ANALYSIS
# ═══════════════════════════════════════════════

def check_attachments(msg):
    found_any = False
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        found_any = True
        content_type = part.get_content_type()
        payload      = part.get_payload(decode=True) or b""
        size         = len(payload)
        md5          = hashlib.md5(payload).hexdigest()
        sha256       = hashlib.sha256(payload).hexdigest()
        ext          = os.path.splitext(filename)[1].lower()
        suspicious   = ext in SUSPICIOUS_EXTENSIONS

        result = {
            "filename":     filename,
            "content_type": content_type,
            "size_bytes":   size,
            "md5":          md5,
            "sha256":       sha256,
            "suspicious_ext": suspicious,
            "vt": {},
            "malicious": False
        }

        print(f"\n  [ATTACHMENT] {filename}")
        print(f"       Type   : {content_type}")
        print(f"       Size   : {size} bytes")
        print(f"       MD5    : {md5}")
        print(f"       SHA256 : {sha256}")

        if suspicious:
            flag(f"Suspicious extension: {ext}")
            update_confidence(30)

        # VirusTotal hash lookup
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=VT_HEADERS, timeout=10
            ).json()
            stats = r["data"]["attributes"]["last_analysis_stats"]
            names = r["data"]["attributes"].get("meaningful_name", filename)
            result["vt"] = {
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "name": names
            }
            print(f"       VT   → Malicious: {stats['malicious']} | Suspicious: {stats['suspicious']}")
            if stats["malicious"] > 0:
                result["malicious"] = True
                update_confidence(40)
        except Exception:
            print(f"       VT   → Hash not found in VT database (new/unknown file)")

        # YARA rule scanning
        yara_scan_attachment(payload, result)

        findings["attachments"].append(result)

    if not found_any:
        print("  No attachments found.")


def load_yara_rules():
    """Load and compile all .yar files from the rules/ directory."""
    if yara is None:
        return None
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
    if not os.path.isdir(rules_dir):
        return None
    rule_files = glob.glob(os.path.join(rules_dir, "*.yar"))
    if not rule_files:
        return None
    try:
        filepaths = {f'rule_{i}': path for i, path in enumerate(rule_files)}
        compiled = yara.compile(filepaths=filepaths)
        return compiled
    except Exception as e:
        print(f"       YARA → Warning: Failed to compile rules: {e}")
        return None


def yara_scan_attachment(payload, result):
    """Scan attachment bytes against compiled YARA rules."""
    result["yara_matches"] = []
    rules = load_yara_rules()
    if rules is None:
        print(f"       YARA → Skipped (no rules found in rules/ directory)")
        return
    try:
        matches = rules.match(data=payload)
        if matches:
            for m in matches:
                tags = list(m.tags) if m.tags else []
                result["yara_matches"].append({"rule": m.rule, "tags": tags})
                tags_str = f" [tags: {', '.join(tags)}]" if tags else ""
                print(f"       YARA → MATCH: {m.rule}{tags_str}")
            update_confidence(25)
        else:
            print(f"       YARA → No rule matches")
    except Exception as e:
        print(f"       YARA → Error: {e}")


# ═══════════════════════════════════════════════
#  5. MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════

def map_mitre():
    print(banner("MITRE ATT&CK MAPPING"))
    techniques = []
    meta = findings["email_meta"]
    ips  = findings["ips"]
    urls = findings["urls"]
    atts = findings["attachments"]

    # Phishing
    techniques.append({
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment" if atts else "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "reason": "Email-based phishing attempt detected"
    })

    # Auth failures → spoofing
    if "fail" in meta.get("spf","").lower() or "fail" in meta.get("dmarc","").lower():
        techniques.append({
            "id": "T1566.003",
            "name": "Phishing: Spearphishing via Email Spoofing",
            "tactic": "Initial Access",
            "reason": "SPF/DMARC failure suggests sender spoofing"
        })

    # Reply-to mismatch → impersonation
    from_addr  = extract_email_address(meta.get("from",""))
    reply_addr = extract_email_address(meta.get("reply_to",""))
    if reply_addr and reply_addr != "N/A" and from_addr != reply_addr:
        techniques.append({
            "id": "T1656",
            "name": "Impersonation",
            "tactic": "Defense Evasion",
            "reason": "Reply-To address differs from From address"
        })

    # Malicious URLs → drive-by or credential harvesting
    malicious_urls = [u for u in urls if u.get("malicious")]
    if malicious_urls:
        techniques.append({
            "id": "T1189",
            "name": "Drive-by Compromise",
            "tactic": "Initial Access",
            "reason": f"{len(malicious_urls)} malicious URL(s) detected"
        })
        techniques.append({
            "id": "T1598.003",
            "name": "Phishing for Information: Spearphishing Link",
            "tactic": "Reconnaissance",
            "reason": "Malicious links may lead to credential harvesting pages"
        })

    # Malicious IPs → C2
    malicious_ips = [i for i in ips if i.get("malicious")]
    if malicious_ips:
        techniques.append({
            "id": "T1071.003",
            "name": "Application Layer Protocol: Mail Protocols",
            "tactic": "Command and Control",
            "reason": f"Email originated from {len(malicious_ips)} known malicious IP(s)"
        })

    # Suspicious attachments
    for att in atts:
        ext = os.path.splitext(att["filename"])[1].lower()
        if ext in [".exe", ".msi", ".dll", ".scr"]:
            techniques.append({
                "id": "T1204.002",
                "name": "User Execution: Malicious File",
                "tactic": "Execution",
                "reason": f"Executable attachment: {att['filename']}"
            })
        elif ext in [".docm", ".xlsm", ".pptm"]:
            techniques.append({
                "id": "T1137",
                "name": "Office Application Startup",
                "tactic": "Persistence",
                "reason": f"Macro-enabled Office file: {att['filename']}"
            })
        elif ext in [".vbs", ".js", ".ps1", ".bat", ".cmd", ".hta"]:
            techniques.append({
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "reason": f"Script-based attachment: {att['filename']}"
            })
        elif ext in [".lnk"]:
            techniques.append({
                "id": "T1547.009",
                "name": "Boot or Logon Autostart: Shortcut Modification",
                "tactic": "Persistence",
                "reason": f"LNK shortcut file detected: {att['filename']}"
            })

    # Deduplicate by ID
    seen = set()
    unique = []
    for t in techniques:
        if t["id"] not in seen:
            seen.add(t["id"])
            unique.append(t)

    findings["mitre_techniques"] = unique

    for t in unique:
        print(f"  [{t['tactic']}] {t['id']} — {t['name']}")
        print(f"       Reason: {t['reason']}")

    return unique


# ═══════════════════════════════════════════════
#  6. VERDICT ENGINE
# ═══════════════════════════════════════════════

def determine_verdict():
    score = findings["confidence"]
    if score >= 60:
        findings["verdict"] = "MALICIOUS"
    elif score >= 30:
        findings["verdict"] = "SUSPICIOUS"
    else:
        findings["verdict"] = "CLEAN"

    color = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}
    print(banner("VERDICT"))
    print(f"  {color[findings['verdict']]}  {findings['verdict']}  (Confidence Score: {score}/100)")


# ═══════════════════════════════════════════════
#  7. AUTO-GENERATE SOC INCIDENT REPORT (Claude AI)
# ═══════════════════════════════════════════════

def generate_report():
    print(banner("GENERATING SOC INCIDENT REPORT"))

    prompt = f"""
You are a Tier 2 SOC analyst writing a formal incident report after triaging a phishing email alert.
Write a complete, professional SOC incident report based ONLY on the findings below.

Use this exact structure:
1. INCIDENT SUMMARY
2. AFFECTED USER / RECIPIENT
3. THREAT ACTOR INDICATORS (IPs, URLs, attachments with their VT/AbuseIPDB scores)
4. ATTACK CHAIN ANALYSIS (narrative, not bullet points)
5. MITRE ATT&CK MAPPING (table: Tactic | Technique ID | Technique Name)
6. IMPACT ASSESSMENT
7. CONTAINMENT ACTIONS TAKEN (list realistic Tier 1 actions: blocked sender, submitted IOCs, etc.)
8. RECOMMENDED REMEDIATION
9. ANALYST NOTES
10. DISPOSITION: {findings['verdict']} — escalate to Tier 2: {'YES' if findings['verdict'] == 'MALICIOUS' else 'NO'}

Be specific, concise, and professional. Write as if this is going into a real ticketing system (e.g. ServiceNow/Jira).
Do NOT add any preamble — start directly with the report.

=== TRIAGE FINDINGS ===
FROM: {findings["email_meta"].get("from","N/A")}
TO: {findings["email_meta"].get("to","N/A")}
SUBJECT: {findings["email_meta"].get("subject","N/A")}
SPF: {findings["email_meta"].get("spf","N/A")} | DKIM: {findings["email_meta"].get("dkim","N/A")} | DMARC: {findings["email_meta"].get("dmarc","N/A")}
VERDICT: {findings["verdict"]} (confidence: {findings["confidence"]}/100)
MALICIOUS IPs: {[i["ip"] for i in findings["ips"] if i.get("malicious")]}
SHODAN DATA: {json.dumps([dict(ip=i["ip"], ports=i.get("shodan", {}).get("ports", []), org=i.get("shodan", {}).get("org", "N/A"), vulns=i.get("shodan", {}).get("vulns", [])) for i in findings["ips"] if i.get("shodan")])}
MALICIOUS URLs: {[u["url"] for u in findings["urls"] if u.get("malicious")]}
ATTACHMENTS: {[a["filename"] for a in findings["attachments"]]}
SUSPICIOUS ATTACHMENTS: {[a["filename"] for a in findings["attachments"] if a.get("suspicious_ext") or a.get("malicious")]}
YARA MATCHES: {json.dumps([dict(file=a["filename"], matches=a.get("yara_matches", [])) for a in findings["attachments"] if a.get("yara_matches")])}
MITRE TECHNIQUES: {[(t["id"], t["name"], t["tactic"]) for t in findings["mitre_techniques"]]}
"""

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.1-8b-instant",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30
        )
        r = response.json()
        if "choices" not in r:
            print(f"\n  🔍 DEBUG — Raw Groq response:\n{json.dumps(r, indent=2)}")
            raise Exception(str(r.get("error", {}).get("message", r)))

        # ── Live quota from Groq response headers ──
        h = response.headers
        req_limit     = h.get("x-ratelimit-limit-requests",     "?")
        req_remaining = h.get("x-ratelimit-remaining-requests", "?")
        req_reset     = h.get("x-ratelimit-reset-requests",     "?")
        tok_limit     = h.get("x-ratelimit-limit-tokens",       "?")
        tok_remaining = h.get("x-ratelimit-remaining-tokens",   "?")
        tok_reset     = h.get("x-ratelimit-reset-tokens",       "?")

        print(f"\n  📊 GROQ API QUOTA")
        print(f"     Requests  : {req_remaining}/{req_limit} remaining  (resets in {req_reset})")
        print(f"     Tokens    : {tok_remaining}/{tok_limit} remaining  (resets in {tok_reset})")

        report_text = r["choices"][0]["message"]["content"]

        # Save report
        timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = f"SOC_Report_{timestamp}.txt"
        with open(report_file, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("  SOC INCIDENT REPORT — AUTO-GENERATED\n")
            f.write(f"  Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"  Analyst Tool: Phishing Analyzer v1.0\n")
            f.write("=" * 70 + "\n\n")
            f.write(report_text)
            f.write("\n\n" + "=" * 70 + "\n")
            f.write("  RAW FINDINGS (JSON)\n")
            f.write("=" * 70 + "\n")
            f.write(json.dumps(findings, indent=2))

        print(f"\n{report_text}")
        print(f"\n  ✅ Report saved to: {report_file}")

    except Exception as e:
        print(f"  ❌ Report generation failed: {e}")
        print("  (Check your Groq API key at console.groq.com)")


# ═══════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════

def banner(title):
    return f"\n{'='*55}\n  {title}\n{'='*55}"

def flag(msg, detail=""):
    detail_str = f" ({detail})" if detail else ""
    print(f"  ⚠️  FLAG: {msg}{detail_str}")

def update_confidence(amount):
    findings["confidence"] = min(100, findings["confidence"] + amount)

def extract_email_address(header_val):
    match = re.search(r'[\w.+-]+@[\w-]+\.[a-zA-Z]+', header_val or "")
    return match.group(0) if match else "N/A"

def extract_auth_result(msg, auth_type):
    auth_results = msg.get("Authentication-Results", "") or ""
    pattern = rf'{auth_type}=(\w+)'
    match = re.search(pattern, auth_results, re.IGNORECASE)
    return match.group(1) if match else "not present"

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html") and not part.get_filename():
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
        except Exception:
            pass
    return body


# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python phishing_analyzer.py <path_to_email.eml>")
        sys.exit(1)

    eml_path = sys.argv[1]
    if not os.path.exists(eml_path):
        print(f"Error: File not found: {eml_path}")
        sys.exit(1)

    print("\n" + "=" * 55)
    print("  PHISHING EMAIL ANALYZER — SOC Triage Tool")
    print(f"  Target: {eml_path}")
    print(f"  Time:   {datetime.now(timezone.utc).isoformat()}")
    print("=" * 55)

    parse_eml(eml_path)
    map_mitre()
    determine_verdict()
    generate_report()
