# [Rule Name]

**Author:** [Name]
**Date:** [YYYY-MM-DD]
**Severity:** [Low / Medium / High / Critical]
**Status:** [Experimental / Tested / Stable]

---

## 🔍 Description
*Provide a summary of what this rule detects.*


### 🛡️ MITRE ATT&CK Mapping
* **Tactic:** [e.g., TA0008 - Lateral Movement]
* **Technique:** [e.g., T1570 - Lateral Tool Transfer]
* **Sub-Technique:** [e.g., T1021.002 - SMB/Windows Admin Shares]

---

## ⚙️ Technical Logic & Syntax

### Requirements
Ensure the following is available:
* [eg., Traffic needed]
* [eg., meta keys needed]

### Rule Syntax (EPL / Rule Builder)

```sql
[EPL Syntax]
```

---

## ⚠️ Tuning & False Positives
### Potential False Positives:
* **Admin Scripts:** System administrators often use for legitimate software deployment.
* **Vulnerability Scanners:** Scanners like Nessus may simulate this behavior.

### Recommended Tuning:
* Whitelist the source IP addresses of known vulnerability scanners: `AND ip.src NOT IN ( '10.10.10.5', '192.168.1.50' )`

---

## 🧪 Testing Validation
### Steps to trigger this rule:
1. On a test machine, download `[sample tool]`.
2. Run the command: `[sample command]`
3. Verify that NetWitness Network sees the traffic.
4. Check the Alerts panel for the alert name defined above.

---

## 📎 Files Included
* `[rule_name].esaa`: The importable definition for NetWitness ESA.
* `test-sample.pcap`: Sample PCAP to verify parsing.
