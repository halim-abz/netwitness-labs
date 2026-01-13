# Kerberos Account Scanning

**Author:** Halim Abouzeid
**Date:** 2025-09-26
**Severity:** Medium
**Status:** Tested

---

## 🔍 Description
Adversaries may attempt to get a listing of valid accounts on a system. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers. Adversaries may use several methods to enumerate accounts. When attempting to authenticate over Kerberos with a user account that do not exist, the following error is returned: 'kdc err c principal unknown'.
This rule detects when multiple authentication attempts over Kerberos for X number of different usernames that don't exist are seen within Y seconds. This behavior can also be indicative of Credential Stuffing.


### 🛡️ MITRE ATT&CK Mapping
* **Tactic:** TA0007 - Discovery
* **Technique:** T1087 - Account Discovery
* **Sub-Technique:** -

---

## ⚙️ Technical Logic & Syntax

### Requirements
Ensure the following is available:
* Kerberos traffic

### Rule Syntax (EPL / Rule Builder)

```sql
@Hint('reclaim_group_aged=120')
@RSAAlert(oneInSeconds=0)

SELECT window(*) FROM 
	Event(
		medium = 1
		AND	error.toLowerCase() IN ( 'kdc err c principal unknown' )
	).std:groupwin(ip_src).win:time_length_batch(60 seconds, 20).std:unique(ad_username_src) group by ip_src having count(*) >= 10 output first every 30 min;
```

