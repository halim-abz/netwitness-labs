# Attachment with Macro Enabled Office Document

**Author:** Halim Abouzeid
**Date:** 2025-09-26
**Severity:** High
**Status:** Tested

---

## 🔍 Description
Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution.
Adversaries may attach Macro enabled office documents, which would allow to execute code on the victim's machine once opened.
This rule detects when an attachment includes a macro-enabled file extension.

### 🛡️ MITRE ATT&CK Mapping
* **Tactic:** TA0001 - Initial Access
* **Technique:** T1566 - Phishing
* **Sub-Technique:** T1566.001 - Spearphishing Attachment

---

## ⚙️ Technical Logic & Syntax

### Requirements
Ensure the following is available:
* Mail traffic

**IMPORTANT:** The below can be a breaking change if you have other ESA rules that do not expect the "filename" meta key to be an array. Make sure to update other ESA rules you may have that do not consider "filename" as an array.

For better accuracy, you can change the Meta Key Type for `filename` from `string` to `String[]`:
1. Go to Admin > Services ESA Correlation > Explore
2. Click on correlation > stream
3. Under "multi-valued" add `,filename` to the end of the list
4. Navigate to Config > ESA Rules > Settings > Meta Key References
5. Click on the red "Re-Sync" button (circular arrows)
6- Verify that "filename" now shows as type "string[]"

### Rule Syntax (EPL / Rule Builder)

```sql
@Name('Module_esa000261_Alert')
@RSAAlert(oneInSeconds=0, identifiers={"ip_src","attachment"})

SELECT * FROM 
	Event(
		attachment IS NOT NULL
		AND (
			asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%docm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%dotm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%xlm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%xlsm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%xltm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%xlam'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%pptm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%potm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%ppsm'))
			OR asStringArray(attachment).anyOf(v => v.toLowerCase() LIKE ('%sldm'))
		)
	).std:unique(ip_src) group by ip_src output first every 30 min;
```
