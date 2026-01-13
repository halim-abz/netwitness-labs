# Context Menu Actions 🖱️

This directory contains configuration files for custom **Context Menu Actions** (Right-click actions) in the NetWitness **Investigate** and **Respond** views.

## 📖 What are Context Menu Actions?
These actions allow an analyst to right-click on a value (like an `ip.src`, `user.dst`, or `filename`) and immediately use it to query an external system.

**Common Use Cases:**
* **Threat Intel:** Right-click an IP -> Open VirusTotal / Cisco Talos.
* **Internal Tools:** Right-click a User -> Search in internal system.
* **Geoloc:** Right-click a City -> Open Google Maps.

## 📂 File Format
We typically share these as **JSON** exports containing:
1.  **Display Name:** What the analyst sees (e.g., "Search on VirusTotal").
2.  **cssClasses (Meta Key):** When this action should appear (e.g., only on `ip.src` or `ip.dst`).
3.  **URL Format:** The destination URL (e.g., `https://www.virustotal.com/gui/ip-address/{{value}}`).

---

## 📥 How to Install

1.  Open the text file of the specific action you want to add.
2.  Log in to **NetWitness**.
3.  Navigate to **Admin** > **System** > **Context Menu Actions**.
4.  Click **Add** (+).
5.  Click on **Switch to Advanced View**
6.  Paste the content of the text file.
7.  Click **Save** and refresh your Investigate view.

---

## ⚠️ Security & Privacy Warning

**Be careful where you send data.**
When you configure a Context Menu Action to an external site (like `google.com` or `virustotal.com`), the value (IP, User, Host) is sent over the internet in the URL.

* **Do not** create actions that send internal PII (Personally Identifiable Information) to public websites.
* **Do not** use HTTP (non-secure) URLs; always ensure the destination is **HTTPS**.

---

## 📂 Conext Menu Actions

| Name | Description |
| :--- | :--- |
| **[`Talos`](talos.json/)** | Query IPs and Domains on Cisco Talos |
| **[`Shodan`](shodan.json/)** | Query IPs on Shodan |
| **[`VirusTotal_IP`](virustotal_ip.json/)** | Query IPs on VirusTotal |
| **[`VirusTotal_Host`](virustotal_host.json/)** | Query Domains on VirusTotal |
