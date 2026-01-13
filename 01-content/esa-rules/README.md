# Event Stream Analysis (ESA) Rules ⚡

This directory contains advanced correlation rules for the NetWitness ESA service.

## 📖 What are ESA Rules?
ESA Rules allow you to correlate events across time and different data sources. Unlike App Rules (which look at a single packet/log in isolation), ESA rules look for **patterns**.

---

## 📥 How to Import ESA Rules

Since these rules are not part of the official Live content, you must create or import them manually.

### Method A: Import via UI (Preferred for .esaa files)
1.  Log in to **NetWitness**.
2.  Navigate to **Configure** > **ESA Rules**.
3.  In the "Rules" tab, click the **Tools** icon > **Import**.
4.  Select the `.esaa` file downloaded from this repo.
5.  **Deploy:** Add the rule to a **Policy** to push it to your ESA server.

### Method B: Manual Creation (For EPL text)
1.  Navigate to **Configure** > **ESA Rules**.
2.  Click **Plus (+)** > **Advanced EPL**.
3.  Copy the logic from the text file in this repo.
4.  Save and add the rule to a **Policy** to push it to your ESA server.

---

## ⚠️ Performance & Safety (READ THIS)

**ESA Rules can be resource-intensive.** A single badly written rule can consume a lot of memory on your ESA server.

**Golden Rules for "Labs" Content:**
1.  **Test in Trial Mode:** When you first deploy a new rule, set its status to "Trial" or just monitor the alert output.
2.  **Watch Memory:** Monitor the ESA service memory usage after deploying complex rules.
