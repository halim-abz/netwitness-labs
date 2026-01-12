# Application Rules (App Rules) 📏

This directory contains custom **Application Rules** (App Rules) for NetWitness Decoders.

## 📖 What are App Rules?
Application Rules are lightweight enrichment and detection logics that sit on the Decoder (Logs or Network). They generate new **Metadata** based on specific criteria and logics within a single session or log.

---

## 📥 How to Import App Rules (.nwr)

Since these are "Labs" rules, they are not available in NetWitness Live. You must import them manually into your Decoder.

### Prerequisites
* You must have **Administrator** access to the NetWitness UI.
* You need the `.nwr` file downloaded from this directory.

### Step-by-Step Import Guide

1.  **Download** the `.nwr` file from this repository to your local machine.
2.  Log in to the **NetWitness Platform**.
3.  Navigate to **Config** > **Policies**.
4.  Under **Content Library** select the **Application Rule** tab.
5.  Click on **Import**.
6.  Browse and select your `.nwr` file.
7.  **Important:** Once imported, the rule is not active, it must be added to a policy and get deployed.
