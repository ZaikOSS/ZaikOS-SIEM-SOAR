# 🛡️ ZaikOS: Advanced SIEM + SOAR Automated Defense Pipeline

![ZaikOS Dashboard Preview](images/dashboard-main.png.png)

**ZaikOS** is an end-to-end Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) architecture. Built from the ground up, this project bridges the gap between offensive security tactics and active defensive engineering. 

It autonomously detects network attacks, enriches threat data using global intelligence APIs, permanently blocks malicious actors at the firewall level in milliseconds, and streams the entire process live to a custom cyberpunk-styled SOC dashboard.

---

## 📑 Table of Contents
* [Project Overview](#-project-overview)
* [Key Features](#-key-features)
* [Architecture & Workflow](#-architecture--workflow)
* [Technology Stack](#-technology-stack)
* [Deep Dive: System Configurations](#-deep-dive-system-configurations)
* [Installation & Deployment](#️-installation--deployment)
* [Environment Variables](#-environment-variables)
* [About the Developer](#-about-the-developer)

---

## 🔎 Project Overview
Modern Security Operations Centers (SOCs) suffer from alert fatigue. ZaikOS was built to solve this by automating the triage and response phases of the incident lifecycle. 

Instead of a human analyst manually checking an IP address against threat databases and logging into a server to ban them, ZaikOS handles the entire pipeline — from detection to remediation — in under 2 seconds.

---

## ✨ Key Features

* **Real-Time Log Ingestion:** Wazuh agent continuously monitors `/var/log/auth.log` and Apache error logs for brute-force and SQL injection attempts.
* **Fault-Tolerant Webhooks:** A custom Python integration script inside Wazuh securely queues and forwards Level 10+ alerts to the backend.
* **Automated Threat Intelligence:** Instantly queries **VirusTotal** (70+ vendors) and **AbuseIPDB** to calculate a confidence score on the attacking IP.
* **Active Automated Response (SOAR):** Utilizes `paramiko` to establish a background SSH connection to the victim machine and dynamically writes `ufw deny` firewall rules to drop the attacker.
* **Live WebSocket Streaming:** A Node.js backend pushes threat verdicts to the frontend in real-time via `Socket.io`.
* **Cyberpunk SOC Dashboard:** A React.js frontend featuring animated terminal output, live threat timeline graphs, and system health monitoring.

---

## 🏗️ Architecture & Workflow

![Architecture Diagram](images/architecture.png)

ZaikOS operates in a 6-stage lifecycle:

### 1️⃣ The Target (Endpoint)
A Linux VM running Custom SSH (Port 2222) and an Apache Web Server. This is the designated attack surface.

### 2️⃣ The SIEM (Wazuh)
The Wazuh Manager detects anomalous behavior (such as `sshd: maximum authentication attempts exceeded`) and triggers a critical alert.
![Wazuh Alerts](images/wazuh.png)

### 3️⃣ The Orchestrator
The custom script catches the alert directly within the Wazuh framework and POSTs the JSON payload to the Node.js API.

### 4️⃣ The Brain (Backend Engine)
Node.js receives the webhook and executes the analyzer engine.

### 5️⃣ Threat Intelligence & Execution
The Python engine cross-references the IP with VirusTotal and AbuseIPDB.
If the risk level is **High** or **Critical**, it SSHs into the Target VM and executes:
`sudo ufw deny from <IP>`

### 6️⃣ The SOC Dashboard
Analysts can watch the attack detection, API intelligence queries, and the firewall block—all happening live on the React dashboard.

---

## 💻 Technology Stack

### 🛡️ Defensive & Systems
* **Wazuh** – SIEM, log analysis, file integrity monitoring
* **Linux UFW** – Automated firewall blocking
* **Paramiko** – Python SSHv2 protocol library

### ⚙️ Backend (SOAR & API)
* **Node.js & Express.js** – Webhook listener and REST API
* **Python 3** – Threat analysis & execution scripts
* **Socket.io** – Bi-directional WebSocket communication
* **Requests** – API querying with exponential backoff

### 🎨 Frontend (Visibility)
* **React.js** – Component-based UI
* **CSS3** – Custom CRT scanline effects, dark-mode styling

---

## 🔬 Deep Dive: System Configurations

### 1️⃣ Wazuh Integration (`ossec.conf`)
To bridge the SIEM with the custom SOAR backend, configure the Wazuh Manager to forward high-severity alerts (Level 10+):

```xml
<ossec_config>
  <integration>
    <name>custom-soar</name>
    <hook_url>http://<BACKEND_IP>:3000/wazuh-alert</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
