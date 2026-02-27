# 🛡️ ZaikOS: Advanced SIEM + SOAR Automated Defense Pipeline

![ZaikOS Dashboard Preview](images/dashboard-main.png.png)

**ZaikOS** is an end-to-end Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) architecture.

Built from the ground up, this project bridges the gap between offensive security tactics and active defensive engineering.

It autonomously detects network attacks, enriches threat data using global intelligence APIs, permanently blocks malicious actors at the firewall level in milliseconds, and streams the entire process live to a custom cyberpunk-styled SOC dashboard.

---

## 📑 Table of Contents

- [🔎 Project Overview](#-project-overview)
- [✨ Key Features](#-key-features)
- [🏗️ Architecture & Workflow](#️-architecture--workflow)
- [💻 Technology Stack](#-technology-stack)
- [🔬 Deep Dive: System Configurations](#-deep-dive-system-configurations)
- [⚙️ Installation & Deployment](#️-installation--deployment)
- [🔐 Environment Variables](#-environment-variables)
- [👨‍💻 About the Developer](#-about-the-developer)
- [📬 Contact](#-contact)

---

## 🔎 Project Overview

Modern Security Operations Centers (SOCs) suffer from alert fatigue. **ZaikOS** was built to solve this by automating the triage and response phases of the incident lifecycle.

Instead of a human analyst manually:

- Checking an IP address against threat intelligence databases  
- Logging into a server  
- Manually adding firewall rules  

ZaikOS handles the entire pipeline — from detection to remediation — in **under 2 seconds**.

This project demonstrates how offensive security knowledge (attack patterns, brute-force behavior, SQLi detection) can be transformed into automated defensive engineering.

---

## ✨ Key Features

### 🔍 Real-Time Log Ingestion
- Wazuh agent continuously monitors:
  - `/var/log/auth.log`
  - Apache error logs  
- Detects brute-force attempts and SQL injection activity.

### 🔔 Fault-Tolerant Webhooks
- Custom Python integration script inside Wazuh.
- Securely queues and forwards **Level 10+ alerts** to the backend.

### 🌍 Automated Threat Intelligence
- Queries:
  - **VirusTotal** (70+ AV vendors)
  - **AbuseIPDB**
- Calculates a dynamic confidence score for attacker IPs.

### 🚫 Active Automated Response (SOAR)
- Uses `paramiko` to establish SSH connection.
- Dynamically executes:
  ```bash
  sudo ufw deny from <IP>
