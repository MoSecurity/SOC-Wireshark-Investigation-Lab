# 🔎 SOC Wireshark Network Investigation Lab

> Hands-on network traffic investigation using Wireshark to identify reconnaissance, suspicious DNS activity, and C2-like HTTP communication.

![Wireshark](https://img.shields.io/badge/Wireshark-Network%20Analysis-blue?logo=wireshark)
![SOC](https://img.shields.io/badge/SOC-Analyst-red)
![Blue Team](https://img.shields.io/badge/Blue%20Team-Defensive%20Security-darkblue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

## 🎯 Project Overview

This project demonstrates a practical SOC-style network investigation using **Wireshark**.

The objective was to analyse packet captures, identify abnormal network behaviour, extract Indicators of Compromise (IOCs), reconstruct suspicious communications, map findings to **MITRE ATT&CK**, and produce evidence-based security assessments.

The investigation covers three different scenarios:

| Scenario | Investigation | Result |
|---|---|---|
| 🔴 Scenario A | TCP Port Scan | Network Service Scanning |
| 🟠 Scenario B | Suspicious DNS / Remote Shell | Command Shell over TCP/53 |
| 🔴 Scenario C | Possible C2 | C2-like HTTP Beaconing |

---

# 🧪 Investigation Workflow

```text
                    PCAP
                     │
                     ▼
              Traffic Analysis
                     │
                     ▼
             Identify Anomalies
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Port Scan   DNS/Shell    C2-like HTTP
          │          │          │
          └──────────┼──────────┘
                     ▼
                IOC Extraction
                     │
                     ▼
             Threat Intelligence
                     │
                     ▼
              MITRE ATT&CK
                     │
                     ▼
             Security Assessment
                     │
                     ▼
               SOC Response
