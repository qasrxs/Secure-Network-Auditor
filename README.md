# 🛡️ ScopeSecure Network Auditor

## Overview
The **ScopeSecure Network Auditor** is a custom Python-based graphical user interface (GUI) application developed during my Cybersecurity Engineering internship. It is designed to automate internal subnet sweeps, actively check for specific critical vulnerabilities (such as exposed SMB 445 and clear-text HTTP), and dynamically generate executive mitigation reports.

## Features
* **Automated Compliance Auditing:** Parses raw Nmap telemetry to identify open ports and services.
* **Vulnerability Mapping:** Cross-references active services against a built-in knowledge base (CVE/CWE).
* **Executive Reporting:** Generates professional, color-coded mitigation reports ready for IT department review.
* **User-Friendly GUI:** Built with `Tkinter` to allow non-technical staff to execute complex network scans with a single click.

## Technologies Used
* Python 3
* Tkinter (GUI)
* Subprocess (System-level execution)
* Nmap (Network Mapper)
