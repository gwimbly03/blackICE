# BlackICE

Advanced, modular pentesting engine written in Python, a collection of scanners and attack modules with a configurable logger and notification system so far.

---

## Table of Contents

- [Features](#features-what-has-been-implemented-so-far)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Configuration](#configuration)  
- [Usage](#usage)  
  - [Run the program](#1-run-the-program)
- [CVE Database Integration](#cve-database-integration) 
- [Directory layout](#directory-layout)
- [What I delivered in Milestone 2](#what-i-delivered-in-milestone-2)  

---
## Features (What has been implemented so far)

* Modular engine that discovers and runs modules from the modules/ directory.
* Custom logging system that can write logs in JSON or CSV, configurable via YAML.
* Terminal and email notifications summarizing module runs and baseline diffs.

---

## Prerequisites

* Python 3.8 or newer
* `pip` (Python package installer)

---

## Installation

1. Clone the repository (if you haven't already):

```bash
git clone https://github.com/towelie03/blackICE.git
cd blackICE
pip install -r requirements.txt

```
Use a virtual environment to keep dependencies isolated.

---

## Configuration 

Upon first run blackICE will create a logger.yaml, logs folder and baseline folder for configuration purposes.   

```
logging:
  format: 'json' #can be json or csv
  output_dir: 'logs'
  console:
    show_progress: true
    show_log_messages: false
    show_module_start: true
    show_module_completion: true
  file:
    include_timestamp: true
    filename_pattern: 'blackice_scan_{timestamp}'
    max_file_size: 10
    backup_count: 5
  include:
    module_results: true
    error_details: true
    scan_metadata: true
    timing_info: true
  email:
    ## Im using mailtrap for testing
    enabled: true  # can be true or false
    smtp_server: 'example.smpt.com'
    smtp_port: 2525
    sender_email: 'example@blackICE.com'  
    sender_username: 'username' 
    sender_password: 'password'  
    recipient_emails:
      - 'test1@example.com' 
      - 'recipient2@example.com'
    notifications:
      baseline_changes: true
      critical_findings: true
      scan_completion: true
```

You can specify the directory you want to save the logs if you have a different place you want them.

---

## Usage

### 1. Run the program

Start the program with:

```bash
python main.py
```

When the program starts, it will:
1. Discover modules under modules/
2. Prompt user to chose the catagorie they want to use 
3. Run selected modules inside that catagorie 
4. Save logs to the logs/ folder

---
## CVE Database Integration

```
==================================================
Running: cve_search
==================================================
Running module: cve_search
Starting module: cve_search on pending_user_input
BlackICE - NVD CVE Live Reporter (Master Search)

Options
1) Lookup CVE by ID (e.g. CVE-2023-1234)
2) Search by keyword (e.g. openssl, apache, rce)
4) Advanced search (open parameter form)
0) Exit
Choose [0/1/2/4] (0):
```

---
## Directory Layout 
```
blackICE/
├─ core/
│  ├─ engine.py
│  └─ logger.py
├─ modules/
│  └─ Pentesting modules
├─ logs/
├─ baseline/
├─ logger.yml
├─ requirements.txt
└─ main.py
```

---

## What I delivered in Milestone 2

* I remade the basic port scanner from the prototype into a multi technique scanner by adding SYN, Xmas, FIN, and NULL stealth scans (via Scapy). Certian scanning techniques need ROOT privilages. Implemented global rate limiting with PPS control and Nmap-style T0–T5 templates, added intelligent banner grabbing with custom handlers for SSH, HTTP, FTP, SMTP, RDP, etc., integrated automatic CVE lookup with result caching, and rebuilt the threading system using a proper queue-based worker pool with thread-safe printing and graceful shutdown. The result is a fast, stealthy, and reconnaissance-rich scanner that now rivals professional tools while remaining fully customizable.
* Created a complete NVD CVE Live Reporter that uses the official NVD API v2.0 with full parameter support, automatic pagination, rich interactive tables, severity/KEV filtering, and export to JSON/Markdown/HTML. It works as long as you have network access on the host.
* Started the FASTAPI implementation for the backend.

