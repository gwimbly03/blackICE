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

* Modular engine that lazy loads modules from the modules/ directory.
* Custom logging system that can write logs in JSON or CSV, configurable via YAML.
* Terminal and email notifications summarizing module runs and baseline diffs.
* Fully functional modules that allow for testing on servers and large networks.
* NVE CVE TUI.
* Fully working web app that has a terminal output which allows you to run all modules.

---

## Prerequisites

* Python 3.8 or newer
* `pip` (Python package installer)
* NodeJS 25 or newer
* `npm` (Node Package manager)

---

## Installation

1. Clone the repository (if you haven't already):

```bash
git clone https://github.com/towelie03/blackICE.git
cd blackICE
pip install -r requirements.txt
npm install


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

To launch the FastAPI backend (API + WebSocket server), from the project root run:

```bash
uvicorn backend.api:app --reload
```

To start the web-based user interface, run:

```bash
npm run dev
```

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
├── backend
│   ├── api.py
│   ├── baseline
│   ├── core
│   │   ├── cve_db.py
│   │   ├── engine.py
│   │   ├── __init__.py
│   │   ├── interactive_tty.py
│   │   ├── logger.py
│   │   ├── module_runner.py
│   │   ├── __pycache__
│   │   └── streamer.py
│   ├── __init__.py
│   ├── logs
│   ├── modules
│   │   ├── arp_spoofing.py
│   │   ├── cve_search.py
│   │   ├── ddos_attacks.py
│   │   ├── dns_cache_poisoning.py
│   │   ├── dns_enum.py
│   │   ├── gateway_scan.py
│   │   ├── linux_baseline_scanner.py
│   │   ├── port_scan.py
│   │   ├── __pycache__
│   │   ├── ssl_scan.py
│   │   ├── vuln_scan.py
│   │   └── web_vuln_scan.py
│   ├── nvd_cve.json
├── frontend
│   ├── eslint.config.js
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── public
│   ├── README.md
│   ├── src
│   │   ├── api.js
│   │   ├── App.css
│   │   ├── App.jsx
│   │   ├── assets
│   │   ├── components
│   │   ├── index.css
│   │   ├── main.jsx
│   │   └── ModuleConsole.jsx
│   └── vite.config.js
├── logger.yaml
├── main.py
├── node_modules
├── package.json
├── package-lock.json
├── README.md
├── requirements.txt
└── shell.nix
```

---

## What I delivered in Milestone 1

* Custom logger that outputs logs in JSON or CSV and takes configuration from a YAML file.
Notifiactions that notify the user by email and on the terminal about when a module is ran and when it finishes executing. The email will display the scan summary and the difference between the new and previous scan, allowing comparsion of the baseline.
* Added new modules to the pentester, they are OWASP Top 10 scan, DDOS attack, DNS poisioning and ARP spoofing.

---

## What I delivered in Milestone 2

* I remade the basic port scanner from the prototype into a multi technique scanner by adding SYN, Xmas, FIN, and NULL stealth scans (via Scapy). Certian scanning techniques need ROOT privilages. Implemented global rate limiting with PPS control and Nmap-style T0–T5 templates, added intelligent banner grabbing with custom handlers for SSH, HTTP, FTP, SMTP, RDP, etc., integrated automatic CVE lookup with result caching, and rebuilt the threading system using a proper queue-based worker pool with thread-safe printing and graceful shutdown. The result is a fast, stealthy, and reconnaissance-rich scanner that now rivals professional tools while remaining fully customizable.
* Created a complete NVD CVE Live Reporter that uses the official NVD API v2.0 with full parameter support, automatic pagination, rich interactive tables, severity/KEV filtering, and export to JSON/Markdown/HTML. It works as long as you have network access on the host.
* Started the FASTAPI implementation for the backend.

---

## What I delivered in Milestone 3

* Implemented a modular execution engine that lazy loads modules. Added REST endpoints to: list available modules, start a module on demand, stop a module safely at any time.
* Integrated WebSocket-based real-time output streaming for module execution and a InteractiveTTY system to: capture module stdout, stream output live to the web UI support interactive stdin where applicable.
* Fixed module runner issues allowing for modules to only start when explicitly triggered by the UI. Stop operations are now idempotent, preventing errors when stopping completed modules (Which happened during the live demo).
* Ensured clean cleanup of tasks, WebSockets, and internal state after module execution.
* Build a web UI to view all discovered modules, select and switch between modules and start and stop modules via UI controls
* Handle module switching and completion gracefully without crashing or desyncing and integrated ANSI-to-HTML conversion for readable terminal output in the browser.
