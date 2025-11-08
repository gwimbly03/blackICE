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
- [Directory layout](#directory-layout) 
- [What I delivered in Milestone 1](#what-i-delivered-in-milestone-1)  

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

## What I delivered in Milestone 1

* Custom logger that outputs logs in JSON or CSV and takes configuration from a YAML file.
* Notifiactions that notify the user by email and on the terminal about when a module is ran and when it finishes executing. The email will display the scan summary and the difference between the new and previous scan, allowing comparsion of the baseline.
* Added new modules to the pentester, they are OWASP Top 10 scan, DDOS attack, DNS poisioning and ARP spoofing.

