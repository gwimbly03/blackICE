# BlackICE


---

## Table of Contents

* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)

  * [1. Run the script](#1-run-the-script)
  * [2. Choose a category](#2-choose-a-category)
  * [3. Choose a module](#3-choose-a-module)
  * [4. Provide input](#4-provide-input)
---

## Prerequisites

* Python 3.8 or newer
* `pip` (Python package installer)

---

## Installation

Install the required Python packages from `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Run the script

Start the program with:

```bash
python main.py
```

### 2. Choose a category

When prompted, type the number of the category you want to use (example categories below — update to match your app):

```
Available Categories:
------------------------------
1. Reconnaissance (3 modules)
2. Vulnerability Assessment (2 modules)
0. Exit BlackICE

Enter category number: 1
```

### 3. Choose a module

After selecting a category, pick a module by typing `1`, `2`, or `3`. Example:

```
Reconnaissance Modules:
------------------------------
1. port_scan            - Port Scanner to find open ports and services and grab their banners
2. gateway_scan         - Scans the gateway to see all the hosts connected, returns the IP and MAC
3. dns_enum             - DNS Enumeration finds the DNS records and subdomains
0. Back to categories

Enter module number: 3
```

### 4. Provide input

Depending on the module you selected, provide an IP address, gateway, or website when prompted:

```
Enter domain to enumerate (e.g., example.com): bcit.ca
```



