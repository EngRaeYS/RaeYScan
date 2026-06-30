# 🔍 RAEYSCAN v2.0
> **Scan the void. Find the truth.**

**RAEYSCAN** is a powerful, multi-threaded OSINT (Open Source Intelligence) and information gathering tool written in Python. It allows security researchers and developers to track digital footprints across various platforms, perform DNS enumeration, and discover potential emails or domain associations based on a specific target username.

---

## 🚀 Features

* **Multi-Platform Scans:** Check account availability across Social Media, Developer Platforms (GitHub, Replit, etc.), and Media Sites (YouTube, Twitch, etc.) simultaneously.
* **Email & Domain Discovery:** Automatically generates and lists potential email combinations and top-level domain availability for the target.
* **DNS & IP Enumeration:** Resolves A, MX, NS, and TXT records linked to the target username's domain space.
* **Dark Web & Pastebin Links:** Generates targeted search paths for fast manual verification on leaks and paste sites.
* **Multi-threaded Performance:** Powered by `ThreadPoolExecutor` for swift and concurrent network scans.
* **Automated Reporting:** Generates clean structured reports in **JSON**, **TXT**, and standalone **HTML** styles upon completion.

---

## 💻 Running the Tool (Open Source)

### Prerequisites
Make sure you have Python installed on your system, then open your terminal or command prompt and install the required dependencies:
```bash
pip install requests dnspython

---

## 💻 Running the Tool (Open Source)
Execution
To run the script directly, download or clone the code, navigate to its directory, and execute.
```bash
python RaeYScan.py

---

## 🛠️ Developer & License
Developed by: Eng RaeYS

License: All Rights Reserved - Eng RaeYS
