# Endpoint Scanner - Burp Suite Extension

This is a Burp Suite extension that integrates a custom Python-based endpoint scanner. It passively analyzes JavaScript files to discover API endpoints, RPC calls, and hidden routes.

## 📂 Architecture

This tool uses a split architecture to bypass Jython's limitations:
* **`endpoint_scanner_burp.py`**: Runs inside Burp Suite (via Jython). Handles the UI tab and traffic listening.
* **`endpoint_scanner.py`**: Runs as a separate system subprocess (Python 3). This allows the use of modern libraries like `pandas` and `playwright`.

## 🚀 Installation

### 1. Python Setup
You need Python 3 installed on your system. Install the dependencies:
```bash
pip install -r requirements.txt
playwright install chromium