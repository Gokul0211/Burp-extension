# Endpoint Scanner — Burp Suite Extension

> A powerful Burp Suite extension that wraps **stoic.py**, an advanced JavaScript endpoint discovery engine. It extracts API endpoints, routes, and service configurations from modern SPAs using static analysis, AST parsing, source map harvesting, and Playwright-based dynamic interception.

---

## 📁 Repository Structure

```
Burp-extension/
├── stoic.py                    # Core scanner engine (run this standalone or via extension)
├── endpoint_scanner_burp.py    # Burp Suite extension (Jython)
├── requirements.txt            # Python dependencies for stoic.py
└── README.md
```

---

## ⚙️ How It Works

`stoic.py` runs a **4-phase scan** against a target web application:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | JS Discovery | Crawls HTML, finds all JavaScript and JSON files. Handles micro-frontends and module federation. |
| 1.5 | Source Map Harvesting | Probes for `.map` files — leaks original source paths and sometimes full source code. |
| 2 | Static Analysis | Regex + AST extraction of endpoints, routes, GraphQL ops, RPC calls. Applies confidence tiering. |
| 3 | Dynamic Interception | Playwright headless browser navigates routes, intercepts live network requests, feeds new JS chunks back into the analyzer recursively. |

The Burp extension (`endpoint_scanner_burp.py`) provides a GUI tab inside Burp Suite to run `stoic.py` as a subprocess against any target, with cookie support, output parsing, and results displayed in a sortable table.

---

## 🧰 Prerequisites

### 1. Python 3.10+

Download from [python.org](https://www.python.org/downloads/) or install via your package manager.

```bash
# Verify
python3 --version
```

### 2. Burp Suite (Community or Pro)

Download from [portswigger.net](https://portswigger.net/burp/communitydownload).

### 3. Jython Standalone JAR (Required for the Burp Extension)

The Burp extension is written in **Jython** (Python 2 running on the JVM inside Burp). You must give Burp a Jython interpreter.

**Download:** [https://www.jython.org/download](https://www.jython.org/download)  
Get the **Standalone JAR** — for example: `jython-standalone-2.7.4.jar`

**Install in Burp:**
1. Open Burp Suite
2. Go to **Extensions → Extensions settings** (or **Extender → Options** in older versions)
3. Under **Python Environment**, click **Select file...**
4. Browse to and select your downloaded `jython-standalone-2.7.4.jar`
5. Click **OK** — Burp will confirm the Jython environment is loaded

> ⚠️ Use **Jython 2.7.3 or 2.7.4** — earlier versions have import issues with newer Java.

---

## 📦 Installing Python Dependencies

### For `stoic.py` (Core Scanner)

Install all dependencies with:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install requests
pip install beautifulsoup4
pip install esprima
pip install pandas
pip install openpyxl
pip install urllib3
```

### For Playwright (Dynamic Analysis — Phase 3)

Playwright requires a separate install step to download the browser binary:

```bash
pip install playwright
python -m playwright install chromium
```

> If you skip this, the scanner will still work but Phase 3 (dynamic interception) will be skipped automatically.

### Full one-liner install:

```bash
pip install requests beautifulsoup4 esprima pandas openpyxl urllib3 playwright && python -m playwright install chromium
```

---

## 🚀 Running `stoic.py` Standalone (CLI)

You can use the scanner entirely from the command line without Burp:

### Basic scan

```bash
python3 stoic.py --target https://example.com
```

### Authenticated scan (with cookies)

```bash
python3 stoic.py --target https://example.com --cookies "sessionid=abc123; csrftoken=xyz"
```

### Fast scan (skip dynamic/Playwright phase)

```bash
python3 stoic.py --target https://example.com --skip-dynamic
```

### Full control

```bash
python3 stoic.py --target https://example.com \
  --cookies "session=abc; token=xyz" \
  --output my_results.json \
  --max-routes 50 \
  --max-depth 5
```

### All CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--target` | (prompt) | Target URL to scan |
| `--cookies` | None | Cookie string — format: `"name=value; name2=value2"` |
| `--no-cookies` | False | Skip cookie prompt entirely |
| `--output` | `results.json` | Output file path for JSON results |
| `--max-routes` | `25` | Max routes to visit per depth level |
| `--max-depth` | `3` | Max navigation depth for dynamic phase |
| `--skip-dynamic` | False | Skip Playwright Phase 3 (faster, static only) |
| `--quiet` | False | Suppress progress output |

---

## 🔌 Installing the Burp Extension

### Step 1 — Place the files

Put both files in the **same directory** on your machine:

```
/your/chosen/folder/
├── stoic.py
└── endpoint_scanner_burp.py
```

The extension auto-discovers `stoic.py` by searching:
- Same directory as the extension file
- `~/stoic.py`
- `~/endpoint_scanner.py` (fallback)

### Step 2 — Load in Burp

1. Open Burp Suite
2. Go to **Extensions → Installed → Add**
3. Set **Extension type** to `Python`
4. Click **Select file** and choose `endpoint_scanner_burp.py`
5. Click **Next** — you should see no errors in the output panel
6. A new **"Endpoint Scanner"** tab will appear in Burp's top nav

> If you see `Scanner not found` in the output, check Step 1 and make sure `stoic.py` is in the same folder.

---

## 🖥️ Using the Burp Extension

### UI Overview

```
┌─────────────────────────────────────────────────────┐
│  Target URL: [________________________] [Start Scan] │
│  Cookies:    [________________________] [Extract from Burp] │
│  ☐ Auto-scan JS files  ☑ Skip dynamic  ☐ Verbose    │
│  Max Routes: [25]   Max Depth: [3]                   │
│  [████████████████░░░░░░░] Scanning...               │
├─────────────────────────────────────────────────────┤
│  Method │ Endpoint │ Type │ Classification │ Source  │
│  ────────────────────────────────────────────────── │
│  GET    │ /api/v1/users │ REST │ HIGH_CONFIDENCE │ … │
│  POST   │ /api/auth    │ REST │ VERIFIED_API    │ … │
├─────────────────────────────────────────────────────┤
│  [Export JSON] [Export TXT] [Add to Site Map]        │
│  [Send to Repeater] [Clear Results]                  │
│  Total: 42 | Backend: 18 | Frontend: 12 | RPC: 5    │
└─────────────────────────────────────────────────────┘
```

### Workflow

**Option A — Manual scan:**
1. Paste the target URL in the **Target URL** field
2. Optionally add cookies (see below)
3. Tune **Max Routes** and **Max Depth** if needed
4. Check **Skip dynamic analysis** for faster results
5. Click **Start Scan**
6. Watch live output in the bottom log pane
7. Results populate the table as they come in

**Option B — From Burp's proxy/repeater:**
1. Right-click any request in Proxy, Repeater, Target, etc.
2. Select **"Scan for Endpoints"** from the context menu
3. The extension auto-fills the URL and cookies from that request
4. Switch to the **Endpoint Scanner** tab and click **Start Scan**

### Cookie Handling

Three ways to provide cookies:

| Method | How |
|--------|-----|
| **Manual** | Type or paste into the Cookies field: `session=abc; token=xyz` |
| **Extract from Burp** | Select a request in Burp → click "Extract from Burp" button |
| **Context menu** | Right-click a request → "Scan for Endpoints" — cookies auto-fill |

### Output Actions

| Button | Action |
|--------|--------|
| **Export JSON** | Save all results to a `.json` file |
| **Export TXT** | Save all results to a human-readable `.txt` file |
| **Add to Site Map** | Push all discovered endpoints into Burp's Site Map |
| **Send to Repeater** | Send selected table row(s) directly to Burp Repeater |
| **Clear Results** | Clear the table and log |

### Auto-scan Mode

Enable **"Auto-scan JS files"** checkbox to passively queue every `.js` file Burp intercepts while you browse. Queued URLs are automatically processed when you next click **Start Scan**.

---

## 📊 Understanding Results

### Classification Tiers

| Classification | Meaning |
|----------------|---------|
| `VERIFIED_API` | Confirmed by actual network interception (Playwright) |
| `HIGH_CONFIDENCE` | Strong static signals — explicit code references, API naming patterns |
| `BACKEND_API` | Likely server-side endpoint — `/api/`, `/v1/`, `/graphql` etc. |
| `FRONTEND_ROUTE` | SPA client-side route — hash routes, Angular/React router paths |
| `RPC_ENDPOINT` | Remote procedure call style endpoint |
| `MEDIUM_CONFIDENCE` | Plausible but less certain |
| `LOW_CONFIDENCE` | Weak signal — review manually |

### Output JSON Format

```json
{
  "scan_metadata": {
    "scanner": "Advanced Endpoint Scanner",
    "target": "https://example.com",
    "timestamp": "2026-02-19 12:00:00",
    "total_endpoints": 42,
    "source_maps_found": 3
  },
  "endpoints": [
    {
      "method": "GET",
      "endpoint": "https://example.com/api/v1/users",
      "type": "REST",
      "classification": "HIGH_CONFIDENCE",
      "source": "main.abc123.js",
      "parameters": ["page", "limit"],
      "confidence_score": 85,
      "tags": ["api_pattern", "explicit_code_reference"]
    }
  ]
}
```

---

## 🔧 Troubleshooting

### Extension doesn't load in Burp
- Confirm Jython standalone JAR is set in **Extensions → Extensions settings → Python Environment**
- Confirm the JAR is the **standalone** version, not the installer version
- Check the **Output** tab in the Extensions panel for error messages

### "Scanner not found" warning
- Make sure `stoic.py` is in the **exact same directory** as `endpoint_scanner_burp.py`
- Check the Burp extension output for the path it searched

### 0 endpoints found
- The site may block automated scrapers (403/WAF/Cloudflare) — add auth cookies
- Try with `--skip-dynamic` disabled so Playwright can catch runtime endpoints
- Check if the site is a pure SPA — Playwright (Phase 3) is required for these

### Playwright not working
```bash
# Reinstall
pip install --upgrade playwright
python -m playwright install chromium

# If permission issues on Linux:
python -m playwright install --with-deps chromium
```

### SSL errors
The scanner runs with `verify=False` by default and suppresses SSL warnings. This is intentional for pentesting use.

### Windows — `python3` not found
Edit line 43 in `endpoint_scanner_burp.py`:
```python
'python_path': 'python'   # Windows uses 'python' not 'python3'
```

---

## 📋 Requirements Summary

| Requirement | Version | Link |
|-------------|---------|------|
| Python | 3.10+ | [python.org](https://www.python.org) |
| Burp Suite | Any (Community or Pro) | [portswigger.net](https://portswigger.net/burp) |
| Jython Standalone JAR | 2.7.3 or 2.7.4 | [jython.org/download](https://www.jython.org/download) |
| requests | latest | via pip |
| beautifulsoup4 | latest | via pip |
| esprima | latest | via pip (optional — AST analysis) |
| pandas | latest | via pip (optional — Excel export) |
| playwright | latest | via pip (optional — dynamic phase) |

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Only use it against systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The authors are not responsible for misuse.
