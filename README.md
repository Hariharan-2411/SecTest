#  SecTest Pro — Form Security Tester (MV3)

Chrome/Brave MV3 extension for safe, repeatable form security testing. It enumerates form fields, runs OWASP-style payloads across compatible inputs, enforces guardrails (allowlist, dry-run, confirmations, rate limits), logs an immutable audit trail, and can generate payloads locally via Ollama (LLM).

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Chrome](https://img.shields.io/badge/chrome-MV3-yellow.svg)

## 🎯 Key Features

### Scan & Enumerate

- Detects `<input>` (by subtype), `<textarea>`, `<select>`, and file inputs
- Captures names/ids/placeholders/required flags and a stable `uniqueId`
- Generates XPath for traceability (not sent in messages)

### OWASP Attack Runner

- Dropdown to select a vulnerability family:
  - XSS, SQL Injection, Command Injection, Path Traversal, SSRF, XPath, LDAP
- Three payload sources:
  - Preset library (safe, educational examples)
  - Upload .txt (one payload per line)
  - Type payload(s) manually (one per line)
  - Optional LLM suggestion (via local Ollama)
- Batch apply to compatible text-like fields (no auto-submit)
- Visually outlines modified fields; skips unsupported types (date, number, range, color, file, select)

### Guardrails & Telemetry

- **Host Allowlist**
  - Per-host control; wildcard `*` supported (default on fresh install)
  - Toggle/curate list in Settings

- **Dry Run Mode (Default)**
  - Safe simulation mode for exploration
  - All actions are simulated and logged without actual execution
  - Switch to LIVE mode with explicit warnings

- **Explicit Confirmation**
  - Every action in LIVE mode requires confirmation
  - Clear description of what will be executed
  - Cancel option always available

- **Audit Log**
  - Comprehensive logging of all actions
  - Tracks: timestamp, URL, action type, element details, results
  - Who/what/when tracking
  - Export functionality for compliance
  - Last 100 entries preserved

- **Rate Limiting**
  - Maximum 20 actions per minute
  - Prevents accidental DoS conditions
  - Automatic throttling

- **Payload Validation**
  - Blocks dangerous patterns:
    - `<script>` tags
    - JavaScript event handlers (`onclick=`, etc.)
    - SQL injection keywords (DROP, DELETE, INSERT, UPDATE, UNION)
    - `eval()` and `exec()` calls
    - Path traversal patterns (`../`)
  - Exception: Sanctioned lab targets bypass restrictions

### Reporting & Validation

- **Test Reporter**
  - Automated coverage reporting
  - Elements found by type
  - Actions performed tracking
  - Success/failure metrics

- **Screenshot Capture**
  - Before/after visual documentation
  - Automatic capture during testing
  - Embedded in reports

- **DOM Snapshots**
  - Full page state preservation
  - HTML snapshot with metadata
  - URL and timestamp tracking

- **Coverage Reports**
  - Exportable JSON format
  - HTML report with statistics
  - Visual charts and summaries

### Optional AI (Ollama) 🚀

- Local-only LLM via Ollama for payload suggestion
- Runtime-configurable URL/model; connection test button
- Handles JSON and streaming responses; timeouts with errors surfaced in UI

## 📦 Installation

### Prerequisites

- Node.js 16+ and npm
- Chrome or Brave
- (Optional) Docker (DVWA, WebGoat, Juice Shop)
- (Optional) Ollama for AI features

### Build from Source

```bash
# Navigate to the project directory
cd chrome-boiler

# Install dependencies
npm install

# Build the extension
npm run build

# The compiled extension will be in the 'build' directory
```

### Load in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `build` directory from this project
5. The extension icon will appear in your toolbar

## 🚀 Quick Start

### First Time Setup

1. Click the SecTest Pro extension icon
2. Click the ⚙️ **Settings** button
3. Add your test targets to the **Host Allowlist**:
   - Enter `localhost` and click Add
   - Enter `127.0.0.1` and click Add
   - Add any other authorized test domains
4. Keep **Dry Run Mode** enabled for initial exploration

### Basic Usage

1. **Navigate** to your target web application
2. **Click** the extension icon in the toolbar
3. **Scan** by clicking "🔍 Scan Page"
4. **Review** the enumerated form elements
5. Choose an attack family from the dropdown
6. Choose payload source (Library / File / Text / LLM) and click “Generate” if using LLM
7. Click “Run Test” to apply across compatible fields (no auto-submit)
8. Export audit log for documentation

## 🧪 Testing Environments

### Local Test Page

Open the included test page for immediate testing:

```bash
# Open in Chrome
open file:///$(pwd)/test-page.html

# Or start a simple server
python3 -m http.server 8000
# Then visit: http://localhost:8000/test-page.html
```

This page includes:
- User registration forms
- Contact forms
- File upload forms
- Advanced input types
- Search forms

### DVWA (Damn Vulnerable Web Application)

```bash
# Start DVWA using the helper script
./test-targets.sh dvwa

# Or manually with Docker
docker run -d -p 8080:80 vulnerables/web-dvwa

# Access at: http://localhost:8080
# Login: admin / password
```

### WebGoat

```bash
# Start WebGoat
./test-targets.sh webgoat

# Access at: http://localhost:8081/WebGoat
```

### All Test Targets

```bash
# Start all test environments
./test-targets.sh all

# Stop all when done
./test-targets.sh stop

# Check status
./test-targets.sh status
```

## 📖 Documentation

- **[Security Testing Guide](SECURITY_TESTING_GUIDE.md)** — end-to-end operations and safety
- **[Ollama Integration Guide](OLLAMA_INTEGRATION.md)** — AI setup and tips

## 🔐 Security & Safety

### Safe by Default

✅ **Enabled by Default:**
- Dry Run Mode
- Host allowlist requirement
- Confirmation dialogs
- Audit logging
- Rate limiting
- Payload validation

❌ **Never Automatic:**
- Form submission
- Navigation
- Cookie modification
- Storage access
- Network requests

### Authorization Required

⚠️ **WARNING:** This tool is for **authorized security testing only**.

**Before using:**
1. ✅ Ensure you have written permission to test
2. ✅ Verify target is in your allowlist
3. ✅ Enable Dry Run for exploration
4. ✅ Document all activities in audit log
5. ✅ Never test production without approval

**Legal Notice:** Unauthorized testing may violate laws including the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act (CMA), and other cybersecurity legislation.

## 🛠️ Development

### Project Structure

```
chrome-boiler/
├── src/
│   ├── manifest.json                 # MV3 manifest
│   ├── pages/
│   │   ├── Background/
│   │   │   └── index.js             # Service worker: rate limiting, validation, defaults
│   │   ├── Content/
│   │   │   └── index.js             # Scanner + executors (attachXML, insert marker, vuln runner)
│   │   └── Popup/
│   │       ├── Popup.jsx            # React UI: scan, attack runner, payload sources, settings
│   │       ├── Popup.css            # UI styles (600px width, grid layout)
│   │       └── index.html           # Enforces popup width early
│   └── utils/
│       ├── payloads.js              # Preset benign payloads per vuln family
│       ├── ollamaIntegration.js     # LLM client with robust fetch & streaming fallback
│       └── testReporter.js          # Screenshots, DOM snapshot, summary
├── build/                            # Bundled extension output
├── test-page.html                    # Rich local test page
├── test-targets.sh                   # Docker helpers (DVWA, WebGoat, Juice Shop)
├── SECURITY_TESTING_GUIDE.md         # Operational guidance
└── OLLAMA_INTEGRATION.md             # AI setup
```

### Codebase Analysis (File-by-File)

- `src/pages/Background/index.js`
  - Sliding-window rate limiter (20/min); badge updates for DRY/LIVE
  - Payload validator blocks dangerous patterns unless host is “sanctioned” (supports `*`)
  - OnInstall defaults: `allowlist: ['*']`, `dryRunMode: true`, `auditLog: []`

- `src/pages/Content/index.js`
  - FormScanner: enumerates inputs/textarea/select/file and returns serializable metadata
  - Actions:
    - `insertTestMarker` (text inputs/textarea) — responds with details (value/name/id)
    - `attachXML` for file inputs via DataTransfer, or insert XML string for text fields
    - `executeVulnTest` — applies chosen payloads to compatible fields; highlights; returns per-field results
  - Safety: `safeSetValue` skips non-text types (date/number/range/color/file/select)
  - `ping` message allows the popup to detect injection before sending work

- `src/pages/Popup/Popup.jsx`
  - State: elements, allowlist, dryRun, auditLog, selected vuln, payload source, LLM config
  - Flow: ping → scan → choose vuln → choose payload source → run → audit log
  - Payload sources: library, file (.txt), manual text (one per line), LLM (Ollama)
  - LLM advanced panel: set base URL/model, test connection; shows last error

- `src/utils/payloads.js`
  - Curated sets for XSS/SQLi/CMDI/Traversal/SSRF/XPath/LDAP (educational only)

- `src/utils/ollamaIntegration.js`
  - Checks availability (127.0.0.1:11434 by default)
  - `generatePayload()` with timeout and streaming NDJSON fallback
  - Runtime `setBaseUrl`, `setModel`, `getLastError` for troubleshooting

- `webpack.config.js`
  - Entries: popup, background, contentScript; HtmlWebpackPlugin emits popup.html
  - Copies manifest/icons/styles to build/

### Build Commands

```bash
# Development build
npm run build

# Watch mode with hot reload
npm run start

# Code formatting
npm run prettier
```

## 🤖 AI Integration (Ollama)

### Setup Ollama

```zsh
# macOS (Homebrew)
brew install ollama
ollama pull llama3
export OLLAMA_ORIGINS='["chrome-extension://*","http://127.0.0.1","https://127.0.0.1","http://localhost","https://localhost"]'
ollama serve
```

### Features (When Integrated)

- **Intelligent Payload Generation**: Context-aware test payloads
- **Vulnerability Suggestions**: AI-powered recommendations
- **Test Strategies**: Adaptive testing approaches
- **Natural Language**: Describe tests in plain English

See [OLLAMA_INTEGRATION.md](OLLAMA_INTEGRATION.md) for complete setup and Brave/Chrome origin tips.

## 📊 Coverage Reporting

### Generate Report

1. Complete your testing session
2. Click ⚙️ **Settings**
3. Click **📥 Export Log**
4. Save JSON file

### Report Contents

- Test session metadata
- Elements found (by type)
- Forms identified
- Actions performed
- Success/failure rates
- Screenshots (if captured)
- DOM snapshots

## 🐛 Troubleshooting

### Extension Not Working

**Symptom:** Nothing happens when clicking Scan

**Solutions:**
1. Refresh the target page
2. Check if host is in allowlist
3. Open DevTools Console for errors
4. Reload extension in chrome://extensions/

### Elements Not Found

**Symptom:** Scan returns 0 elements

**Solutions:**
1. Wait for page to fully load
2. Check if forms are in iframes
3. Verify content script injected (check Console)

### Actions Not Executing

**Symptom:** "Element not found" error

**Solutions:**
1. Re-scan before performing actions
2. Verify element still exists on page
3. Check if page has dynamic content

### Rate Limit Exceeded
### LLM “403” or not generating

Symptoms:
- Popup shows “LLM not available” or button spins; server logs `403 /api/generate`.

Fix:
- Allow the extension origin in Ollama:
```zsh
export OLLAMA_ORIGINS='["chrome-extension://*","http://127.0.0.1","https://127.0.0.1","http://localhost","https://localhost"]'
ollama serve
```
- In the popup: Settings → LLM Advanced → set URL `http://127.0.0.1:11434`, model `llama3`, click “Test Connection.”


**Symptom:** "Rate limit exceeded" message

**Solutions:**
1. Wait 60 seconds
2. Or reload extension to reset counter

## 📈 Roadmap

### Version 1.1 (Planned)

- [x] Ollama integration in UI (connection test + suggestions)
- [x] Batch operations across compatible fields
- [ ] Per-field selection checkboxes
- [ ] Clear-all after test / auto-revert
- [ ] Custom payload templates saved per host

### Version 1.2 (Future)

- [ ] GraphQL support
- [ ] API endpoint testing
- [ ] WebSocket testing
- [ ] Multi-tab coordination

### Version 2.0 (Vision)

- [ ] ML-based vulnerability detection
- [ ] Automated test generation
- [ ] Integration with CI/CD
- [ ] Team collaboration features

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Update documentation
5. Submit pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for **educational purposes and authorized security testing only**.

**Users are responsible for:**
- Obtaining proper authorization before testing
- Complying with all applicable laws
- Using tool ethically and responsibly
- Understanding tool capabilities and limitations

**The authors:**
- Provide this tool "as is" without warranty
- Assume no liability for misuse
- Do not endorse unauthorized testing
- Encourage responsible disclosure

## 🙏 Acknowledgments

Built with:
- React 18
- Webpack 5
- Chrome Extension Manifest V3
- Ollama (AI integration)

Inspired by:
- OWASP Testing Guide
- Burp Suite methodology
- ZAP Proxy

Test targets:
- DVWA Project
- WebGoat Project
- OWASP Juice Shop

## 📞 Support

- **Issues:** Open a GitHub issue
- **Questions:** Check documentation first
- **Security:** Report responsibly to maintainers

---

**Version:** 1.0.0  
**Last Updated:** October 14, 2025  
**Status:** Production Ready

**Happy (Authorized) Testing! 🔒🐛**
