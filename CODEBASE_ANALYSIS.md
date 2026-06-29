# 📚 SecTest Pro - Codebase Analysis

## 🎯 Overview

SecTest Pro is a Chrome Manifest V3 extension for web application security testing. It combines form enumeration, vulnerability payload injection, AI-powered suggestions via Ollama, and comprehensive safety guardrails.

---

## 🗂️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Chrome Extension                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Popup UI   │  │   Content    │  │  Background  │      │
│  │  (React)     │  │   Script     │  │Service Worker│      │
│  │              │  │              │  │              │      │
│  │ - Scan Forms │  │ - Enumerate  │  │ - Rate Limit │      │
│  │ - Run Tests  │  │ - Inject     │  │ - Validate   │      │
│  │ - Settings   │  │ - Highlight  │  │ - Logging    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │               │
│         └──────────────────┴──────────────────┘              │
│                           │                                   │
└───────────────────────────┼───────────────────────────────────┘
                            │
                   ┌────────▼────────┐
                   │  Ollama LLM     │
                   │  (Optional)     │
                   │  Port 11434     │
                   └─────────────────┘
```

---

## 📁 Important Files Detailed Analysis

### **1. `src/manifest.json` - Extension Configuration**

```json
{
  "manifest_version": 3,
  "name": "SecTest Pro - Form Security Tester",
  "version": "1.0.0"
}
```

**Purpose:** Chrome extension entry point
**Key Permissions:**
- `storage` - Save settings, audit logs, allowlist
- `activeTab` - Access current tab DOM
- `scripting` - Inject content scripts
- `tabs` - Query tabs and capture screenshots

**Components:**
- `background.service_worker` - Background processing
- `action.default_popup` - Popup UI (popup.html)
- `content_scripts` - Injected into web pages

---

### **2. `src/pages/Content/index.js` - DOM Scanner & Injector** ⭐

**Purpose:** Runs in the context of web pages, scans forms, injects payloads

#### **Class: FormScanner**

##### **Core Methods:**

**a) `scanPage()`** - 339 lines
```javascript
scanPage() {
  // Scans DOM for:
  // - <input> all types
  // - <textarea>
  // - <select> dropdowns
  // - <input type="file"> 
  
  // Returns: Array of element metadata
}
```

**What it does:**
1. Uses `document.querySelectorAll()` to find all form elements
2. Extracts metadata:
   - `type`, `name`, `id`, `placeholder`
   - `required`, `value`
   - `uniqueId` (for tracking)
   - `xpath` (for precise location)
3. Stores reference to actual DOM element
4. Returns sanitized data (removes DOM refs for messaging)

**b) `getXPath(element)`** - Lines 94-110
```javascript
getXPath(element) {
  // Generates XPath selector like:
  // /html/body/form[1]/input[2]
  // OR
  // //*[@id="username"]
}
```

**What it does:**
- Creates unique XPath selector for each element
- Useful for traceability and debugging
- Fallback to positional path if no ID

**c) `safeSetValue(element, value)`** - Lines 117-148
```javascript
safeSetValue(element, value) {
  // Safely injects payload into compatible fields
  // Returns: { success: true/false, reason }
}
```

**What it does:**
- **Whitelist approach:** Only allows text-like inputs
- **Blocks:** number, range, date, color, file inputs
- **Allows:** text, search, email, url, tel, password, textarea
- Prevents errors and type mismatches

#### **Message Handlers:**

**a) `ping`** - Connection test
```javascript
if (request.action === 'ping') {
  sendResponse({ ok: true });
}
```

**b) `scanPage`** - Trigger scan
```javascript
if (request.action === 'scanPage') {
  const results = scanner.scanPage();
  sendResponse({ success: true, elements: results });
}
```

**c) `executeVulnTest`** - Inject payloads
```javascript
if (request.action === 'executeVulnTest') {
  // For each selected element:
  // 1. Find DOM element by uniqueId
  // 2. Try each payload
  // 3. Highlight on success (orange border)
  // 4. Return results array
}
```

**d) `attachFile`** - File upload simulation
```javascript
if (request.action === 'attachFile') {
  // Decodes base64 file data
  // Creates Blob → File object
  // Uses DataTransfer API to attach
  // Highlights field (green border)
}
```

**Key Feature:** Visual feedback via temporary border colors
- Green: File attached
- Orange: Payload injected
- Blue: XML attached

---

### **3. `src/pages/Background/index.js` - Service Worker** ⭐

**Purpose:** Background tasks, validation, rate limiting

#### **Object: rateLimiter**

```javascript
const rateLimiter = {
  maxActionsPerMinute: 20,
  actions: [], // Timestamps
  
  canPerformAction() {
    // Sliding window algorithm
    // Removes timestamps > 1 minute old
    // Checks if under limit
  },
  
  getRemainingActions() {
    // Returns available actions
  }
}
```

**What it does:**
- Prevents abuse (DoS prevention)
- Maximum 20 actions per 60 seconds
- Sliding window (not fixed intervals)

#### **Object: payloadValidator**

```javascript
const payloadValidator = {
  dangerousPatterns: [
    /<script[\s\S]*?>/i,      // XSS
    /DROP\s+TABLE/i,          // SQL DROP
    /DELETE\s+FROM/i,         // SQL DELETE
    /\.\.\/\.\.\//g,          // Path traversal
    /eval\s*\(/i,             // Code execution
    // ... more patterns
  ],
  
  isSafe(payload, targetHost) {
    // 1. Check if sanctioned lab
    // 2. Check dangerous patterns
    // 3. Return validation result
  }
}
```

**Sanctioned Labs Bypass:**
- `localhost`, `127.0.0.1`, `dvwa`, `webgoat`, `google`
- These targets bypass validation
- Allows testing real attack payloads

**Why this matters:**
- Protects against accidental production use
- Educational safety net
- Can be disabled for authorized testing

#### **Runtime Behaviors:**

**a) Installation Handler**
```javascript
chrome.runtime.onInstalled.addListener(() => {
  // Sets defaults:
  // - allowlist: ['*']
  // - dryRunMode: true
  // - auditLog: []
});
```

**b) Badge Status**
```javascript
chrome.storage.onChanged.addListener((changes) => {
  if (changes.dryRunMode) {
    // Shows "DRY" (orange) or "LIVE" (green) badge
  }
});
```

---

### **4. `src/pages/Popup/Popup.jsx` - React UI** ⭐⭐⭐

**Purpose:** Main user interface (771 lines)

#### **State Management (33 useState hooks!)**

Key state variables:
```javascript
const [elements, setElements] = useState([]);        // Scanned elements
const [selectedIds, setSelectedIds] = useState(new Set());  // Checkboxes
const [dryRunMode, setDryRunMode] = useState(true);  // Safety mode
const [allowlist, setAllowlist] = useState([]);      // Approved hosts
const [auditLog, setAuditLog] = useState([]);        // Action history
const [selectedVuln, setSelectedVuln] = useState(DEFAULT_VULNS[0].key);
const [payloadSource, setPayloadSource] = useState('library');
const [ollamaAvailable, setOllamaAvailable] = useState(false);
const [activeTab, setActiveTab] = useState('Scan');  // Tab navigation
```

#### **Four Main Tabs:**

**1. Scan Tab** - Element enumeration
```javascript
<button onClick={scanPage}>🔍 Scan Page</button>
// Shows:
// - Total elements found
// - Select all/clear/files only
// - Checkboxes for each element
// - Element metadata (type, name, id, etc.)
```

**2. Payloads Tab** - Payload selection
```javascript
// Four sources:
// 1. Library (preset templates)
// 2. File upload (any file type)
// 3. Manual text (multi-line)
// 4. LLM generation (Ollama)

<button onClick={runVulnTest}>🚀 Run Test</button>
```

**3. History Tab** - Payload reuse
```javascript
// Shows last 50 payload executions
// Actions: Insert, Copy, Delete
// Stored in chrome.storage.local
```

**4. Settings Tab** - Configuration
```javascript
// - Dry Run Mode toggle
// - Host Allowlist management
// - Audit Log export
// - Ollama connection settings
```

#### **Key Functions:**

**a) `scanPage()`** - Lines 120-154
```javascript
const scanPage = async () => {
  // 1. Check if host allowed
  // 2. Ping content script
  // 3. Send 'scanPage' message
  // 4. Display results
  // 5. Log to audit
};
```

**b) `runVulnTest()`** - Lines 261-352
```javascript
const runVulnTest = async () => {
  // 1. Get vulnerability type (XSS, SQLi, etc.)
  // 2. Determine payload source
  // 3. Get selected elements
  // 4. Send to content script
  // 5. Show results alert
  // 6. Save to history
};
```

**c) `fetchLlmSuggestion()`** - Lines 241-254
```javascript
const fetchLlmSuggestion = async () => {
  // 1. Call ollama.generatePayload()
  // 2. Show loading state
  // 3. Populate textarea
  // 4. Handle errors (403, timeout, etc.)
};
```

**d) `confirmAndExecute()`** - Lines 156-165
```javascript
const confirmAndExecute = (action, element, callback) => {
  if (dryRunMode) {
    alert(`🔒 DRY RUN: Would execute ${action}`);
    return;
  }
  // Show confirmation modal
};
```

#### **UI Features:**

**Visual Indicators:**
- 🔒 Dry Run badge (orange)
- ⚠️ Host not allowed banner (red)
- ✅ Success messages
- ❌ Error alerts
- 📝📄📋📎 Element type icons

**Keyboard Interactions:**
- Enter in allowlist input → Add host
- File picker for payload upload
- Textarea for manual payloads

---

### **5. `src/utils/ollamaIntegration.js` - AI Integration** ⭐

**Purpose:** Interface with local Ollama LLM for payload generation

#### **Class: OllamaPayloadAssistant**

**Constructor:**
```javascript
constructor(baseUrl = 'http://127.0.0.1:11434') {
  this.baseUrl = baseUrl;
  this.model = 'llama3.2:1b';  // Lightweight model
  this.isAvailable = false;
  this.lastErrorMessage = '';
  this.checkAvailability();  // Auto-check on init
}
```

**Key Methods:**

**a) `checkAvailability()`** - Lines 14-34
```javascript
async checkAvailability() {
  // GET http://127.0.0.1:11434/api/tags
  // Returns: List of installed models
  // Sets: this.isAvailable flag
}
```

**b) `generatePayload(context)`** - Lines 36-110
```javascript
async generatePayload(context) {
  // Input:
  // {
  //   elementType: 'input',
  //   elementName: 'username',
  //   testType: 'SQL Injection',
  //   vulnerability: 'Auth Bypass'
  // }
  
  // Process:
  // 1. Build prompt with context
  // 2. POST to /api/generate
  // 3. Handle JSON or NDJSON streaming
  // 4. Parse response [PAYLOAD]...[EXPLANATION]
  // 5. Return { payload, explanation, rawResponse }
}
```

**Prompt Engineering:**
```javascript
buildPrompt(context) {
  return `You are a security testing assistant...
  
Context:
- Element Type: ${elementType}
- Test Type: ${testType}

Requirements:
1. Payload must be safe and educational
2. Designed for authorized testing only
3. Should not cause harm
4. Include explanation

Format: [PAYLOAD] <payload> [EXPLANATION] <explanation>`;
}
```

**c) `suggestVulnerability(elementInfo)`** - Lines 142-174
```javascript
async suggestVulnerability(elementInfo) {
  // Analyzes element type/name/id
  // Returns: 3 suggested tests
  // Example: "Test for XSS, SQLi, CSRF"
}
```

**d) `generateTestStrategy(pageContext)`** - Lines 176-208
```javascript
async generateTestStrategy(pageContext) {
  // Input: Page metadata (forms, inputs, file uploads)
  // Returns: Prioritized testing strategy
}
```

**e) `getTemplatePayloads()`** - Lines 211-248
```javascript
getTemplatePayloads() {
  return {
    xss: ['<script>alert("XSS")</script>', ...],
    sqli: ["' OR '1'='1", ...],
    xxe: ['<?xml version="1.0"?>...', ...],
    pathTraversal: ['../../../etc/passwd', ...],
    commandInjection: ['; ls -la', ...],
    ldap: ['*)(uid=*', ...]
  };
}
```

**Error Handling:**
- 20-second timeout on requests
- Captures response body on errors (helps debug 403)
- Differentiates JSON vs streaming responses
- Returns null on failure (graceful degradation)

---

### **6. `src/utils/payloads.js` - Payload Library**

**Purpose:** Centralized vulnerability payload templates

```javascript
export const PAYLOADS = {
  xss: {
    key: 'xss',
    label: 'XSS',
    payloads: [
      '<script>alert(1)</script>',
      '" onmouseover=alert(1) x="',
      // ... 4 total
    ]
  },
  sqli: { ... },
  cmdi: { ... },
  pathTraversal: { ... },
  ssrf: { ... },
  xpath: { ... },
  ldap: { ... }
};

export const DEFAULT_VULNS = [
  PAYLOADS.xss,
  PAYLOADS.sqli,
  // ... all 7 types
];
```

**Design Philosophy:**
- Educational payloads (not weaponized)
- Safe for lab environments
- Demonstrative rather than destructive
- OWASP-inspired coverage

---

### **7. `src/utils/testReporter.js` - Reporting System**

**Purpose:** Generate coverage reports with screenshots

#### **Class: TestReporter**

**Data Structure:**
```javascript
this.testResults = {
  timestamp: ISO string,
  url: string,
  formsFound: number,
  inputsFound: number,
  textareasFound: number,
  selectsFound: number,
  fileInputsFound: number,
  actionsPerformed: [],
  screenshots: [],
  domSnapshots: []
};
```

**Key Methods:**

**a) `captureScreenshot()`** - Lines 48-62
```javascript
async captureScreenshot() {
  // Uses chrome.tabs.captureVisibleTab()
  // Returns: Base64 PNG data URL
  // Stores in testResults.screenshots[]
}
```

**b) `captureDOMSnapshot()`** - Lines 64-73
```javascript
captureDOMSnapshot() {
  // Saves document.documentElement.outerHTML
  // Includes: URL, title, timestamp
  // Useful for post-analysis
}
```

**c) `generateReport()`** - Lines 75-92
```javascript
generateReport() {
  // Calculates summary statistics:
  // - Total elements
  // - Total actions
  // - Success rate
  // - Screenshots count
  
  return report;  // JSON object
}
```

**d) `exportReport(format)`** - Lines 94-103
```javascript
exportReport(format = 'json') {
  if (format === 'json') {
    return JSON.stringify(report, null, 2);
  }
  if (format === 'html') {
    return this.generateHTMLReport(report);
  }
}
```

**e) `generateHTMLReport(report)`** - Lines 105-200
```javascript
generateHTMLReport(report) {
  // Returns: Full HTML document with:
  // - Summary cards (gradient design)
  // - Element breakdown table
  // - Actions performed table
  // - Embedded screenshots
  // - Professional styling
}
```

---

### **8. `scripts/ollama-proxy.js` - CORS Proxy**

**Purpose:** Bypass Chrome extension origin restrictions

#### **The Problem:**
```
Extension Origin: chrome-extension://abc123...
Ollama expects: http://localhost or http://127.0.0.1
Result: 403 Forbidden (CORS violation)
```

#### **The Solution:**
```javascript
// 1. Accept requests from extension
// 2. Strip Origin header
// 3. Add permissive CORS headers
// 4. Forward to Ollama
// 5. Return response
```

**Key Functions:**

**a) `setCors(res)`** - Lines 28-32
```javascript
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,...');
  res.setHeader('Access-Control-Allow-Headers', '*');
}
```

**b) Request Handler** - Lines 34-92
```javascript
http.createServer((req, res) => {
  // Handle OPTIONS (preflight)
  if (req.method === 'OPTIONS') {
    setCors(res);
    res.writeHead(200);
    res.end();
    return;
  }
  
  // Only forward /api/* routes
  if (!req.url.startsWith('/api/')) {
    return { ok: true, message: 'Proxy alive' };
  }
  
  // Clone headers, remove Origin/Referer
  const headers = { ...req.headers };
  delete headers['origin'];
  delete headers['referer'];
  
  // Proxy request to Ollama
  const proxyReq = transport.request(options, (proxyRes) => {
    setCors(res);
    proxyRes.pipe(res);  // Stream response back
  });
  
  req.pipe(proxyReq);  // Stream request body
});
```

**Usage:**
```bash
node scripts/ollama-proxy.js

# Then in extension settings:
# Ollama Base URL: http://127.0.0.1:5000
```

**Port Handling:**
- Default: 5000
- Auto-retry on next port if in use
- Environment variable: `PROXY_PORT`

---

### **9. `test-page.html` - Testing Playground**

**Purpose:** Local HTML page with various form elements for testing

**Contains:**
```html
<!-- 1. Login Form -->
<form id="login-form">
  <input type="text" name="username" required>
  <input type="password" name="password">
  <button>Login</button>
</form>

<!-- 2. Search Form -->
<form id="search-form">
  <input type="search" name="query">
  <button>Search</button>
</form>

<!-- 3. File Upload -->
<form id="upload-form">
  <input type="file" name="document">
  <input type="file" name="image" accept="image/*">
  <button>Upload</button>
</form>

<!-- 4. Advanced Fields -->
<form id="complex-form">
  <textarea name="comment"></textarea>
  <select name="country">
    <option>USA</option>
    <option>Canada</option>
  </select>
  <input type="email" name="email">
  <input type="tel" name="phone">
  <input type="url" name="website">
  <button>Submit</button>
</form>
```

**How to Use:**
1. Open file in browser: `file:///path/to/test-page.html`
2. Add `file:///*` to allowlist OR allow `file://*` pattern
3. Click extension → Scan Page
4. Practice payload injection safely

---

## 🔄 Data Flow Diagrams

### **Scan Flow:**
```
User clicks "Scan Page"
    ↓
Popup.jsx: scanPage()
    ↓
chrome.tabs.sendMessage({ action: 'scanPage' })
    ↓
Content/index.js: Message listener
    ↓
FormScanner.scanPage()
    ↓
document.querySelectorAll('input, textarea, select')
    ↓
Extract metadata (name, id, type, xpath)
    ↓
Return elements array
    ↓
Popup: setElements(response.elements)
    ↓
Display in UI with checkboxes
```

### **Payload Injection Flow:**
```
User selects vulnerability type
    ↓
User chooses payload source (library/file/text/LLM)
    ↓
User clicks "Run Test"
    ↓
Popup: runVulnTest()
    ↓
Check Dry Run Mode
    ↓
[DRY RUN] → Alert simulation, log, stop
[LIVE MODE] → Show confirmation modal
    ↓
User confirms
    ↓
chrome.tabs.sendMessage({
  action: 'executeVulnTest',
  payloads: ['<script>alert(1)</script>', ...],
  uniqueIds: ['input_0_123', 'input_1_123']
})
    ↓
Content/index.js: executeVulnTest handler
    ↓
For each uniqueId:
  - Find element
  - Call safeSetValue()
  - Apply visual highlight
    ↓
Return results array
    ↓
Popup: Show alert with success count
    ↓
Add to audit log
    ↓
Save to payload history
```

### **LLM Generation Flow:**
```
User selects "LLM suggestion"
    ↓
User clicks "Generate with LLM"
    ↓
Popup: fetchLlmSuggestion()
    ↓
ollama.generatePayload({
  elementType: 'input',
  testType: 'SQL Injection'
})
    ↓
ollamaIntegration.js: buildPrompt()
    ↓
POST http://127.0.0.1:11434/api/generate
{
  model: 'llama3.2:1b',
  prompt: '...',
  stream: false
}
    ↓
[Option A: Direct] Ollama accepts
[Option B: Via Proxy] Proxy strips Origin → Ollama
    ↓
Ollama generates response
    ↓
parsePayloadResponse()
    ↓
Extract [PAYLOAD] and [EXPLANATION]
    ↓
Return to Popup
    ↓
setLlmPayload(result.payload)
    ↓
Display in textarea
```

---

## 🔐 Security Features

### **1. Host Allowlist**
- **Default:** `['*']` (allow all) ⚠️
- **Recommended:** Specific hosts only
- **Check:** Before every action
- **UI:** Settings tab management

### **2. Dry Run Mode**
- **Default:** Enabled (safe)
- **Behavior:** Simulates actions, shows alert
- **Visual:** Orange "DRY" badge
- **Toggle:** Settings tab

### **3. Confirmation Dialogs**
- **When:** LIVE mode only
- **Shows:** Action description
- **Options:** Confirm / Cancel
- **Purpose:** Prevent accidents

### **4. Rate Limiting**
- **Limit:** 20 actions/minute
- **Algorithm:** Sliding window
- **Enforced:** Background service worker
- **Scope:** Per extension instance

### **5. Payload Validation**
- **Patterns:** Dangerous keywords blocked
- **Bypass:** Sanctioned labs
- **Examples Blocked:**
  - `<script>` tags
  - `DROP TABLE`
  - `eval()` calls
  - Path traversal `../`

### **6. Audit Logging**
- **Stored:** chrome.storage.local
- **Limit:** Last 100 entries
- **Data:** Timestamp, URL, action, element, result
- **Export:** JSON format
- **Immutable:** Append-only

---

## 🎨 UI/UX Design

### **Color Scheme:**
- Primary: `#667eea` (Purple-blue)
- Secondary: `#764ba2` (Purple)
- Success: `#4CAF50` (Green)
- Warning: `#FF9800` (Orange)
- Error: `#f44336` (Red)

### **Icons:**
- 📝 Input field
- 📄 Textarea
- 📋 Select dropdown
- 📎 File input
- 🔍 Scan
- 🚀 Run test
- ⚙️ Settings
- 📜 History

### **Responsive Elements:**
- Tabs for navigation
- Cards for elements
- Modals for confirmations
- Badges for status
- Buttons with icons

---

## 📊 Storage Schema

### **chrome.storage.local:**

```javascript
{
  // Host allowlist
  allowlist: ['*', 'localhost', 'dvwa', ...],
  
  // Safety mode
  dryRunMode: true,
  
  // Audit trail (last 100)
  auditLog: [
    {
      timestamp: '2024-12-02T10:30:00.000Z',
      action: 'VULN_TEST',
      url: 'http://localhost/login',
      element: { name: 'username', type: 'input' },
      result: 'SUCCESS',
      dryRun: false
    },
    // ... more entries
  ],
  
  // Payload reuse (last 50)
  payloadHistory: [
    {
      timestamp: '2024-12-02T10:30:00.000Z',
      vuln: 'xss',
      payloadSource: 'library',
      payloads: ['<script>alert(1)</script>', ...],
      targets: ['input_0_123', 'input_1_123']
    },
    // ... more entries
  ]
}
```

---

## 🚀 Extension Lifecycle

### **Installation:**
1. User loads unpacked extension
2. `chrome.runtime.onInstalled` fires
3. Sets default storage values
4. Shows "DRY" badge
5. Ready to use

### **Popup Open:**
1. Load React app (popup.bundle.js)
2. Read storage settings
3. Check Ollama availability (background)
4. Query current tab URL
5. Display UI

### **Page Scan:**
1. Inject content script (if not present)
2. Send `scanPage` message
3. Content script enumerates DOM
4. Return elements metadata
5. Display in popup with checkboxes

### **Test Execution:**
1. User configures test
2. Popup sends message to content script
3. Content script modifies DOM
4. Visual feedback (borders)
5. Return results
6. Update audit log

### **Extension Unload:**
1. Service worker terminates
2. Storage persists
3. Content scripts remain active
4. Popup closes

---

## 🐛 Common Issues & Solutions

### **Issue: Content script not available**
**Cause:** Page loaded before extension installed
**Solution:** Reload page

### **Issue: 403 Forbidden from Ollama**
**Cause:** Chrome extension origin not allowed
**Solutions:**
1. Set `OLLAMA_ORIGINS` environment variable
2. Use proxy: `node scripts/ollama-proxy.js`

### **Issue: Payloads not injecting**
**Cause:** Element type not supported (date, number, etc.)
**Solution:** Check `safeSetValue()` whitelist

### **Issue: Rate limit exceeded**
**Cause:** >20 actions in 1 minute
**Solution:** Wait or adjust `maxActionsPerMinute`

---

## 🧪 Testing Workflow

### **Development Testing:**
1. `npm run build` - Compile extension
2. Load in Chrome: `chrome://extensions/`
3. Open `test-page.html`
4. Add to allowlist
5. Test each vulnerability type
6. Check audit log
7. Export report

### **Production Testing:**
1. Set up vulnerable lab (DVWA, WebGoat)
2. Add to allowlist
3. Enable LIVE mode
4. Run systematic tests
5. Document findings
6. Export audit trail

---

## 📈 Future Enhancements

### **Potential Improvements:**
1. **TypeScript migration** - Better type safety
2. **Unit tests** - Jest/React Testing Library
3. **CI/CD pipeline** - Automated builds
4. **More payload templates** - SSTI, SSRF variants
5. **Custom payload builder** - Visual editor
6. **Collaborative features** - Team sharing
7. **Cloud sync** - Cross-device audit logs
8. **Advanced reporting** - PDF exports, charts
9. **Browser automation** - Puppeteer integration
10. **Plugin system** - Custom scanners

---

## 🎓 Learning Resources

### **For Understanding This Codebase:**
- Chrome Extension API: https://developer.chrome.com/docs/extensions/
- React Hooks: https://react.dev/reference/react
- Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

### **For Security Testing:**
- DVWA: https://github.com/digininja/DVWA
- WebGoat: https://github.com/WebGoat/WebGoat
- PortSwigger Academy: https://portswigger.net/web-security

---

## 📝 Summary

**SecTest Pro** is a well-architected Chrome extension that balances:
- ✅ **Power** - Comprehensive testing capabilities
- ✅ **Safety** - Multiple guardrails and confirmations
- ✅ **Usability** - Clean UI with React
- ✅ **Extensibility** - AI integration, modular design
- ✅ **Compliance** - Audit logging, reporting

**Key Strengths:**
- Content script isolation
- Non-invasive scanning
- Visual feedback
- Educational focus

**Areas for Improvement:**
- Default wildcard allowlist
- No authentication system
- Limited test coverage
- Missing TypeScript types

**Best Use Cases:**
- Authorized penetration testing
- Security training
- CTF competitions
- Lab environment validation
- Bug bounty hunting (with permission)

---

## 🧬 Enhanced Field & Page Extraction (v1.1)

The shallow form scanner has been replaced by a pure, tested extraction engine
in **`src/utils/extraction.js`** (no `chrome.*` calls — unit-tested under jsdom).
The content script (`Content/index.js`) is now a thin adapter over it.

### New capabilities

**1. Rich field metadata** — beyond name/type/id, each field now captures:
form `action`/`method`/`enctype`, `maxlength`/`minlength`/`pattern`/`min`/`max`/`step`,
`autocomplete`, `readonly`/`disabled`/`hidden`, resolved `label`
(`<label for>` → wrapping label → aria-label → placeholder), and contenteditable elements.

**2. Attack-surface tags** (`computeTags`) — each field gets a `tags[]` array:
`hidden`, `csrf-token`, `file-upload`, `password`, `email`, `search`,
`redirect-param` (open-redirect candidate), `id-param` (IDOR candidate),
`unvalidated`. Matching uses whole-token name analysis to avoid false positives
(e.g. `video` does not match `id`). Tags drive UI badges and sharpen LLM context.

**3. Deep traversal** (`collectFields`) — recurses **open Shadow DOM** roots
(incl. nested) and **same-origin iframes**, tagging each field's `context`
(`light`/`shadow`/`iframe`). Cross-origin iframes are counted as
`unscannable.crossOriginFrames`. (Closed shadow roots are invisible to script —
in browsers and jsdom alike — so they cannot be counted or read.)

**4. Passive page recon** (`extractPageRecon`) — read-only, **issues no network
requests**: title, meta tags, HTML comments, inline-JS endpoint discovery,
framework fingerprint, form summary, link/button inventory, and **cookie /
storage names only** (never values; HttpOnly cookies are invisible to JS).
A "Export Page Source" action snapshots the full DOM for offline analysis.

**5. Light active recon** (background `activeRecon` / `probeEndpoint`) — GET-only
fetches of `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`, plus
discovered endpoints **only on explicit click**. Fully gated: **allowlist →
dry-run (reports `wouldFetch` without fetching) → rate-limit → audit-log**.
Same-origin enforced; no payloads are ever sent during recon.

### New UI — 🛰️ Recon tab
Form-grouped recon, framework badges, storage names, HTML comments,
discovered-endpoints list with per-item **Probe** buttons, and an Active Recon
panel. The Scan tab now shows **tag badges** and richer per-field details.

### Testing
Jest + jsdom harness added (`npm test`). ~115 tests cover field metadata, every
tag heuristic, traversal (shadow/iframe), recon parsing, active-recon gating,
and an end-to-end run against `test-page.html` (extended with a shadow-DOM host,
same-origin iframe, and redirect/IDOR params).

### Files
- `src/utils/extraction.js` — pure extraction core (fields, tags, traversal, recon)
- `src/utils/reconHelpers.js` — pure active-recon URL/gating helpers
- `src/pages/Content/index.js` — thin adapter + `getPageRecon`/`extractPageSource`
- `src/pages/Background/index.js` — gated `activeRecon`/`probeEndpoint`
- `src/pages/Popup/Popup.jsx` — Recon tab + tag badges
- `tests/` — Jest suites · `jest.config.js`, `babel.config.js`

---

**Generated:** December 2, 2024 (extraction enhancements: see v1.1 section)  
**Author:** AI Analysis of SecTest Pro Codebase  
**Version:** 1.1.0
