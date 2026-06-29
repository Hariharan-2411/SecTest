# 🏗️ SecTest Pro - Architecture Diagrams

## 📐 System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Chrome Browser                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                   EXTENSION CONTEXT                            │  │
│  │                                                                │  │
│  │  ┌──────────────┐      ┌──────────────┐     ┌──────────────┐ │  │
│  │  │   Popup UI   │◄────►│  Background  │     │   Storage    │ │  │
│  │  │   (React)    │      │Service Worker│◄────►│ (chrome.api) │ │  │
│  │  │              │      │              │     │              │ │  │
│  │  │ • Scan Tab   │      │ • Rate Limit │     │ • allowlist  │ │  │
│  │  │ • Payloads   │      │ • Validation │     │ • auditLog   │ │  │
│  │  │ • History    │      │ • Badge      │     │ • dryRunMode │ │  │
│  │  │ • Settings   │      │              │     │              │ │  │
│  │  └──────┬───────┘      └──────────────┘     └──────────────┘ │  │
│  │         │                                                     │  │
│  │         │ chrome.tabs.sendMessage()                          │  │
│  │         │                                                     │  │
│  └─────────┼─────────────────────────────────────────────────────┘  │
│            │                                                          │
│  ┌─────────▼──────────────────────────────────────────────────────┐ │
│  │                      WEB PAGE CONTEXT                          │ │
│  │                                                                │ │
│  │  ┌──────────────┐         ┌─────────────────────────────┐    │ │
│  │  │Content Script│◄───────►│     Page DOM                │    │ │
│  │  │              │         │                             │    │ │
│  │  │ • FormScanner│         │  <input name="username">    │    │ │
│  │  │ • safeSetVal │         │  <textarea id="comment">    │    │ │
│  │  │ • getXPath   │         │  <select name="country">    │    │ │
│  │  │ • attachFile │         │  <input type="file">        │    │ │
│  │  └──────────────┘         └─────────────────────────────┘    │ │
│  │                                                                │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
           │
           │ fetch() / HTTP
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     EXTERNAL SERVICES                                 │
│                                                                        │
│  ┌─────────────────┐        ┌────────────────────┐                  │
│  │ Ollama Proxy    │        │  Ollama Server     │                  │
│  │ (Optional)      │───────►│                    │                  │
│  │ Port 5000       │        │  Port 11434        │                  │
│  │                 │        │                    │                  │
│  │ • Strip Origin  │        │  • llama3.2:1b     │                  │
│  │ • Add CORS      │        │  • mistral         │                  │
│  │ • Proxy requests│        │  • llama2          │                  │
│  └─────────────────┘        └────────────────────┘                  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Message Flow Diagram

```
┌─────────────┐                                           ┌─────────────┐
│   Popup     │                                           │   Content   │
│  (React UI) │                                           │   Script    │
└──────┬──────┘                                           └──────┬──────┘
       │                                                         │
       │ 1. User clicks "Scan Page"                             │
       │─────────────────────────────────────────────────────────►
       │    chrome.tabs.sendMessage({                           │
       │      action: 'scanPage'                                │
       │    })                                                   │
       │                                                         │
       │                                    2. scanner.scanPage()│
       │                              document.querySelectorAll()│
       │                                     Extract metadata    │
       │                                                         │
       │◄─────────────────────────────────────────────────────────
       │    sendResponse({                                      │
       │      success: true,                                    │
       │      elements: [...]                                   │
       │    })                                                   │
       │                                                         │
       │ 3. Display elements in UI                              │
       │    with checkboxes                                     │
       │                                                         │
       │ 4. User selects elements                               │
       │    and clicks "Run Test"                               │
       │                                                         │
       │ 5. Confirmation dialog (LIVE mode)                     │
       │                                                         │
       │ 6. Send payload injection request                      │
       │─────────────────────────────────────────────────────────►
       │    chrome.tabs.sendMessage({                           │
       │      action: 'executeVulnTest',                        │
       │      payloads: ['<script>...', ...],                   │
       │      uniqueIds: ['input_0_123', ...]                   │
       │    })                                                   │
       │                                                         │
       │                              7. For each uniqueId:     │
       │                                 • Find element         │
       │                                 • safeSetValue()       │
       │                                 • Highlight border     │
       │                                                         │
       │◄─────────────────────────────────────────────────────────
       │    sendResponse({                                      │
       │      success: true,                                    │
       │      results: [{success, payload}, ...]                │
       │    })                                                   │
       │                                                         │
       │ 8. Show success alert                                  │
       │    Add to audit log                                    │
       │    Save to history                                     │
       │                                                         │
```

---

## 🤖 Ollama Integration Flow

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Popup     │         │Ollama Proxy │         │   Ollama    │
│  Component  │         │  (Optional) │         │   Server    │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                        │
       │ 1. User clicks        │                        │
       │    "Generate with LLM"│                        │
       │                       │                        │
       │ 2. fetchLlmSuggestion()                       │
       │    ollama.generatePayload({...})              │
       │                       │                        │
       │ 3. POST /api/generate │                        │
       │───────────────────────►                        │
       │    Origin: chrome-extension://...              │
       │                       │                        │
       │                       │ 4. Strip Origin header │
       │                       │    Add CORS headers    │
       │                       │────────────────────────►
       │                       │    POST /api/generate  │
       │                       │    Origin: (removed)   │
       │                       │                        │
       │                       │                        │ 5. Generate
       │                       │                        │    response
       │                       │                        │    using LLM
       │                       │                        │
       │                       │◄────────────────────────
       │                       │    200 OK              │
       │                       │    { response: "..." } │
       │                       │                        │
       │◄───────────────────────                        │
       │    200 OK (with CORS) │                        │
       │    Access-Control-Allow-Origin: *              │
       │                       │                        │
       │ 6. parsePayloadResponse()                     │
       │    Extract [PAYLOAD] and [EXPLANATION]        │
       │                       │                        │
       │ 7. Display in UI      │                        │
       │    setLlmPayload()    │                        │
       │                       │                        │
```

**Direct Connection (without proxy):**
```
Popup ────► Ollama (requires OLLAMA_ORIGINS env var)
```

**With Proxy (easier):**
```
Popup ────► Proxy ────► Ollama (no configuration needed)
```

---

## 📦 Component Hierarchy

```
<Popup>
  │
  ├─ Header
  │  ├─ Title: "🔒 SecTest Pro"
  │  └─ Badge: "DRY RUN" / "LIVE"
  │
  ├─ Warning Banner (if host not allowed)
  │
  ├─ Tab Navigation
  │  ├─ 🔍 Scan Tab
  │  ├─ 🧰 Payloads Tab
  │  ├─ 📜 History Tab
  │  └─ ⚙️ Settings Tab
  │
  ├─ Tab Content (conditional)
  │  │
  │  ├─ IF activeTab === 'Scan':
  │  │  ├─ Controls
  │  │  │  ├─ "Scan Page" button
  │  │  │  ├─ "Settings" button
  │  │  │  └─ Vulnerability dropdown + "Run Test"
  │  │  │
  │  │  └─ Elements List
  │  │     ├─ Stats bar (count, select buttons)
  │  │     └─ Element Cards (map over elements)
  │  │        ├─ Checkbox
  │  │        ├─ Icon (📝📄📋📎)
  │  │        ├─ Type & Name
  │  │        └─ Details (id, placeholder, required)
  │  │
  │  ├─ IF activeTab === 'Payloads':
  │  │  ├─ Radio: Preset Payloads
  │  │  ├─ Radio: Upload File
  │  │  │  └─ <input type="file">
  │  │  ├─ Radio: Manual Text
  │  │  │  └─ <textarea>
  │  │  └─ Radio: LLM Suggestion
  │  │     ├─ "Generate" button
  │  │     ├─ Result textarea
  │  │     └─ Ollama status hint
  │  │
  │  ├─ IF activeTab === 'History':
  │  │  └─ History Items (map over payloadHistory)
  │  │     ├─ Timestamp
  │  │     ├─ Vulnerability type
  │  │     ├─ Payload source
  │  │     ├─ Actions: Insert / Copy / Delete
  │  │     └─ Payload preview
  │  │
  │  └─ IF activeTab === 'Settings':
  │     ├─ Dry Run Toggle
  │     ├─ Host Allowlist
  │     │  ├─ Input + "Add" button
  │     │  └─ List (with "×" remove buttons)
  │     ├─ Audit Log
  │     │  ├─ Entry count
  │     │  └─ "Export" button
  │     └─ Ollama Configuration
  │        ├─ Base URL input
  │        ├─ Model name input
  │        ├─ "Test Connection" button
  │        └─ Status / Error display
  │
  └─ Confirmation Modal (if confirmAction)
     ├─ Message
     └─ Actions: "✓ Confirm" / "✗ Cancel"
```

---

## 💾 Data Flow - Storage

```
┌─────────────────────────────────────────────────────────────┐
│                   chrome.storage.local                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  allowlist: ['*', 'localhost', 'dvwa']                       │
│      ▲                                                        │
│      │ Read on mount, Write on change                        │
│      ▼                                                        │
│  [Settings Tab] ────► addToAllowlist()                       │
│                  └──► removeFromAllowlist()                  │
│                                                               │
│  ─────────────────────────────────────────────────────────   │
│                                                               │
│  dryRunMode: true                                            │
│      ▲                                                        │
│      │ Read on mount, Write on toggle                        │
│      ▼                                                        │
│  [Settings Tab] ────► toggleDryRun()                         │
│  [Header Badge] ────► Display "DRY" / "LIVE"                 │
│  [Background]   ────► Update badge color                     │
│                                                               │
│  ─────────────────────────────────────────────────────────   │
│                                                               │
│  auditLog: [                                                 │
│    {                                                          │
│      timestamp: "2024-12-02T10:30:00Z",                      │
│      action: "VULN_TEST",                                    │
│      url: "http://localhost/login",                          │
│      element: { name: "username", type: "input" },           │
│      result: "SUCCESS",                                      │
│      dryRun: false                                           │
│    },                                                         │
│    ... (max 100 entries)                                     │
│  ]                                                            │
│      ▲                                                        │
│      │ Append on each action                                 │
│      ▼                                                        │
│  [All Actions] ────► addToAuditLog()                         │
│  [Settings Tab] ───► exportAuditLog() (download JSON)        │
│                                                               │
│  ─────────────────────────────────────────────────────────   │
│                                                               │
│  payloadHistory: [                                           │
│    {                                                          │
│      timestamp: "2024-12-02T10:30:00Z",                      │
│      vuln: "xss",                                            │
│      payloadSource: "library",                               │
│      payloads: ["<script>alert(1)</script>"],                │
│      targets: ["input_0_123", "input_1_123"]                 │
│    },                                                         │
│    ... (max 50 entries)                                      │
│  ]                                                            │
│      ▲                                                        │
│      │ Save on test execution                                │
│      ▼                                                        │
│  [runVulnTest()] ──► savePayloadHistory()                    │
│  [History Tab]   ───► Display, Insert, Copy, Delete          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Payload Injection Process

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: User Prepares Test                                   │
└───────────────────┬──────────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │ Select Vulnerability │
         │ Type (XSS, SQLi, ...) │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │ Choose Payload Source│
         │ • Library            │
         │ • File Upload        │
         │ • Manual Text        │
         │ • LLM Generation     │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │ Select Target Fields │
         │ (checkboxes)         │
         └──────────┬───────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────────────┐
│ Step 2: Click "Run Test"                                   │
└───────────────┬────────────────────────────────────────────┘
                │
                ▼
      ┌─────────────────────┐
      │ Check Dry Run Mode  │
      └─────────┬───────────┘
                │
        ┌───────┴──────┐
        │              │
        ▼              ▼
   [DRY RUN]      [LIVE MODE]
        │              │
        │              ▼
        │      ┌──────────────────┐
        │      │ Show Confirmation│
        │      │ Modal            │
        │      └──────┬───────────┘
        │             │
        │     ┌───────┴──────┐
        │     │              │
        │     ▼              ▼
        │  Cancel        Confirm
        │     │              │
        │     └──────┐       │
        │            │       │
        ▼            ▼       ▼
   Alert      End    Continue
   "DRY RUN"          │
   Log                │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Send to Content Script                              │
└───────────────┬─────────────────────────────────────────────┘
                │
                ▼
       chrome.tabs.sendMessage({
         action: 'executeVulnTest',
         vulnKey: 'xss',
         payloads: ['<script>alert(1)</script>', ...],
         uniqueIds: ['input_0_123', ...]
       })
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Content Script Processing                           │
└───────────────┬─────────────────────────────────────────────┘
                │
                ▼
       ┌────────────────────┐
       │ For Each uniqueId: │
       └────────┬───────────┘
                │
                ▼
       ┌────────────────────┐
       │ findElementByUniqueId │
       └────────┬───────────┘
                │
        ┌───────┴──────┐
        │              │
        ▼              ▼
   Not Found      Found
        │              │
        │              ▼
        │     ┌────────────────────┐
        │     │ Check Element Type │
        │     └────────┬───────────┘
        │              │
        │      ┌───────┴──────┐
        │      │              │
        │      ▼              ▼
        │  Unsupported   Supported
        │  (select, file) (input, textarea)
        │      │              │
        │      │              ▼
        │      │     ┌────────────────────┐
        │      │     │ Try Each Payload   │
        │      │     └────────┬───────────┘
        │      │              │
        │      │              ▼
        │      │     ┌────────────────────┐
        │      │     │ safeSetValue()     │
        │      │     └────────┬───────────┘
        │      │              │
        │      │      ┌───────┴──────┐
        │      │      │              │
        │      │      ▼              ▼
        │      │   Failed        Success
        │      │      │              │
        │      │      │              ▼
        │      │      │     ┌────────────────────┐
        │      │      │     │ element.value = p  │
        │      │      │     └────────┬───────────┘
        │      │      │              │
        │      │      │              ▼
        │      │      │     ┌────────────────────┐
        │      │      │     │ Highlight Border   │
        │      │      │     │ (orange, 1.5s)     │
        │      │      │     └────────┬───────────┘
        │      │      │              │
        ▼      ▼      ▼              ▼
   ┌──────────────────────────────────────────┐
   │ Collect Result                            │
   │ { uniqueId, success, reason/payload }    │
   └──────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 5: Return Results                                       │
└───────────────┬─────────────────────────────────────────────┘
                │
                ▼
       sendResponse({
         success: true,
         results: [
           { uniqueId: 'input_0_123', success: true, payload: '...' },
           { uniqueId: 'input_1_123', success: false, reason: 'unsupported' }
         ]
       })
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 6: Popup Handles Response                               │
└───────────────┬─────────────────────────────────────────────┘
                │
                ▼
       ┌────────────────────┐
       │ Count Successes    │
       └────────┬───────────┘
                │
                ▼
       ┌────────────────────┐
       │ Show Alert         │
       │ "✅ Test applied   │
       │  to 2/3 fields"    │
       └────────┬───────────┘
                │
                ▼
       ┌────────────────────┐
       │ addToAuditLog()    │
       └────────┬───────────┘
                │
                ▼
       ┌────────────────────┐
       │ savePayloadHistory()│
       └────────────────────┘
```

---

## 🔒 Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                 User Action Attempt                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │ Layer 1: Host Check  │
          │ isHostAllowed(url)   │
          └──────────┬───────────┘
                     │
             ┌───────┴──────┐
             │              │
             ▼              ▼
         Not Allowed    Allowed
             │              │
             ▼              ▼
         ⚠️ Alert      Continue
         "Host not           │
         in allowlist"       │
                             ▼
                  ┌──────────────────────┐
                  │ Layer 2: Dry Run     │
                  │ Check dryRunMode     │
                  └──────────┬───────────┘
                             │
                     ┌───────┴──────┐
                     │              │
                     ▼              ▼
                [DRY RUN]      [LIVE MODE]
                     │              │
                     ▼              ▼
                Simulate      Continue
                Log Only           │
                     │              ▼
                     │   ┌──────────────────────┐
                     │   │ Layer 3: Confirm     │
                     │   │ Show modal dialog    │
                     │   └──────────┬───────────┘
                     │              │
                     │      ┌───────┴──────┐
                     │      │              │
                     │      ▼              ▼
                     │   Cancel        Confirm
                     │      │              │
                     └──────┴──────┐       │
                                   │       │
                                   ▼       ▼
                              End     Continue
                                          │
                                          ▼
                               ┌──────────────────────┐
                               │ Layer 4: Rate Limit  │
                               │ Check action count   │
                               └──────────┬───────────┘
                                          │
                                  ┌───────┴──────┐
                                  │              │
                                  ▼              ▼
                              Exceeded      Within Limit
                                  │              │
                                  ▼              ▼
                              ⚠️ Alert      Continue
                              "Rate limit        │
                              exceeded"          │
                                                 ▼
                                      ┌──────────────────────┐
                                      │ Layer 5: Validation  │
                                      │ Check payload safety │
                                      └──────────┬───────────┘
                                                 │
                                         ┌───────┴──────┐
                                         │              │
                                         ▼              ▼
                                    Dangerous      Safe
                                         │              │
                                         ▼              ▼
                                     ⚠️ Block      Continue
                                     (unless lab)       │
                                                        ▼
                                             ┌──────────────────────┐
                                             │ Layer 6: Execute     │
                                             │ Perform action       │
                                             │ Log to audit         │
                                             └──────────────────────┘
```

---

## 📊 State Transitions

```
┌─────────────────┐
│  INSTALLED      │ Initial state after loading extension
└────────┬────────┘
         │
         │ User opens popup
         ▼
┌─────────────────┐
│  IDLE           │ Waiting for user interaction
└────────┬────────┘
         │
         │ User clicks "Scan Page"
         ▼
┌─────────────────┐
│  SCANNING       │ loading = true
└────────┬────────┘
         │
         │ Content script responds
         ▼
┌─────────────────┐
│  SCANNED        │ elements populated, loading = false
└────────┬────────┘
         │
         │ User selects elements & payload
         │ User clicks "Run Test"
         ▼
┌─────────────────┐
│  CONFIRMING     │ (LIVE mode only)
└────────┬────────┘
         │
         │ User confirms
         ▼
┌─────────────────┐
│  EXECUTING      │ Sending payloads
└────────┬────────┘
         │
         │ Results received
         ▼
┌─────────────────┐
│  COMPLETED      │ Show results, update logs
└────────┬────────┘
         │
         │ Back to IDLE
         ▼
┌─────────────────┐
│  IDLE           │
└─────────────────┘
```

---

## 🎨 Visual Design System

```
┌─────────────────────────────────────────────────────────┐
│                   COLOR PALETTE                          │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Primary:    #667eea  ████████  Purple-blue             │
│  Secondary:  #764ba2  ████████  Deep purple             │
│                                                           │
│  Success:    #4CAF50  ████████  Green                   │
│  Warning:    #FF9800  ████████  Orange                  │
│  Error:      #f44336  ████████  Red                     │
│  Info:       #2196F3  ████████  Blue                    │
│                                                           │
│  Text:       #333333  ████████  Dark gray               │
│  Muted:      #999999  ████████  Light gray              │
│  Background: #f5f5f5  ████████  Off-white               │
│                                                           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   TYPOGRAPHY                             │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Headings:  16-24px, bold, #667eea                      │
│  Body:      14px, normal, #333333                       │
│  Small:     12px, normal, #999999                       │
│  Code:      Monaco, Courier, monospace                  │
│                                                           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   SPACING                                │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  xs:   4px                                               │
│  sm:   8px                                               │
│  md:   16px                                              │
│  lg:   24px                                              │
│  xl:   32px                                              │
│                                                           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   COMPONENTS                             │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Button:                                                 │
│  ┌──────────────┐                                       │
│  │ 🔍 Scan Page │  Primary: gradient bg, white text    │
│  └──────────────┘  Secondary: white bg, gray text      │
│                                                           │
│  Badge:                                                  │
│  ┌─────┐                                                │
│  │ DRY │  Orange bg, white text, rounded               │
│  └─────┘                                                │
│                                                           │
│  Card:                                                   │
│  ┌────────────────────────────────┐                     │
│  │ 📝 input  username             │ White bg, shadow   │
│  │ ID: username                   │ Rounded corners    │
│  │ Required                       │ Hover effect       │
│  └────────────────────────────────┘                     │
│                                                           │
│  Modal:                                                  │
│  ┌────────────────────────────────┐                     │
│  │ ⚠️ Confirm Action              │ Overlay + card     │
│  │                                │                     │
│  │ Execute XSS Test on "username"?│                     │
│  │                                │                     │
│  │  [ ✓ Confirm ]  [ ✗ Cancel ]  │                     │
│  └────────────────────────────────┘                     │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## 🧬 Enhanced Extraction Architecture (v1.1)

```
┌──────────────────────────────────────────────────────────────┐
│ Popup (React)                                                 │
│  Scan tab ── scanPage ──┐         Recon tab ── getPageRecon ──┐│
│  (tag badges)           │                                     ││
│                         │   activeRecon / probeEndpoint ──────┼┼──► Background
└─────────────────────────┼─────────────────────────────────────┘│   (gated GET:
                          │                                       │    allowlist →
              chrome.tabs.sendMessage                             │    dry-run →
                          ▼                                       │    rate-limit →
┌──────────────────────────────────────────────────────────────┐│    audit)
│ Content Script (thin adapter)                                 ││      │
│   scanPage()  ─────────────► collectFields(document.body)     ││      ▼ fetch GET
│   getPageRecon() ──────────► extractPageRecon({doc, win})     ││  robots.txt,
│   extractPageSource()                                          ││  sitemap.xml,
└──────────────────────────┬───────────────────────────────────┘│  security.txt
                           │                                      │
                           ▼                                      │
┌──────────────────────────────────────────────────────────────┐│
│ src/utils/extraction.js  (PURE — jsdom-tested)               ││
│   • extractFieldMetadata  → rich per-field object             ││
│   • computeTags           → attack-surface tags[]            ││
│   • collectFields         → light + shadow DOM + iframes     ││
│   • extractPageRecon      → passive recon (NO requests)      ││
│ src/utils/reconHelpers.js (PURE) → URL build / same-origin /  ││
│   isHostAllowed gating                                        ││
└──────────────────────────────────────────────────────────────┘
```

**Key boundary:** all DOM→data logic lives in pure modules (`extraction.js`,
`reconHelpers.js`) with no `chrome.*` calls, so it is unit-tested under jsdom.
The content script and background worker are thin, chrome-coupled adapters.
Active recon is GET-only and gated (allowlist → dry-run → rate-limit → audit).

---

**Generated:** December 2, 2024 (v1.1 extraction section added)  
**Document:** Architecture & Diagrams for SecTest Pro  
**Version:** 1.1.0
