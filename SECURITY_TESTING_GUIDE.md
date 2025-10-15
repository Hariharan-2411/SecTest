# SecTest Pro - Security Testing Extension

## Overview
SecTest Pro is a professional Chrome MV3 extension designed for security testing of web applications. It provides comprehensive form enumeration, payload injection capabilities, and robust guardrails to ensure safe testing practices.

## Features

### Phase 1: Scan & Surface (MVP)
- **Form Element Enumeration**: Automatically detects and catalogs:
  - `<input>` fields (all types)
  - `<textarea>` elements
  - `<select>` dropdowns
  - File upload inputs
- **Test Actions**:
  - Insert Test Marker: Adds unique timestamped markers to form fields
  - Attach Harmless XML: Injects or attaches safe XML payloads
- **No Auto-Submit**: All actions are manual; no automatic form submissions

### Phase 2: Guardrails & Telemetry
- **Host Allowlist**: Per-host permission system
  - Only operates on explicitly allowed domains
  - Default sanctioned labs: localhost, 127.0.0.1, dvwa, webgoat
- **Dry Run Mode**: Safe testing mode enabled by default
  - Simulates actions without actual execution
  - Explicit confirmation dialogs in LIVE mode
- **Immutable Audit Log**: Comprehensive logging of all actions
  - Timestamp, URL, action type, element details, results
  - Export functionality for compliance and analysis
- **Rate Limiting**: Maximum 20 actions per minute to prevent abuse
- **Payload Validation**: Blocks dangerous patterns including:
  - `<script>` tags
  - JavaScript event handlers
  - SQL injection keywords (DROP, DELETE, INSERT, UPDATE, UNION)
  - Path traversal attempts
  - Exception: Sanctioned lab targets bypass restrictions

### Phase 3: Package & Validate
- **Test Reporter**: Automated coverage reporting
  - Elements found (by type)
  - Actions performed
  - Success/failure tracking
- **Screenshot Capture**: Before/after visual documentation
- **DOM Snapshots**: Full page state preservation
- **Coverage Reports**: Exportable JSON and HTML formats

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the extension:
   ```bash
   npm run build
   ```
4. Load in Chrome:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `build` directory

## Usage

### Initial Setup
1. Click the extension icon in Chrome toolbar
2. Open Settings (⚙️ button)
3. Configure host allowlist:
   - Add domains you want to test (e.g., `localhost`, `dvwa`)
   - Remove domains you don't need
4. Set Dry Run Mode preference:
   - ✅ Enabled (default): Safe simulation mode
   - ❌ Disabled: Live testing with confirmation dialogs

### Scanning a Page
1. Navigate to your target web application
2. Click the extension icon
3. Click "🔍 Scan Page"
4. Review the enumerated form elements

### Performing Actions
1. After scanning, each element displays available actions:
   - **📝 Insert Marker**: Adds a unique test marker like `[TEST_1697234567890]`
   - **📎 Attach XML**: Injects/attaches harmless XML payload

2. In Dry Run Mode:
   - Actions are simulated and logged
   - No actual changes to the page

3. In Live Mode:
   - Confirmation dialog appears before each action
   - Actions are executed and logged

### Audit Log
- View log entry count in Settings
- Export log as JSON for analysis
- Each entry includes:
  - Timestamp (ISO 8601 format)
  - Action performed
  - Target URL
  - Element details
  - Result status
  - Dry run flag

## Testing Workflow

### Recommended Testing Process

1. **Setup Phase**
   ```
   - Add target hosts to allowlist
   - Enable Dry Run mode
   - Clear audit log (optional)
   ```

2. **Discovery Phase**
   ```
   - Navigate to each page/form
   - Scan page
   - Review element catalog
   - Export coverage data
   ```

3. **Testing Phase**
   ```
   - Disable Dry Run (if authorized)
   - Execute test actions
   - Confirm each action
   - Monitor results
   ```

4. **Documentation Phase**
   ```
   - Capture screenshots
   - Export audit log
   - Generate coverage report
   - Review findings
   ```

### Testing with DVWA

[Damn Vulnerable Web Application](https://github.com/digininja/DVWA) is perfect for testing:

1. Setup DVWA locally:
   ```bash
   docker run --rm -it -p 80:80 vulnerables/web-dvwa
   ```

2. Add to allowlist:
   - `localhost`
   - `127.0.0.1`
   - `dvwa` (if using custom hosts)

3. Test various forms:
   - Login page
   - SQL Injection
   - XSS (Stored/Reflected)
   - File Upload
   - Command Injection

### Testing with WebGoat

1. Setup WebGoat:
   ```bash
   docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat
   ```

2. Add `localhost:8080` to allowlist

3. Test lessons systematically

## Rate Limiting

The extension enforces a rate limit of **20 actions per minute** to prevent:
- Accidental DoS conditions
- Excessive automated testing
- Unintended system impact

If rate limit is reached:
- Wait 60 seconds
- Or reload the extension to reset counter

## Security Considerations

### ⚠️ Important Warnings

1. **Authorization Required**: Only test applications you own or have explicit permission to test
2. **Production Systems**: Never test production systems without proper authorization
3. **Data Handling**: Be cautious with sensitive data in test environments
4. **Legal Compliance**: Understand local laws regarding security testing

### Safe Usage Guidelines

✅ **DO:**
- Test in isolated lab environments
- Use Dry Run mode for exploration
- Keep audit logs for accountability
- Add only authorized hosts to allowlist
- Document all testing activities

❌ **DON'T:**
- Test production systems without authorization
- Disable guardrails on untrusted sites
- Share credentials or sensitive data
- Bypass rate limiting mechanisms
- Test systems you don't own

## Integration with Ollama LLM (Phase 4 - Future)

Once core functionality is validated, the extension will integrate with locally deployed Ollama models to provide:

- **Intelligent Payload Generation**: Context-aware test payloads
- **Vulnerability Suggestions**: ML-based vulnerability identification
- **Test Strategy Recommendations**: Adaptive testing approaches
- **Natural Language Interface**: Describe tests in plain English

### Planned Features:
```javascript
// Example future integration
const payloadAssistant = {
  async generatePayload(context) {
    const response = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      body: JSON.stringify({
        model: 'llama2',
        prompt: `Generate a security test payload for: ${context}`
      })
    });
    return response.json();
  }
};
```

## Architecture

### Components

```
┌─────────────────────────────────────────────────────┐
│                   Chrome Extension                   │
├─────────────────────────────────────────────────────┤
│                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │   Popup UI   │  │   Content    │  │Background │ │
│  │   (React)    │◄─┤    Script    │◄─┤  Worker   │ │
│  └──────────────┘  └──────────────┘  └───────────┘ │
│         │                 │                  │       │
│         ├─────────────────┼──────────────────┤       │
│         │                 │                  │       │
│  ┌──────▼─────────────────▼──────────────────▼────┐ │
│  │           Chrome Storage API                    │ │
│  │  (Allowlist, Audit Log, Settings)              │ │
│  └─────────────────────────────────────────────────┘ │
│                                                       │
└─────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │   Target Web    │
                  │   Application   │
                  └─────────────────┘
```

### Message Flow

1. User clicks "Scan Page" in popup
2. Popup sends message to content script
3. Content script scans DOM, returns element data
4. User performs action
5. Background worker validates (rate limit, payload check)
6. Content script executes action
7. Result logged to audit log
8. UI updated with confirmation

## Development

### Build Commands

```bash
# Development build
npm run build

# Start dev server with hot reload
npm run start

# Format code
npm run prettier
```

### File Structure

```
chrome-boiler/
├── src/
│   ├── manifest.json              # Extension manifest (MV3)
│   ├── pages/
│   │   ├── Background/
│   │   │   └── index.js          # Service worker (guardrails, rate limiting)
│   │   ├── Content/
│   │   │   └── index.js          # Form scanner, action executor
│   │   └── Popup/
│   │       ├── Popup.jsx         # React UI component
│   │       └── Popup.css         # Styling
│   └── utils/
│       └── testReporter.js       # Coverage reporting
├── build/                         # Compiled extension
└── package.json
```

## API Reference

### Content Script Messages

#### Scan Page
```javascript
chrome.tabs.sendMessage(tabId, { 
  action: 'scanPage' 
}, (response) => {
  // response.elements = array of form elements
});
```

#### Insert Test Marker
```javascript
chrome.tabs.sendMessage(tabId, {
  action: 'insertTestMarker',
  uniqueId: 'input_0_1697234567890'
}, (response) => {
  // response.success, response.message
});
```

#### Attach XML
```javascript
chrome.tabs.sendMessage(tabId, {
  action: 'attachXML',
  uniqueId: 'file_0_1697234567890'
}, (response) => {
  // response.success, response.message
});
```

### Background Worker Messages

#### Check Rate Limit
```javascript
chrome.runtime.sendMessage({
  action: 'checkRateLimit'
}, (response) => {
  // response.allowed, response.remaining
});
```

#### Validate Payload
```javascript
chrome.runtime.sendMessage({
  action: 'validatePayload',
  payload: '<test>data</test>',
  host: 'localhost'
}, (response) => {
  // response.safe, response.reason
});
```

## Troubleshooting

### Common Issues

**Extension not working after page load**
- Refresh the target page after loading the extension
- Content scripts only inject on new page loads

**"Element not found" error**
- Re-scan the page before performing actions
- Element references are tied to specific scan sessions

**Rate limit exceeded**
- Wait 60 seconds for counter to reset
- Or reload the extension

**Host not allowed**
- Add the current hostname to allowlist in Settings
- Check that hostname exactly matches (including subdomains)

**Actions not executing in Live mode**
- Confirm the action in the dialog
- Check browser console for errors
- Verify element is still present on page

## License

MIT License - See LICENSE file for details

## Contributing

This is a security testing tool. Contributions should:
1. Maintain or enhance security guardrails
2. Improve testing capabilities
3. Add better logging/reporting
4. Follow existing code style

## Disclaimer

This tool is designed for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before testing any web application. Unauthorized testing may be illegal and unethical.

The authors assume no liability for misuse of this tool.

---

**Version**: 1.0.0  
**Last Updated**: 2025-10-14  
**Status**: Production Ready
