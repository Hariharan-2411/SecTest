# Ollama Integration Guide for SecTest Pro

## Overview

This guide explains how to integrate SecTest Pro with Ollama for AI-assisted payload generation and vulnerability testing recommendations.

## Prerequisites

- SecTest Pro extension installed and working
- Basic understanding of LLMs and prompt engineering
- Authorization to test target systems

## Installing Ollama

### macOS

```bash
# Download and install from official website
curl -fsSL https://ollama.com/install.sh | sh

# Or using Homebrew
brew install ollama
```

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Windows

Download the installer from [ollama.com/download](https://ollama.com/download)

## Setting Up Ollama

### 1. Start Ollama Service

```bash
# Start the Ollama service (runs on port 11434 by default)
ollama serve
```

### 2. Pull Recommended Models

```bash
# Pull Llama 2 (7B model, ~4GB)
ollama pull llama2

# Or pull Llama 3 for better performance (requires more RAM)
ollama pull llama3

# For faster responses with less RAM, use Mistral
ollama pull mistral

# For specialized security testing (if available)
ollama pull codellama
```

### 3. Verify Installation

```bash
# Test the model
ollama run llama2 "Hello, world!"

# List installed models
ollama list
```

## Testing Ollama Connectivity

### Command Line Test

```bash
# Test API endpoint
curl http://localhost:11434/api/tags

# Generate test response
curl http://localhost:11434/api/generate -d '{
  "model": "llama2",
  "prompt": "Generate a simple XSS test payload",
  "stream": false
}'
```

### Browser Test

1. Open Chrome DevTools Console (F12)
2. Run this test:

```javascript
fetch('http://localhost:11434/api/tags')
  .then(r => r.json())
  .then(data => console.log('Ollama models:', data))
  .catch(err => console.error('Ollama not available:', err));
```

## Integrating with SecTest Pro

### Phase 1: Enable CORS (if needed)

If you encounter CORS errors, run Ollama with CORS enabled:

```bash
# Set environment variable
export OLLAMA_ORIGINS="chrome-extension://*"

# Start Ollama
ollama serve
```

Or create a systemd service (Linux) or LaunchDaemon (macOS) with the environment variable.

### Phase 2: Update Extension Configuration

Create a configuration file in the extension:

```javascript
// src/config/ollama.config.js
export const ollamaConfig = {
  baseUrl: 'http://localhost:11434',
  model: 'llama2',
  enabled: true,
  timeout: 30000, // 30 seconds
  options: {
    temperature: 0.7,
    top_p: 0.9,
    top_k: 40
  }
};
```

### Phase 3: Add UI Components

The Popup will include:
- "🤖 AI Assist" button for payload generation
- Model selector dropdown
- Vulnerability suggestions panel

## Usage Examples

### 1. Generate Custom Payload

```javascript
import OllamaPayloadAssistant from './utils/ollamaIntegration.js';

const assistant = new OllamaPayloadAssistant();

// Wait for availability check
await assistant.checkAvailability();

// Generate payload for specific context
const result = await assistant.generatePayload({
  elementType: 'input',
  elementName: 'username',
  testType: 'SQL Injection',
  vulnerability: 'Authentication Bypass'
});

console.log('Payload:', result.payload);
console.log('Explanation:', result.explanation);
```

### 2. Get Vulnerability Suggestions

```javascript
const element = {
  type: 'input',
  name: 'search',
  id: 'search-box',
  required: false
};

const suggestions = await assistant.suggestVulnerability(element);
console.log('Test Suggestions:', suggestions);
```

### 3. Generate Test Strategy

```javascript
const pageContext = {
  url: 'http://localhost/dvwa',
  formsFound: 5,
  inputsFound: 12,
  fileInputsFound: 2
};

const strategy = await assistant.generateTestStrategy(pageContext);
console.log('Recommended Strategy:', strategy);
```

### 4. Use Template Payloads

```javascript
const templates = assistant.getTemplatePayloads();

// Get all XSS payloads
console.log('XSS Tests:', templates.xss);

// Get SQL injection payloads
console.log('SQLi Tests:', templates.sqli);
```

## Prompt Engineering Best Practices

### Effective Prompts for Security Testing

**Good Prompt:**
```
Generate a safe SQL injection test payload for a login form username field. 
The payload should test for authentication bypass vulnerabilities in a 
controlled lab environment. Include explanation of what it tests.
```

**Bad Prompt:**
```
Give me SQL injection
```

### Context is Key

Always provide:
1. Element type and name
2. Specific vulnerability to test
3. Environment context (lab/production)
4. Expected behavior
5. Safety constraints

### Example Prompts

#### XSS Testing
```
Generate a reflected XSS test payload for a search input field that:
- Uses event handlers instead of script tags
- Tests for improper output encoding
- Is safe for authorized testing
- Includes explanation of the attack vector
```

#### File Upload Testing
```
Create a test file upload payload for testing file type validation:
- Target: Image upload field accepting .jpg, .png
- Test: Bypass using double extensions or MIME type manipulation
- Environment: DVWA lab
- Include the file header/magic bytes explanation
```

#### API Testing
```
Generate a JSON injection payload for an API endpoint that:
- Tests for improper input validation
- Attempts to inject additional fields
- Safe for authorized testing
- Explain the potential vulnerability
```

## Model Recommendations

### For General Testing (Recommended)

**Llama 2 (7B)**
- Good balance of speed and quality
- Works on systems with 8GB+ RAM
- Best for general payload generation

```bash
ollama pull llama2
```

### For Advanced Testing

**Llama 3 (8B)**
- Better understanding of security concepts
- More accurate payload generation
- Requires 16GB+ RAM

```bash
ollama pull llama3
```

### For Quick Responses

**Mistral (7B)**
- Faster inference
- Lower resource requirements
- Good for vulnerability suggestions

```bash
ollama pull mistral
```

### For Code-Focused Testing

**CodeLlama**
- Better for code injection payloads
- Understands programming contexts
- Good for API testing

```bash
ollama pull codellama
```

## Performance Optimization

### 1. Model Quantization

Use smaller quantized models for faster responses:

```bash
# 4-bit quantized model (faster, less accurate)
ollama pull llama2:7b-q4_0

# 8-bit quantized model (balanced)
ollama pull llama2:7b-q8_0
```

### 2. GPU Acceleration

If you have an NVIDIA GPU:

```bash
# Ollama automatically uses GPU if available
# Check GPU usage:
nvidia-smi

# Force CPU usage (if needed):
CUDA_VISIBLE_DEVICES=-1 ollama serve
```

### 3. Adjust Context Window

```javascript
const assistant = new OllamaPayloadAssistant();
assistant.contextLength = 2048; // Reduce for faster responses
```

## Troubleshooting

### Ollama Not Available

**Error:** "Ollama is not available"

**Solutions:**
1. Check if Ollama service is running: `ps aux | grep ollama`
2. Verify port 11434 is accessible: `curl http://localhost:11434/api/tags`
3. Check firewall settings
4. Restart Ollama: `killall ollama && ollama serve`

### CORS Errors

**Error:** "Access-Control-Allow-Origin"

**Solutions:**
1. Set OLLAMA_ORIGINS environment variable:
   ```bash
   export OLLAMA_ORIGINS="chrome-extension://*,http://localhost:*"
   ollama serve
   ```

2. Or use a local proxy:
   ```javascript
   // In background.js
   chrome.webRequest.onHeadersReceived.addListener(
     details => ({
       responseHeaders: [
         ...details.responseHeaders,
         { name: 'Access-Control-Allow-Origin', value: '*' }
       ]
     }),
     { urls: ['http://localhost:11434/*'] },
     ['blocking', 'responseHeaders']
   );
   ```

### Slow Response Times

**Issue:** Payload generation takes too long

**Solutions:**
1. Use a smaller model (mistral instead of llama3)
2. Reduce temperature and top_p values
3. Enable GPU acceleration
4. Use quantized models
5. Reduce max_tokens in request

### Model Download Issues

**Issue:** Model download fails or is incomplete

**Solutions:**
1. Check internet connection
2. Verify disk space: `df -h`
3. Clear Ollama cache: `rm -rf ~/.ollama/models`
4. Re-download: `ollama pull llama2`

## Security Considerations

### ⚠️ Important Warnings

1. **API Exposure**: Ollama runs on localhost:11434. Ensure it's not exposed to external networks.

2. **Prompt Injection**: Be careful with user-controlled input in prompts. Sanitize all inputs.

3. **Rate Limiting**: Implement rate limiting for API calls to prevent abuse.

4. **Payload Validation**: Always validate generated payloads before use. Don't blindly trust AI output.

5. **Logging**: Log all AI-generated payloads for audit purposes.

### Best Practices

✅ **DO:**
- Keep Ollama updated: `ollama update`
- Use models from official Ollama library
- Validate and sanitize all AI outputs
- Test generated payloads in safe environments first
- Log AI interactions for audit

❌ **DON'T:**
- Expose Ollama to public networks
- Use AI-generated payloads without review
- Trust AI for critical security decisions
- Skip manual validation of outputs
- Use AI in production environments without testing

## Advanced Configuration

### Custom Model Fine-Tuning

Create a custom model for security testing:

```bash
# Create Modelfile
cat > Modelfile << EOF
FROM llama2
PARAMETER temperature 0.7
PARAMETER top_p 0.9

SYSTEM """
You are a security testing assistant specialized in generating educational 
payloads for authorized penetration testing. Always:
1. Emphasize safety and authorization
2. Explain the vulnerability being tested
3. Provide safe, educational examples
4. Warn about legal and ethical considerations
"""
EOF

# Build custom model
ollama create sectest-assistant -f Modelfile

# Use in extension
assistant.setModel('sectest-assistant');
```

### Batch Processing

For testing multiple elements:

```javascript
async function batchGeneratePayloads(elements) {
  const assistant = new OllamaPayloadAssistant();
  const results = [];

  for (const element of elements) {
    const payload = await assistant.generatePayload({
      elementType: element.type,
      elementName: element.name,
      testType: 'XSS',
      vulnerability: 'Input Validation'
    });
    
    results.push({
      element: element.name,
      payload: payload.payload,
      explanation: payload.explanation
    });

    // Rate limiting
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  return results;
}
```

## Integration Roadmap

### Phase 4.1: Basic Integration
- [x] Ollama connectivity check
- [x] Simple payload generation
- [ ] Add to Popup UI
- [ ] Template payload selector

### Phase 4.2: Advanced Features
- [ ] Vulnerability suggestions per element
- [ ] Test strategy generation
- [ ] Context-aware payload tuning
- [ ] Custom model support

### Phase 4.3: AI-Powered Analysis
- [ ] Automated vulnerability detection
- [ ] Result interpretation
- [ ] Report generation with AI insights
- [ ] Learning from test outcomes

## Resources

- [Ollama Official Documentation](https://github.com/ollama/ollama/blob/main/docs/README.md)
- [Ollama Model Library](https://ollama.com/library)
- [Prompt Engineering Guide](https://www.promptingguide.ai/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Support

For issues related to:
- **Ollama**: https://github.com/ollama/ollama/issues
- **SecTest Pro**: Open an issue in the extension repository
- **Model Selection**: https://ollama.com/library

---

**Last Updated:** 2025-10-14  
**Ollama Version:** 0.1.x+  
**Compatible Models:** llama2, llama3, mistral, codellama
