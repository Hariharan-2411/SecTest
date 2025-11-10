#!/usr/bin/env node
// Simple runner for src/utils/ollamaIntegration.js
// Checks availability, lists models, and generates a sample payload.

const path = require('path');

// Require the assistant (module.exports fallback is provided in the file)
const imported = require(path.join(__dirname, '..', 'src', 'utils', 'ollamaIntegration.js'));
// Support both ESM-like default export and CommonJS export
const OllamaPayloadAssistant = imported && imported.default ? imported.default : imported;

async function main() {
  const assistant = new OllamaPayloadAssistant('http://127.0.0.1:11434');
  console.log('Checking Ollama availability...');
  const available = await assistant.checkAvailability();
  console.log('Available:', available);
  if (!available) {
    console.error('Ollama not available. Last error:', assistant.getLastError());
    process.exitCode = 1;
    return;
  }

  console.log('\nListing available models...');
  const models = await assistant.listAvailableModels();
  console.log('Models:', models);

  console.log('\nGenerating sample payload...');
  try {
    const payload = await assistant.generatePayload({
      elementType: 'input',
      elementName: 'username',
      testType: 'SQL Injection',
      vulnerability: 'Authentication Bypass'
    });

    console.log('\nPayload result:');
    console.log('payload:', payload.payload);
    console.log('explanation:', payload.explanation);
  } catch (err) {
    console.error('Error generating payload:', err?.message || err);
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error('Unhandled error in runner:', err);
  process.exitCode = 3;
});
