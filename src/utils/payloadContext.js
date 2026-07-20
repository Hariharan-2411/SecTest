// Grounded payload context (B1) — pure, unit-testable (no chrome.*/network).
//
// The AI payload source used to send a generic stub. This assembles the OBSERVED
// surface into a compact grounding blob so Groq crafts payloads tailored to the
// target's actual stack: the detected framework (React/Angular/Vue/jQuery change
// the XSS breakout entirely), the reflection context + sink type from a real
// DOM-XSS finding, and observed param names. Keeps the back-compat fields the
// proxy already reads. Analytical only — it selects and trims existing data.

function str(v, max = 200) {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

/**
 * Build the grounding context for AI payload generation. Pure; never throws.
 * @param {string|{key?:string,label?:string}} vuln  the selected vuln family
 * @param {{inventory?:object, findings?:object[], recon?:object}} sources
 *   inventory = a SINGLE host's inventory object (endpoints/params/…)
 * @returns compact context object safe to send to the proxy
 */
export function buildPayloadContext(vuln, sources) {
  const { inventory = {}, findings = [], recon = null, priorWins = [] } =
    sources && typeof sources === 'object' ? sources : {};
  const vulnLabel =
    typeof vuln === 'string'
      ? vuln
      : (vuln && (vuln.label || vuln.key)) || '';

  const frameworks = recon && Array.isArray(recon.frameworks) ? recon.frameworks.slice(0, 4) : [];

  const xss = (Array.isArray(findings) ? findings : []).filter((f) => f && f.type === 'dom-xss');
  const withCtx = xss.find((f) => f.reflection || f.sink) || xss[0] || null;

  const inv = inventory && typeof inventory === 'object' ? inventory : {};
  const params = Array.isArray(inv.params) ? inv.params.filter((p) => typeof p === 'string').slice(0, 20) : [];

  return {
    // back-compat fields the proxy already reads
    elementType: 'input',
    elementName: '*',
    testType: 'Payload Generation',
    vulnerability: vulnLabel || 'General testing',
    // grounding
    framework: frameworks.join(', '),
    reflectionContext: withCtx ? str(withCtx.reflection, 40) : '',
    sink: withCtx ? str(withCtx.sink, 60) : '',
    params,
    // Recalled payloads that worked before on this framework/sink/vuln (B4).
    ...(Array.isArray(priorWins) && priorWins.length
      ? { priorWins: priorWins.filter((p) => typeof p === 'string').slice(0, 5).map((p) => str(p, 300)) }
      : {}),
  };
}
