// DOM-XSS sink mapping — pure, unit-testable (no chrome.*/network).
//
// Static, heuristic analysis of JS text: it locates dangerous DOM *sinks* (places
// where a string becomes markup/code) and notes any controllable *sources*
// (location, referrer, postMessage, …) nearby. A sink fed by a source is a
// candidate DOM-XSS worth MANUAL review — this module never claims a bug, it
// only points a human at the interesting lines.
//
// Purely analytical: it inspects text you already loaded. It fetches nothing.

// Sinks: string → markup / code / navigation.
const SINK_PATTERNS = [
  { sink: 'innerHTML', re: /\.innerHTML\s*=/ },
  { sink: 'outerHTML', re: /\.outerHTML\s*=/ },
  { sink: 'insertAdjacentHTML', re: /\.insertAdjacentHTML\s*\(/ },
  { sink: 'document.write', re: /\bdocument\.write(?:ln)?\s*\(/ },
  { sink: 'eval', re: /\beval\s*\(/ },
  { sink: 'Function', re: /\bnew\s+Function\s*\(/ },
  { sink: 'setTimeout(string)', re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/ },
  { sink: 'jquery.html', re: /\$\([^)]*\)\.html\s*\(/ },
  { sink: 'location.assign', re: /\blocation\s*(?:\.href)?\s*=|\blocation\.(?:assign|replace)\s*\(/ },
  { sink: 'script.src', re: /\.src\s*=\s*[^;]*(?:location|search|hash|referrer|params)/i },
];

// Sources: attacker-controllable inputs.
const SOURCE_PATTERNS = [
  { source: 'location', re: /\blocation\.(?:href|search|hash|pathname)\b|\bdocument\.(?:URL|documentURI)\b/ },
  { source: 'referrer', re: /\bdocument\.referrer\b/ },
  { source: 'window.name', re: /\bwindow\.name\b/ },
  { source: 'postMessage', re: /\b(?:onmessage|addEventListener\s*\(\s*["']message["'])|\bevent\.data\b|\be\.data\b/ },
  { source: 'cookie', re: /\bdocument\.cookie\b/ },
  { source: 'URLSearchParams', re: /\bURLSearchParams\b|\.searchParams\b/ },
];

const PROXIMITY_LINES = 2; // how far to look for a source around a sink

function sourcesNear(lines, idx) {
  const found = new Set();
  const lo = Math.max(0, idx - PROXIMITY_LINES);
  const hi = Math.min(lines.length - 1, idx + PROXIMITY_LINES);
  for (let i = lo; i <= hi; i++) {
    for (const { source, re } of SOURCE_PATTERNS) {
      if (re.test(lines[i])) found.add(source);
    }
  }
  return Array.from(found);
}

/**
 * Map DOM-XSS sinks in a blob of JS/text.
 * @returns {{sink:string, line:number, snippet:string, sources:string[]}[]}
 *   `sources` is non-empty when a controllable source sits within a couple of
 *   lines of the sink — i.e. a higher-priority manual-review candidate.
 */
export function mapSinks(source) {
  if (!source || typeof source !== 'string') return [];
  const lines = source.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { sink, re } of SINK_PATTERNS) {
      if (re.test(line)) {
        out.push({
          sink,
          line: i + 1,
          snippet: line.trim().slice(0, 200),
          sources: sourcesNear(lines, i),
        });
      }
    }
  }
  return out;
}

/** True when a mapped sink has a controllable source nearby (tainted candidate). */
export function isTaintedSink(entry) {
  return Boolean(entry && Array.isArray(entry.sources) && entry.sources.length);
}

export { SINK_PATTERNS, SOURCE_PATTERNS };
