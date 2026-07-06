/* eslint-disable no-empty */
// Pure DOM -> data extraction helpers for SecTest Pro.
//
// This module deliberately contains NO chrome.* calls and no side effects on
// the page, so it can be unit-tested under jsdom and reused by the content
// script. Functions take DOM elements / documents and return plain objects.

import { findSecrets } from './secrets';
import { mapSinks } from './sinks';

/**
 * Resolve a human-readable label for a form field, trying the most reliable
 * sources first:
 *   1. <label for="id">  (explicit association)
 *   2. wrapping <label>  (implicit association)
 *   3. aria-label
 *   4. placeholder
 * Returns '' when no source is available.
 */
export function resolveLabel(el) {
  if (!el) return '';

  // 1. Explicit <label for="...">
  if (el.id) {
    try {
      const escaped =
        typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(el.id) : el.id;
      const explicit = el.ownerDocument.querySelector(`label[for="${escaped}"]`);
      if (explicit && explicit.textContent.trim()) {
        return explicit.textContent.trim();
      }
    } catch (_) {
      /* invalid selector – ignore and continue */
    }
  }

  // 2. Wrapping <label>
  const wrapping = el.closest && el.closest('label');
  if (wrapping && wrapping.textContent.trim()) {
    return wrapping.textContent.trim();
  }

  // 3. aria-label
  const aria = el.getAttribute && el.getAttribute('aria-label');
  if (aria && aria.trim()) return aria.trim();

  // 4. placeholder
  const placeholder = el.getAttribute && el.getAttribute('placeholder');
  if (placeholder && placeholder.trim()) return placeholder.trim();

  return '';
}

// ---------------------------------------------------------------------------
// Attack-surface tagging
// ---------------------------------------------------------------------------
// Heuristic name lists. Tokens are matched against the field name split on
// common separators (_ - . space) so we match whole tokens, not substrings
// (e.g. "video" must NOT match "id").

const CSRF_TOKEN_NAMES = [
  'csrf',
  'csrf_token',
  'csrftoken',
  'csrfmiddlewaretoken',
  'xsrf',
  'xsrf-token',
  'xsrf_token',
  '_csrf',
  '_token',
  'authenticity_token',
  '__requestverificationtoken',
  'requestverificationtoken',
];

const REDIRECT_PARAM_NAMES = [
  'url',
  'next',
  'redirect',
  'redirect_uri',
  'redirecturl',
  'redirect_url',
  'return',
  'returnurl',
  'return_url',
  'returnto',
  'dest',
  'destination',
  'continue',
  'callback',
  'goto',
  'forward',
];

const ID_PARAM_NAMES = [
  'id',
  'uid',
  'pid',
  'user_id',
  'userid',
  'account',
  'account_id',
  'accountid',
  'order_id',
  'orderid',
  'doc_id',
  'docid',
  'object_id',
  'objectid',
  'record_id',
  'item_id',
];

const SEARCH_NAMES = ['q', 's', 'query', 'search', 'keyword', 'keywords', 'term'];

const EMAIL_NAME_HINTS = ['email', 'e_mail', 'mail'];

// Split a field name into lowercase tokens for whole-token matching.
function nameTokens(name) {
  return String(name || '')
    .toLowerCase()
    .split(/[_\-.\s]+/)
    .filter(Boolean);
}

// True when the full (normalised) name matches a list entry, OR any single
// token of the name matches. This catches both "csrf_token" (full) and
// "user_id" -> token "id".
function nameMatches(name, list) {
  const lower = String(name || '').toLowerCase();
  if (list.includes(lower)) return true;
  const tokens = nameTokens(name);
  return tokens.some((t) => list.includes(t));
}

/**
 * Compute attack-surface tags for a field, given its extracted metadata.
 * Returns a de-duplicated array of tag strings.
 */
export function computeTags(meta = {}) {
  const tags = new Set();
  const subType = (meta.subType || '').toLowerCase();
  const name = meta.name || '';

  if (meta.hidden) tags.add('hidden');

  if (meta.hidden && nameMatches(name, CSRF_TOKEN_NAMES)) {
    tags.add('csrf-token');
  }

  if (meta.type === 'file' || subType === 'file') tags.add('file-upload');

  if (subType === 'password') tags.add('password');

  if (subType === 'email' || nameMatches(name, EMAIL_NAME_HINTS)) {
    tags.add('email');
  }

  if (subType === 'search' || nameMatches(name, SEARCH_NAMES)) {
    tags.add('search');
  }

  if (nameMatches(name, REDIRECT_PARAM_NAMES)) tags.add('redirect-param');

  if (nameMatches(name, ID_PARAM_NAMES)) tags.add('id-param');

  // "unvalidated": a free-text field with no client-side validation. Only
  // meaningful for text-like inputs and textareas.
  const textLike =
    meta.type === 'textarea' ||
    (meta.type === 'input' &&
      ['text', 'search', 'url', 'tel', ''].includes(subType));
  const hasValidation =
    meta.pattern != null ||
    meta.maxlength != null ||
    meta.minlength != null;
  if (textLike && !hasValidation) tags.add('unvalidated');

  return Array.from(tags);
}

// Numeric attribute helper: returns the parsed integer or undefined when the
// attribute is absent (so callers can omit it from the output object).
function intAttr(el, attr) {
  if (!el.hasAttribute(attr)) return undefined;
  const n = parseInt(el.getAttribute(attr), 10);
  return Number.isNaN(n) ? undefined : n;
}

// String attribute helper: returns the value or undefined when absent.
function strAttr(el, attr) {
  return el.hasAttribute(attr) ? el.getAttribute(attr) : undefined;
}

// Attach only-defined properties to keep output objects free of null/undefined
// noise (tests assert undefined for unset constraints).
function assignDefined(target, source) {
  for (const [k, v] of Object.entries(source)) {
    if (v !== undefined) target[k] = v;
  }
  return target;
}

/**
 * Extract rich metadata from a single field element (input / textarea / select
 * / contenteditable). Returns a plain, serialisable object.
 */
export function extractFieldMetadata(el) {
  if (!el) return null;
  const tag = el.tagName ? el.tagName.toLowerCase() : '';

  const base = {
    name: el.getAttribute && el.getAttribute('name') ? el.getAttribute('name') : '',
    id: el.id || '',
    required: !!(el.required || (el.hasAttribute && el.hasAttribute('required'))),
    readonly: !!(el.readOnly || (el.hasAttribute && el.hasAttribute('readonly'))),
    disabled: !!(el.disabled || (el.hasAttribute && el.hasAttribute('disabled'))),
  };

  let meta;

  if (tag === 'textarea') {
    meta = {
      ...base,
      type: 'textarea',
      subType: 'textarea',
      placeholder: el.getAttribute('placeholder') || '',
      value: el.value != null ? el.value : '',
      hidden: el.hasAttribute('hidden'),
    };
    assignDefined(meta, {
      maxlength: intAttr(el, 'maxlength'),
      minlength: intAttr(el, 'minlength'),
      autocomplete: strAttr(el, 'autocomplete'),
    });
  } else if (tag === 'select') {
    meta = {
      ...base,
      type: 'select',
      subType: 'select',
      options: Array.from(el.options || []).map((o) => o.value),
      selectedValue: el.value,
      hidden: el.hasAttribute('hidden'),
    };
    assignDefined(meta, { autocomplete: strAttr(el, 'autocomplete') });
  } else if (
    tag === 'input' &&
    (el.getAttribute('type') || 'text').toLowerCase() === 'file'
  ) {
    meta = {
      ...base,
      type: 'file',
      subType: 'file',
      accept: el.getAttribute('accept') || '*',
      multiple: !!(el.multiple || el.hasAttribute('multiple')),
      hidden: el.hasAttribute('hidden'),
    };
  } else if (tag === 'input') {
    const subType = (el.getAttribute('type') || 'text').toLowerCase();
    meta = {
      ...base,
      type: 'input',
      subType,
      placeholder: el.getAttribute('placeholder') || '',
      value: el.value != null ? el.value : '',
      hidden: subType === 'hidden' || el.hasAttribute('hidden'),
    };
    assignDefined(meta, {
      maxlength: intAttr(el, 'maxlength'),
      minlength: intAttr(el, 'minlength'),
      pattern: strAttr(el, 'pattern'),
      min: strAttr(el, 'min'),
      max: strAttr(el, 'max'),
      step: strAttr(el, 'step'),
      autocomplete: strAttr(el, 'autocomplete'),
    });
  } else {
    // contenteditable or other custom field
    meta = {
      ...base,
      type: 'contenteditable',
      subType: 'contenteditable',
      value: el.textContent != null ? el.textContent : '',
      hidden: el.hasAttribute('hidden'),
    };
  }

  // Form association (only when the element belongs to a <form>).
  const form = el.form || (el.closest && el.closest('form'));
  if (form) {
    assignDefined(meta, {
      formAction: form.getAttribute('action') || '',
      formMethod: (form.getAttribute('method') || 'get').toLowerCase(),
      formEnctype:
        form.getAttribute('enctype') ||
        'application/x-www-form-urlencoded',
    });
  }

  // Resolved label.
  const label = resolveLabel(el);
  if (label) meta.label = label;

  // Attack-surface tags computed from the assembled metadata.
  meta.tags = computeTags(meta);

  return meta;
}

// ---------------------------------------------------------------------------
// Deep DOM traversal
// ---------------------------------------------------------------------------

const FIELD_SELECTOR =
  'input, textarea, select, [contenteditable=""], [contenteditable="true"]';

/**
 * Walk a root (Document/Element/ShadowRoot) collecting every field, descending
 * into open shadow roots and same-origin iframes. Returns:
 *   { fields: [...metadata with uniqueId & context], unscannable: { crossOriginFrames } }
 *
 * Closed shadow roots and cross-origin iframes cannot be read from script;
 * cross-origin frames are counted, closed shadow roots are inherently invisible.
 */
export function collectFields(root, options = {}) {
  const scanId = options.scanId || Date.now();
  const fields = [];
  const unscannable = { crossOriginFrames: 0 };
  let counter = 0;

  const pushField = (el, context) => {
    const meta = extractFieldMetadata(el);
    if (!meta) return;
    meta.context = context;
    meta.uniqueId = `${meta.type}_${counter++}_${scanId}`;
    // Keep a live DOM reference for later injection (stripped before messaging
    // by the content-script adapter, exactly as the original scanner did).
    meta.element = el;
    fields.push(meta);
  };

  const walk = (node, context) => {
    if (!node) return;

    // Query fields directly within this root.
    let matches = [];
    try {
      matches = Array.from(node.querySelectorAll(FIELD_SELECTOR));
    } catch (_) {}
    for (const el of matches) {
      pushField(el, context);
    }

    // Descend into open shadow roots of every element in this root.
    let allEls = [];
    try {
      allEls = Array.from(node.querySelectorAll('*'));
    } catch (_) {}
    for (const el of allEls) {
      const sr = el.shadowRoot; // null for closed roots and non-hosts
      if (sr) {
        walk(sr, 'shadow');
      }
    }

    // Descend into iframes (same-origin only).
    let frames = [];
    try {
      frames = Array.from(node.querySelectorAll('iframe, frame'));
    } catch (_) {}
    for (const frame of frames) {
      let doc = null;
      try {
        doc = frame.contentDocument;
      } catch (_) {
        // Accessing contentDocument throws for cross-origin frames.
        unscannable.crossOriginFrames++;
        continue;
      }
      if (doc && doc.body) {
        walk(doc.body, 'iframe');
      } else if (doc === null) {
        // Some cross-origin frames return null rather than throwing.
        unscannable.crossOriginFrames++;
      }
    }
  };

  walk(root, options.context || 'light');

  return { fields, unscannable };
}

// ---------------------------------------------------------------------------
// Passive page recon (read-only — no network requests)
// ---------------------------------------------------------------------------

// Endpoint patterns: absolute paths beginning with /api or similar, and fully
// qualified http(s) URLs, found inside string literals.
const URL_RE = /https?:\/\/[^\s"'`<>()]+/g;
const PATH_RE = /['"`](\/[A-Za-z0-9_\-./]*\/[A-Za-z0-9_\-./]*)['"`]/g;

/**
 * Find candidate endpoints (paths and URLs) inside a blob of JS/text.
 * De-duplicated. Pure string analysis — does not fetch anything.
 */
export function findInlineEndpoints(source) {
  if (!source || typeof source !== 'string') return [];
  const found = new Set();

  let m;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(source))) {
    found.add(m[0].replace(/[.,;)]+$/, ''));
  }

  PATH_RE.lastIndex = 0;
  while ((m = PATH_RE.exec(source))) {
    found.add(m[1]);
  }

  return Array.from(found);
}

/**
 * Analyze a blob of script text for all passive signals at once: candidate
 * endpoints, likely secrets (masked), and DOM-XSS sinks. Shared by the passive
 * page recon (inline scripts) and the deep-JS scan (external same-origin
 * scripts) so both surface the same signal set. Pure — fetches nothing.
 */
export function analyzeScriptSource(source) {
  const src = typeof source === 'string' ? source : '';
  return {
    endpoints: findInlineEndpoints(src),
    secrets: findSecrets(src),
    sinks: mapSinks(src),
  };
}

// Framework detection: window globals + script-src filename hints.
const FRAMEWORK_GLOBALS = [
  ['React', 'React'],
  ['ReactDOM', 'React'],
  ['Vue', 'Vue'],
  ['ng', 'Angular'],
  ['angular', 'Angular'],
  ['jQuery', 'jQuery'],
  ['$', 'jQuery'],
  ['Svelte', 'Svelte'],
  ['__NEXT_DATA__', 'Next.js'],
  ['__NUXT__', 'Nuxt'],
];

const FRAMEWORK_SRC_HINTS = [
  [/react(\.|-|@)/i, 'React'],
  [/vue(\.|-|@)/i, 'Vue'],
  [/angular(\.|-|@)/i, 'Angular'],
  [/jquery(\.|-|@)/i, 'jQuery'],
  [/svelte/i, 'Svelte'],
  [/\bnext\b|_next\//i, 'Next.js'],
];

/**
 * Identify front-end frameworks present on the page via window globals and
 * <script src> hints. Returns a de-duplicated array of names.
 */
export function fingerprintFrameworks(windowRef = {}, documentRef) {
  const names = new Set();

  for (const [global, label] of FRAMEWORK_GLOBALS) {
    try {
      if (windowRef && windowRef[global] != null) names.add(label);
    } catch (_) {}
  }

  if (documentRef && documentRef.querySelectorAll) {
    let scripts = [];
    try {
      scripts = Array.from(documentRef.querySelectorAll('script[src]'));
    } catch (_) {}
    for (const s of scripts) {
      const src = s.getAttribute('src') || '';
      for (const [re, label] of FRAMEWORK_SRC_HINTS) {
        if (re.test(src)) names.add(label);
      }
    }
  }

  return Array.from(names);
}

// Collect HTML comment text nodes from a document.
function collectComments(documentRef) {
  const comments = [];
  if (!documentRef || !documentRef.createNodeIterator) return comments;
  try {
    // NodeFilter.SHOW_COMMENT === 128
    const iter = documentRef.createNodeIterator(
      documentRef.documentElement || documentRef.body,
      128
    );
    let node;
    while ((node = iter.nextNode())) {
      const text = (node.nodeValue || '').trim();
      if (text) comments.push(text);
    }
  } catch (_) {}
  return comments;
}

// Read storage keys (names only, never values).
function storageKeys(store) {
  const keys = [];
  if (!store) return keys;
  try {
    const len = store.length || 0;
    for (let i = 0; i < len; i++) {
      const k = store.key(i);
      if (k != null) keys.push(k);
    }
  } catch (_) {}
  return keys;
}

/**
 * Assemble a passive recon snapshot of the page. Reads only what is already in
 * the loaded document/window — it issues NO network requests.
 *
 * @param {{documentRef: Document, windowRef: Window}} refs
 */
export function extractPageRecon({ documentRef, windowRef = {} } = {}) {
  const doc = documentRef;
  const recon = {
    title: (doc && doc.title) || '',
    url: (windowRef && windowRef.location && windowRef.location.href) || '',
    meta: {},
    comments: [],
    endpoints: [],
    secrets: [],
    sinks: [],
    forms: [],
    links: [],
    buttonCount: 0,
    cookieNames: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    frameworks: [],
  };

  if (!doc) return recon;

  // Meta tags (name -> content).
  let metas = [];
  try {
    metas = Array.from(doc.querySelectorAll('meta[name]'));
  } catch (_) {}
  for (const meta of metas) {
    const name = meta.getAttribute('name');
    if (name) recon.meta[name] = meta.getAttribute('content') || '';
  }

  // HTML comments.
  recon.comments = collectComments(doc);

  // Inline-script endpoints.
  let scripts = [];
  try {
    scripts = Array.from(doc.querySelectorAll('script:not([src])'));
  } catch (_) {}
  const endpointSet = new Set();
  const secretKeys = new Set();
  for (const s of scripts) {
    const { endpoints, secrets, sinks } = analyzeScriptSource(s.textContent || '');
    for (const ep of endpoints) endpointSet.add(ep);
    for (const sec of secrets) {
      const key = sec.type + ':' + sec.preview;
      if (!secretKeys.has(key)) {
        secretKeys.add(key);
        recon.secrets.push(sec);
      }
    }
    for (const sink of sinks) recon.sinks.push(sink);
  }
  recon.endpoints = Array.from(endpointSet);

  // Form summary.
  let forms = [];
  try {
    forms = Array.from(doc.querySelectorAll('form'));
  } catch (_) {}
  recon.forms = forms.map((f) => ({
    action: f.getAttribute('action') || '',
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    enctype: f.getAttribute('enctype') || 'application/x-www-form-urlencoded',
    fieldCount: f.querySelectorAll('input, textarea, select').length,
  }));

  // Links + buttons.
  let links = [];
  try {
    links = Array.from(doc.querySelectorAll('a[href]'));
  } catch (_) {}
  recon.links = Array.from(new Set(links.map((a) => a.getAttribute('href')).filter(Boolean)));
  try {
    recon.buttonCount = doc.querySelectorAll(
      'button, input[type="button"], input[type="submit"]'
    ).length;
  } catch (_) {}

  // Cookie names only (HttpOnly cookies are invisible to JS — noted limitation).
  try {
    const raw = doc.cookie || '';
    recon.cookieNames = raw
      .split(';')
      .map((c) => c.split('=')[0].trim())
      .filter(Boolean);
  } catch (_) {}

  // Storage keys (names only). Reading the localStorage/sessionStorage getter
  // can itself throw a SecurityError when storage is blocked (e.g. Brave
  // Shields, sandboxed/opaque-origin documents), so guard the property access
  // — not just the helper — and degrade gracefully instead of aborting recon.
  let ls = null;
  let ss = null;
  try {
    ls = windowRef.localStorage;
  } catch (_) {}
  try {
    ss = windowRef.sessionStorage;
  } catch (_) {}
  recon.localStorageKeys = storageKeys(ls);
  recon.sessionStorageKeys = storageKeys(ss);

  // Frameworks.
  recon.frameworks = fingerprintFrameworks(windowRef, doc);

  return recon;
}
