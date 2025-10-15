console.log('SecTest Pro - Background Service Worker');

// Rate limiting
const rateLimiter = {
  actions: [],
  maxActionsPerMinute: 20,
  
  canPerformAction() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    // Clean old actions
    this.actions = this.actions.filter(time => time > oneMinuteAgo);
    
    if (this.actions.length >= this.maxActionsPerMinute) {
      return false;
    }
    
    this.actions.push(now);
    return true;
  },
  
  getRemainingActions() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    this.actions = this.actions.filter(time => time > oneMinuteAgo);
    return this.maxActionsPerMinute - this.actions.length;
  }
};

// Payload validator - blocks dangerous patterns
const payloadValidator = {
  dangerousPatterns: [
    /<script[\s\S]*?>/i,
    /javascript:/i,
    /on\w+\s*=/i, // Event handlers like onclick=
    /eval\s*\(/i,
    /DROP\s+TABLE/i,
    /DELETE\s+FROM/i,
    /INSERT\s+INTO/i,
    /UPDATE\s+.*SET/i,
    /UNION\s+SELECT/i,
    /exec\s*\(/i,
    /\.\.\/\.\.\//g, // Path traversal
  ],
  
  isSafe(payload, targetHost) {
    // Check if host is a sanctioned lab target
  const sanctionedLabs = ['*', 'dvwa', 'localhost', '127.0.0.1', 'google', 'webgoat', 'hackazon'];
  const isSanctioned = sanctionedLabs.includes('*') || sanctionedLabs.some(lab => targetHost.includes(lab));
    
    if (isSanctioned) {
      console.log('✓ Sanctioned lab target - allowing payload');
      return { safe: true, reason: 'Sanctioned lab target' };
    }
    
    // Check for dangerous patterns
    for (const pattern of this.dangerousPatterns) {
      if (pattern.test(payload)) {
        return { 
          safe: false, 
          reason: `Dangerous pattern detected: ${pattern.toString()}` 
        };
      }
    }
    
    return { safe: true, reason: 'Passed validation' };
  }
};

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkRateLimit') {
    const canPerform = rateLimiter.canPerformAction();
    const remaining = rateLimiter.getRemainingActions();
    
    sendResponse({ 
      allowed: canPerform, 
      remaining: remaining,
      message: canPerform ? 'Action allowed' : 'Rate limit exceeded'
    });
    return true;
  }
  
  if (request.action === 'validatePayload') {
    const validation = payloadValidator.isSafe(request.payload, request.host);
    sendResponse(validation);
    return true;
  }
});

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('SecTest Pro installed');
  
  chrome.storage.local.get(['allowlist', 'dryRunMode', 'auditLog'], (result) => {
    if (!result.allowlist) {
      chrome.storage.local.set({ 
  allowlist: ['*'],
        dryRunMode: true,
        auditLog: []
      });
    }
  });
});

// Badge update to show dry run status
chrome.storage.local.get(['dryRunMode'], (result) => {
  if (result.dryRunMode) {
    chrome.action.setBadgeText({ text: 'DRY' });
    chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
  } else {
    chrome.action.setBadgeText({ text: 'LIVE' });
    chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
  }
});

// Listen for storage changes to update badge
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (changes.dryRunMode) {
    if (changes.dryRunMode.newValue) {
      chrome.action.setBadgeText({ text: 'DRY' });
      chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
    } else {
      chrome.action.setBadgeText({ text: 'LIVE' });
      chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
    }
  }
});
