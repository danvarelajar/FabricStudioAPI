// Session-based token management - tokens are stored server-side in sessions
let confirmedHosts = []; // Array of {host, port}
let templates = []; // Array of template objects
let editingConfigId = null; // Track if we're editing an existing configuration
let editingEventId = null; // Track if we're editing an existing event
// Session-based: credentials are managed server-side, no need to store client_id/client_secret
let currentNhiId = null; // Track which NHI credential is currently loaded
let sessionExpiresAt = null; // Track session expiration time
let sessionStatusCache = null; // Cache for session status check
let sessionStatusCacheTime = 0; // Timestamp of last session status check
const SESSION_STATUS_CACHE_DURATION = 2000; // Cache session status for 2 seconds

// Global error handler for unhandled errors
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
  // Log to backend (fail silently if backend unavailable)
  fetch('/api/v1/log-error', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      message: event.error?.message || 'Unknown error',
      stack: event.error?.stack || '',
      url: window.location.href,
      userAgent: navigator.userAgent
    })
  }).catch(() => {}); // Fail silently
});

// Global handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  // Log to backend (fail silently if backend unavailable)
  fetch('/api/v1/log-error', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      message: event.reason?.message || String(event.reason) || 'Unhandled promise rejection',
      stack: event.reason?.stack || '',
      url: window.location.href,
      userAgent: navigator.userAgent
    })
  }).catch(() => {}); // Fail silently
});

const el = (id) => document.getElementById(id);

// Styled alert modal
function alertStyled(titleText, messageText, isError = false) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(0,0,0,0.4)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '9999';

    const dialog = document.createElement('div');
    dialog.style.background = 'white';
    dialog.style.border = '1px solid #d2d2d7';
    dialog.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)';
    dialog.style.width = '600px';
    dialog.style.maxWidth = '90%';
    dialog.style.maxHeight = '80vh';
    dialog.style.padding = '16px';
    dialog.style.borderRadius = '0';
    dialog.style.overflow = 'auto';

    const title = document.createElement('div');
    title.textContent = titleText || (isError ? 'Error' : 'Success');
    title.style.fontWeight = '600';
    title.style.marginBottom = '12px';
    title.style.color = isError ? '#f87171' : '#34d399';
    title.style.fontSize = '16px';
    dialog.appendChild(title);

    const message = document.createElement('div');
    message.textContent = messageText || '';
    message.style.marginBottom = '16px';
    message.style.color = '#1d1d1f';
    message.style.fontSize = '13px';
    message.style.whiteSpace = 'pre-wrap';
    message.style.fontFamily = 'monospace';
    message.style.background = '#f5f5f7';
    message.style.padding = '12px';
    message.style.border = '1px solid #d2d2d7';
    message.style.maxHeight = '400px';
    message.style.overflowY = 'auto';
    dialog.appendChild(message);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.justifyContent = 'flex-end';
    actions.style.gap = '8px';

    const okBtn = document.createElement('button');
    okBtn.type = 'button';
    okBtn.textContent = 'OK';
    okBtn.onclick = () => { document.body.removeChild(overlay); resolve(); };

    actions.appendChild(okBtn);
    dialog.appendChild(actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Close on Escape
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') okBtn.click();
    });
    
    okBtn.focus();
  });
}
function isValidIp(v) {
  // IPv4 dotted-quad, each octet 0-255
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v)) return false;
  const parts = v.split('.');
  return parts.every(p => {
    if (p.length > 1 && p.startsWith('0')) return false; // no leading zeros
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}
function isValidDomain(v) {
  // RFC 1035/1123-ish domain with at least one dot and alpha TLD
  if (!v || v.length > 253) return false;
  const labels = v.split('.');
  if (labels.length < 2) return false; // require at least one dot
  // TLD must be 2-63 letters
  const tld = labels[labels.length - 1];
  if (!/^[A-Za-z]{2,63}$/.test(tld)) return false;
  return labels.every(label => {
    if (!label || label.length > 63) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    // disallow all-numeric labels to avoid confusion with IPs
    if (/^\d+$/.test(label)) return false;
    return true;
  });
}
function splitHostPort(item) {
  const idx = item.lastIndexOf(':');
  if (idx > -1) {
    const hostPart = item.slice(0, idx);
    const portPart = item.slice(idx + 1);
    if (/^\d{1,5}$/.test(portPart)) {
      return { host: hostPart, port: Number(portPart) };
    }
  }
  return { host: item, port: undefined };
}
function parseFabricHosts() {
  const input = el('fabricHost');
  if (!input) return [];
  const raw = input.value.split(/\s+/).map(s => s.trim()).filter(Boolean);
  return raw.map(splitHostPort);
}
function renderHostChips() {
  // Delegate to the generic function for manual input
  renderHostChipsForTarget('fabricHost', 'fabricHostChips', 'fabricHostStatus', validatedHosts);
  // Update mismatch highlighting for NHI hosts when manual hosts change
  updateNhiHostMismatches();
}

// Function to check if a host exists in the manual host list
function isHostInManualList(host, port) {
  return validatedHosts.some(vh => 
    vh.host === host && vh.port === port
  );
}

// Update mismatch highlighting for NHI credential hosts
function updateNhiHostMismatches() {
  if (!window.validatedNhiHosts || window.validatedNhiHosts.length === 0) {
    return;
  }
  
  // Re-render NHI host chips with mismatch detection
  renderHostChipsForTarget(
    'fabricHostFromNhi', 
    'fabricHostFromNhiChips', 
    'fabricHostFromNhiStatus', 
    window.validatedNhiHosts,
    (host, port) => !isHostInManualList(host, port) // Mark as mismatch if not in manual list
  );
}

function removeValidatedHost(index) {
  // Delegate to the generic function
  removeValidatedHostFromArray(index, 'fabricHost', 'fabricHostChips', 'fabricHostStatus', validatedHosts);
  
  // Update confirmed hosts
  confirmedHosts = validatedHosts.map(({host, port}) => ({host, port}));
  renderFabricHostList(); // Fire and forget - async call
}

function validateAndAddHost(hostText) {
  if (!hostText || !hostText.trim()) return false;
  
  const {host, port} = splitHostPort(hostText.trim());
  const hostOk = isValidIp(host) || isValidDomain(host);
  const portOk = port === undefined || (port >= 1 && port <= 65535);
  const isValid = hostOk && portOk;
  
  // Only add to validated hosts if valid
  if (isValid) {
    // Check if already exists to avoid duplicates
    const exists = validatedHosts.some(vh => 
      vh.host === host && vh.port === port
    );
    if (!exists) {
      validatedHosts.push({host, port, isValid: true});
    }
  }
  
  return isValid;
}

function populateHostsFromInput(hostsString, targetInputId = 'fabricHost', targetChipsId = 'fabricHostChips', targetStatusId = 'fabricHostStatus') {
  try {
    if (!hostsString || !hostsString.trim()) {
      const chipsContainer = el(targetChipsId);
      if (chipsContainer) chipsContainer.innerHTML = '';
      const status = el(targetStatusId);
      if (status) { status.textContent = ''; status.className = 'status'; }
      return;
    }
    
    // Get the appropriate validated hosts array based on target
    let targetValidatedHosts = validatedHosts;
    if (targetInputId === 'fabricHostFromNhi') {
      // Use a separate array for NHI hosts
      if (!window.validatedNhiHosts) window.validatedNhiHosts = [];
      targetValidatedHosts = window.validatedNhiHosts;
    } else {
      targetValidatedHosts = validatedHosts;
    }
    
    // Clear existing validated hosts for this target
    targetValidatedHosts.length = 0;
    
    // Parse and validate each host
    const hosts = hostsString.trim().split(/\s+/).filter(h => h.trim());
    hosts.forEach(host => {
      validateAndAddHostToArray(host.trim(), targetValidatedHosts);
    });
    
    // Render chips and update status for the target
    if (targetInputId === 'fabricHostFromNhi') {
      // For NHI hosts, render with mismatch detection
      renderHostChipsForTarget(
        targetInputId, 
        targetChipsId, 
        targetStatusId, 
        targetValidatedHosts,
        (host, port) => !isHostInManualList(host, port) // Mark as mismatch if not in manual list
      );
    } else {
      // For manual hosts, render normally and update NHI mismatches
      renderHostChipsForTarget(targetInputId, targetChipsId, targetStatusId, targetValidatedHosts);
      updateNhiHostMismatches();
    }
  } catch (error) {
  }
}

function validateAndAddHostToArray(hostText, targetArray) {
  if (!hostText || !hostText.trim()) return false;
  
  const {host, port} = splitHostPort(hostText.trim());
  const hostOk = isValidIp(host) || isValidDomain(host);
  const portOk = port === undefined || (port >= 1 && port <= 65535);
  const isValid = hostOk && portOk;
  
  // Only add to validated hosts if valid
  if (isValid) {
    // Check if already exists to avoid duplicates
    const exists = targetArray.some(vh => 
      vh.host === host && vh.port === port
    );
    if (!exists) {
      targetArray.push({host, port, isValid: true});
    }
  }
  
  return isValid;
}

function renderHostChipsForTarget(inputId, chipsContainerId, statusId, targetValidatedHosts, isMismatchedFn = null) {
  const chipsContainer = el(chipsContainerId);
  if (!chipsContainer) return;
  
  chipsContainer.innerHTML = '';
  
  if (targetValidatedHosts.length === 0) {
    chipsContainer.style.display = 'none';
    return;
  }
  
  chipsContainer.style.display = 'flex';
  
  targetValidatedHosts.forEach(({host, port}, index) => {
    const entry = host + (port !== undefined ? ':' + port : '');
    
    const chip = document.createElement('div');
    // Determine chip class based on mismatch status
    let chipClass = 'host-chip valid';
    if (isMismatchedFn && isMismatchedFn(host, port)) {
      chipClass = 'host-chip mismatch';
    }
    chip.className = chipClass;
    
    const chipText = document.createElement('span');
    chipText.className = 'chip-text';
    chipText.textContent = entry;
    chip.appendChild(chipText);
    
    const chipDelete = document.createElement('button');
    chipDelete.className = 'chip-delete';
    chipDelete.textContent = '×';
    chipDelete.type = 'button';
    chipDelete.title = 'Remove host';
    chipDelete.addEventListener('click', () => {
      removeValidatedHostFromArray(index, inputId, chipsContainerId, statusId, targetValidatedHosts);
    });
    chip.appendChild(chipDelete);
    
    chipsContainer.appendChild(chip);
  });
  
  // Update status
  const status = el(statusId);
  if (status) {
    if (targetValidatedHosts.length > 0) {
      const mismatchCount = isMismatchedFn ? targetValidatedHosts.filter(({host, port}) => isMismatchedFn(host, port)).length : 0;
      if (mismatchCount > 0) {
        status.textContent = `${targetValidatedHosts.length} host(s) - ${mismatchCount} mismatch(es)`;
        status.className = 'status';
        status.style.color = '#ff8800';
      } else {
        status.textContent = `${targetValidatedHosts.length} host(s) valid`;
        status.className = 'status';
        status.style.color = '#10b981';
      }
    } else {
      status.textContent = '';
      status.className = 'status';
    }
  }
}

function removeValidatedHostFromArray(index, inputId, chipsContainerId, statusId, targetValidatedHosts) {
  if (index < 0 || index >= targetValidatedHosts.length) return;
  
  targetValidatedHosts.splice(index, 1);
  
  // Update input value with remaining validated hosts
  const input = el(inputId);
  if (input) {
    if (targetValidatedHosts.length === 0) {
      input.value = '';
    } else {
      const remaining = targetValidatedHosts.map(({host, port}) => 
        host + (port !== undefined ? ':' + port : '')
      ).join(' ');
      input.value = remaining + ' ';
    }
  }
  
  // Re-render chips with mismatch detection if this is NHI hosts
  if (inputId === 'fabricHostFromNhi') {
    renderHostChipsForTarget(
      inputId, 
      chipsContainerId, 
      statusId, 
      targetValidatedHosts,
      (host, port) => !isHostInManualList(host, port)
    );
  } else if (inputId === 'editFabricHost') {
    // For edit field, re-render chips and update validation status
    renderHostChipsForTarget(inputId, chipsContainerId, statusId, targetValidatedHosts);
    const status = el(statusId);
    const input = el(inputId);
    if (status && input) {
      if (targetValidatedHosts.length > 0) {
        status.textContent = `${targetValidatedHosts.length} host(s) valid`;
        status.className = 'status';
        status.style.color = '#10b981';
        input.style.borderColor = '#10b981';
      } else {
        status.textContent = '';
        status.className = 'status';
        input.style.borderColor = '';
      }
    }
  } else {
    renderHostChipsForTarget(inputId, chipsContainerId, statusId, targetValidatedHosts);
    // When manual hosts change, update NHI mismatches
    updateNhiHostMismatches();
  }
}

function updateValidationStatus() {
  const status = el('fabricHostStatus');
  const input = el('fabricHost');
  
  if (validatedHosts.length === 0) {
    if (status) { status.textContent = ''; status.className = 'status'; }
    if (input) { input.style.borderColor = ''; }
  } else {
    // All validated hosts are valid (since we only add valid ones)
    if (status) { 
      status.textContent = `${validatedHosts.length} host(s) valid`; 
      status.className = 'status'; 
      status.style.color = '#10b981'; 
    }
    if (input) { input.style.borderColor = '#10b981'; }
  }
}


function validateFabricHosts(forceValidation = false) {
  const input = el('fabricHost');
  if (!input) return true;
  
  // Render chips from validated hosts
  renderHostChips();
  updateValidationStatus();
  
  // If forced validation (e.g., on blur), validate current input if any
  if (forceValidation && input.value.trim()) {
    const currentValue = input.value.trim();
    const parts = currentValue.split(/\s+/).filter(p => p.trim());
    
    // Validate any hosts that aren't already in validatedHosts
    parts.forEach(part => {
      const {host, port} = splitHostPort(part.trim());
      const exists = validatedHosts.some(vh => 
        vh.host === host && vh.port === port
      );
      if (!exists) {
        validateAndAddHost(part.trim()); // Only adds if valid
      }
    });
    
    renderHostChips();
    updateValidationStatus();
  }
  
  // Auto-confirm hosts when they're validated
  if (validatedHosts.length > 0) {
    autoConfirmHosts();
    // Enable Add Row button if hosts are confirmed
    const addRowBtn = el('btnAddRow');
    if (addRowBtn && confirmedHosts.length > 0) {
      addRowBtn.disabled = false;
    }
  }
  
  // Return true if we have at least one validated host
  return validatedHosts.length > 0;
}
function getFabricHostPrimary() {
  if (confirmedHosts.length > 0) {
    const hostObj = confirmedHosts[0];
    // Return host without port (ports are handled separately for token storage)
    // The host string might contain port, so extract just the hostname/IP
    const hostOnly = hostObj.host ? hostObj.host.split(':')[0] : '';
    return hostOnly;
  }
  const parsed = parseFabricHosts();
  if (parsed.length > 0 && parsed[0]?.host) {
    return parsed[0].host.split(':')[0];
  }
  return '';
}

function validateGuestPassword(password) {
  if (!password || password.trim().length === 0) {
    return { valid: true, errors: [] }; // Empty password is allowed (optional field)
  }
  
  const errors = [];
  
  // At least 7 characters
  if (password.length < 7) {
    errors.push('at least 7 characters');
  }
  
  // At least 1 uppercase letter
  if (!/[A-Z]/.test(password)) {
    errors.push('1 uppercase letter');
  }
  
  // At least 1 number
  if (!/[0-9]/.test(password)) {
    errors.push('1 number');
  }
  
  // At least 1 special character
  if (!/[^a-zA-Z0-9]/.test(password)) {
    errors.push('1 special character');
  }
  
  return {
    valid: errors.length === 0,
    errors: errors
  };
}

function showPasswordError(inputId, errorId, validation) {
  const errorSpan = el(errorId);
  if (!errorSpan) return;
  
  if (!validation.valid && validation.errors.length > 0) {
    errorSpan.textContent = `Missing: ${validation.errors.join(', ')}`;
    errorSpan.style.display = 'inline';
  } else {
    errorSpan.style.display = 'none';
  }
}

function validateGuestPasswordField(inputId, errorId) {
  const input = el(inputId);
  if (!input) return true; // Field doesn't exist, consider valid
  
  const password = input.value.trim();
  const validation = validateGuestPassword(password);
  showPasswordError(inputId, errorId, validation);
  return validation.valid;
}

function getAllConfirmedHosts() {
  return confirmedHosts.length > 0 ? confirmedHosts : parseFabricHosts();
}

function initGuestPasswordValidation() {
  // Track which inputs already have listeners attached (by element reference, not ID)
  const attachedInputs = new WeakSet();
  
  // Add validation listeners to password fields when they exist
  const setupPasswordValidation = (inputId, errorId) => {
    const input = el(inputId);
    if (!input) return; // Field doesn't exist yet
    
    // Skip if already attached to this element
    if (attachedInputs.has(input)) {
      return;
    }
    
    // Mark this element as attached
    attachedInputs.add(input);
    
    input.addEventListener('input', () => {
      validateGuestPasswordField(inputId, errorId);
    });
    input.addEventListener('blur', () => {
      validateGuestPasswordField(inputId, errorId);
    });
  };
  
  // Set up validation for preparation section password field
  setupPasswordValidation('chgPass', 'chgPassError');
  
  // Set up validation for configurations section password field
  setupPasswordValidation('editChgPass', 'editChgPassError');
  
  // Also set up when sections are loaded dynamically
  // Only observe childList changes, not attribute changes (like style.display)
  const observer = new MutationObserver((mutations) => {
    // Only process if actual DOM nodes were added/removed
    const hasNodeChanges = mutations.some(m => m.type === 'childList' && (m.addedNodes.length > 0 || m.removedNodes.length > 0));
    if (hasNodeChanges) {
      // Reset and re-attach for new elements (WeakSet automatically handles removed elements)
      setupPasswordValidation('chgPass', 'chgPassError');
      setupPasswordValidation('editChgPass', 'editChgPassError');
    }
  });
  
  const contentContainer = document.getElementById('content-container');
  if (contentContainer) {
    observer.observe(contentContainer, { 
      childList: true, 
      subtree: true,
      attributes: false  // Don't observe attribute changes (prevents loop when error spans show/hide)
    });
  }
}

// Session status check - tokens are stored server-side
// Uses short-term caching to avoid redundant API calls during configuration loading
async function checkSessionStatus() {
  // Return cached result if still valid (within cache duration)
  // Note: null is a valid cached value (means no session), so we check cacheTime instead
  const now = Date.now();
  if (sessionStatusCacheTime > 0 && (now - sessionStatusCacheTime) < SESSION_STATUS_CACHE_DURATION) {
    return sessionStatusCache;
  }
  
  try {
    const res = await api('/auth/session/status', {
      credentials: 'include' // Include cookies
    });
    if (res.ok) {
      const data = await res.json();
      sessionExpiresAt = data.expires_at ? new Date(data.expires_at) : null;
      // Cache successful result
      sessionStatusCache = data;
      sessionStatusCacheTime = now;
      return data;
    } else if (res.status === 401) {
      // Session expired
      sessionExpiresAt = null;
      // Cache null result to avoid repeated 401s
      sessionStatusCache = null;
      sessionStatusCacheTime = now;
      return null;
    }
    // Cache null result for other errors too
    sessionStatusCache = null;
    sessionStatusCacheTime = now;
    return null;
  } catch (error) {
    // Cache null result on exception
    sessionStatusCache = null;
    sessionStatusCacheTime = now;
    return null;
  }
}
function handleSessionExpired() {
  // Clear any cached data
  currentNhiId = null;
  sessionExpiresAt = null;
  // Clear session status cache to force fresh check
  sessionStatusCache = null;
  sessionStatusCacheTime = 0;
  // Show message to user
  showStatus('Session expired. Please reload NHI credential.');
  // Update UI
  renderFabricHostList(); // Fire and forget - async call
}

// Removed mergeAuth - tokens are now managed server-side via session cookies

// Helper function to auto-confirm hosts when they're available
function autoConfirmHosts() {
  // Determine which host source to use
  const hostSourceManual = el('hostSourceManual');
  const useManualHosts = hostSourceManual && hostSourceManual.checked;
  
  let sourceValidatedHosts;
  if (useManualHosts) {
    sourceValidatedHosts = validatedHosts;
  } else {
    if (!window.validatedNhiHosts) window.validatedNhiHosts = [];
    sourceValidatedHosts = window.validatedNhiHosts;
  }
  
  // Auto-confirm hosts if we have any
  if (sourceValidatedHosts && sourceValidatedHosts.length > 0) {
    confirmedHosts = sourceValidatedHosts.map(({host, port}) => ({host, port}));
    return true;
  }
  return false;
}

async function renderFabricHostList(shouldConfirmHosts = false) {
  const listEl = el('fabricHostList');
  if (!listEl) return;
  listEl.innerHTML = '';
  const items = parseFabricHosts();
  // Auto-confirm hosts when they're available (no manual confirmation needed)
  if (items && items.length > 0) {
    confirmedHosts = items; // Store confirmed hosts automatically
  }
  
  // Use existing sessionExpiresAt instead of making API call
  // The session status will be checked when actually needed (e.g., before API calls)
  
  items.forEach(({host, port}, i) => {
    const li = document.createElement('li');
    // Session-based: tokens are managed server-side
    const tokenStatus = sessionExpiresAt && sessionExpiresAt > new Date() ? ' [Session OK]' : ' [No Session]';
    li.textContent = host + (port ? (':' + port) : '') + tokenStatus;
    listEl.appendChild(li);
  });
}

async function checkRunningTasks(host, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      // Cookies are sent automatically - no need for Authorization header
      const res = await api('/tasks/status', { 
        params: { fabric_host: host },
        credentials: 'include'
      });
      if (!res.ok) {
        if (res.status === 401) {
          handleSessionExpired();
        }
        return {running: false, error: true};
      }
      const data = await res.json();
      const runningCount = data.running_count ?? 0;
      if (runningCount === 0) return {running: false, error: false};
      await new Promise(r => setTimeout(r, 2000));
    } catch (error) {
      logMsg(`Error checking tasks on ${host}: ${error.message || error}`);
      return {running: false, error: true};
    }
  }
  return {running: true, error: false}; // Timeout - tasks still running
}

async function waitForNoRunningTasks(hosts, actionName) {
  const checks = hosts.map(async ({host}) => {
    // User is already authenticated via login - proceed with check
    const checkResult = await checkRunningTasks(host, 1000); // Quick check first
    if (!checkResult.running) {
      return {host, success: true};
    } else {
      logMsg(`Waiting for running tasks to complete on ${host}...`);
      const completed = await checkRunningTasks(host, 900000); // 15 minute wait
      if (!completed.running) {
        logMsg(`All tasks completed on ${host}`);
        return {host, success: true};
      } else {
        logMsg(`Timeout waiting for tasks on ${host}`);
        return {host, success: false, error: 'Tasks still running'};
      }
    }
  });
  const results = await Promise.all(checks);
  const failed = results.filter(r => !r.success);
  if (failed.length > 0) {
    const failedHosts = failed.map(r => r.host).join(', ');
    showStatus(`Warning: Running tasks detected on ${failedHosts}. Proceeding anyway.`);
  }
  return results;
}

async function executeOnAllHosts(actionName, actionFn, options = {}) {
  const hosts = getAllConfirmedHosts();
  if (hosts.length === 0) {
    // Auto-confirm hosts if available
    if (autoConfirmHosts()) {
      // Hosts are now confirmed, continue
    } else {
      showStatus('No hosts configured. Please add at least one valid host.');
      return;
    }
    return;
  }
  
  // Check for running tasks before executing action
  if (options.checkTasks !== false) {
    await waitForNoRunningTasks(hosts, actionName);
  }
  
  const results = [];
  const promises = hosts.map(async ({host}) => {
    // User is already authenticated via login - proceed with operation
    try {
      await actionFn(host, null); // Token is retrieved server-side
      return {host, success: true};
    } catch (error) {
      showStatus(`${actionName} failed on ${host}: ${error.message || error}`);
      return {host, success: false, error: error.message || error};
    }
  });
  results.push(...await Promise.all(promises));
  const successCount = results.filter(r => r.success).length;
  if (successCount === hosts.length) {
    showStatus(`${actionName} completed successfully on all ${hosts.length} host(s)`);
  } else {
    showStatus(`${actionName} completed on ${successCount}/${hosts.length} host(s)`);
  }
  return results;
}
// Load NHI credentials into dropdown
// Cache for NHI credentials to avoid duplicate calls
let _nhiCredentialsCache = null;
let _nhiCredentialsLoading = null;

async function loadNhiCredentialsForAuth() {
  const select = el('nhiCredentialSelect');
  if (!select) return;
  
  // If already loading, wait for that request
  if (_nhiCredentialsLoading) {
    await _nhiCredentialsLoading;
    if (_nhiCredentialsCache) {
      populateNhiCredentialsDropdown(select, _nhiCredentialsCache);
      return;
    }
  }
  
  // If we have cached data, use it
  if (_nhiCredentialsCache) {
    populateNhiCredentialsDropdown(select, _nhiCredentialsCache);
    return;
  }
  
  // Load credentials
  _nhiCredentialsLoading = (async () => {
    try {
      const res = await api('/nhi/list');
      if (!res.ok) {
        select.innerHTML = '<option value="">Error loading credentials</option>';
        return;
      }
      
      const data = await res.json();
      const credentials = data.credentials || [];
      _nhiCredentialsCache = credentials;
      populateNhiCredentialsDropdown(select, credentials);
    } catch (error) {
      select.innerHTML = '<option value="">Error loading credentials</option>';
    } finally {
      _nhiCredentialsLoading = null;
    }
  })();
  
  await _nhiCredentialsLoading;
}

function populateNhiCredentialsDropdown(select, credentials) {
  // Clear and rebuild dropdown
  select.innerHTML = '<option value="">Select NHI credential...</option>';
  credentials.forEach(cred => {
    const option = document.createElement('option');
    option.value = cred.id.toString(); // Ensure ID is a string
    option.textContent = `${cred.name} (${cred.client_id})`;
    select.appendChild(option);
  });
  
  // If no credentials, clear any previously selected value
  if (credentials.length === 0) {
    select.value = '';
  }
}

// Clear NHI credentials cache (call after save/delete/update)
function clearNhiCredentialsCache() {
  _nhiCredentialsCache = null;
  _requestCache.clear(); // Clear API cache for /nhi/list
}

// Load selected NHI credential - no password required
async function loadSelectedNhiCredential() {
  const select = el('nhiCredentialSelect');
  const statusSpan = el('nhiLoadStatus');
  
  if (!select) return;
  
  const nhiId = select.value;
  
  if (!nhiId) {
    if (statusSpan) statusSpan.textContent = 'Please select a credential';
    return;
  }
  
  // Validate that the selected ID exists in the dropdown
  const selectedOption = select.options[select.selectedIndex];
  if (!selectedOption || selectedOption.value !== nhiId) {
    // Stale selection, refresh the dropdown and show error
    await loadNhiCredentialsForAuth();
    if (statusSpan) statusSpan.textContent = 'Please select a valid credential';
    showStatus('Selected credential no longer exists. Please refresh and select again.');
    select.value = '';
    return;
  }
  
  try {
    if (statusSpan) statusSpan.textContent = 'Loading...';
    // No password required - uses FS_SERVER_SECRET
    const res = await api(`/nhi/get/${nhiId}`);
    
    if (!res.ok) {
      let errorText = 'Unknown error';
      try {
        const errorData = await res.json().catch(() => null);
        if (errorData && errorData.detail) {
          errorText = errorData.detail;
        } else {
          errorText = await res.text().catch(() => 'Unknown error');
        }
      } catch (e) {
        errorText = await res.text().catch(() => 'Unknown error');
      }
      
      if (statusSpan) statusSpan.textContent = 'Failed to load credential';
      
      // If 404, refresh dropdown as credential may have been deleted
      if (res.status === 404) {
        await loadNhiCredentialsForAuth();
        select.value = '';
        showStatus(`NHI credential not found. The credential may have been deleted. Please select a different one.`);
      } else if (res.status === 400) {
        showStatus(`Failed to load NHI credential: ${errorText}`);
      } else {
        showStatus(`Failed to load NHI credential: ${errorText}`);
      }
      
      currentNhiId = null;
      sessionExpiresAt = null;
      // Session-based: tokens are managed server-side
      
      // Clear NHI credential from session
      try {
        await api('/auth/session/nhi-credential', {
          method: 'PUT',
          params: { nhi_credential_id: null }
        });
      } catch (error) {
        // Ignore errors when clearing
      }
      
      // Disable Add Row button on error
      const addRowBtnError = el('btnAddRow');
      if (addRowBtnError) addRowBtnError.disabled = true;
      
      // Disable the NHI credential input and radio button on error
      const fabricHostFromNhiInput = el('fabricHostFromNhi');
      if (fabricHostFromNhiInput) {
        fabricHostFromNhiInput.disabled = true;
        fabricHostFromNhiInput.value = '';
        fabricHostFromNhiInput.style.backgroundColor = '#f5f5f7';
        fabricHostFromNhiInput.style.cursor = 'not-allowed';
        try {
          populateHostsFromInput('', 'fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus');
        } catch (e) {
        }
      }
      const hostSourceNhi = el('hostSourceNhi');
      if (hostSourceNhi) {
        hostSourceNhi.disabled = true;
        if (hostSourceNhi.checked) {
          const hostSourceManual = el('hostSourceManual');
          if (hostSourceManual) {
            hostSourceManual.checked = true;
          }
        }
      }
      
      return;
    }
    
    let nhiData;
    try {
      nhiData = await res.json();
    } catch (jsonError) {
      if (statusSpan) statusSpan.textContent = 'Invalid response';
      showStatus(`Failed to parse response from server: ${jsonError.message || jsonError}`);
      return;
    }
    
    if (!nhiData || typeof nhiData !== 'object') {
      if (statusSpan) statusSpan.textContent = 'Invalid response';
      showStatus('Invalid response format from server');
      return;
    }
    // Session-based: client_id/client_secret are not needed - tokens are managed server-side
    currentNhiId = parseInt(nhiId);
    
    // Update session with selected NHI credential ID
    try {
      await api('/auth/session/nhi-credential', {
        method: 'PUT',
        params: { nhi_credential_id: currentNhiId }
      });
    } catch (error) {
      console.warn(`Failed to update session with NHI credential ID: ${error.message || error}`);
      // Continue anyway - the credential is still loaded
    }
    
    // Enable Add Row button after NHI credential is selected
    const addRowBtn = el('btnAddRow');
    if (addRowBtn) addRowBtn.disabled = false;
    
    // Session-based: tokens are managed server-side
    // Session is created automatically by backend when NHI credential is loaded
    // No need to check session status - user is already authenticated via login
    
    const nhiHosts = [];
    // Session-based: tokens are stored server-side, backend returns hosts_with_tokens array
    if (nhiData.hosts_with_tokens && Array.isArray(nhiData.hosts_with_tokens) && nhiData.hosts_with_tokens.length > 0) {
      // Collect host list from hosts_with_tokens array
      nhiHosts.push(...nhiData.hosts_with_tokens);
      // NHI credential contains stored tokens
    }
    
    // Handle Fabric Host population from NHI credential
    const fabricHostFromNhiInput = el('fabricHostFromNhi');
    
    if (nhiHosts.length > 0) {
      // Always populate the NHI hosts input (enable it and make it editable)
      const nhiHostsStr = nhiHosts.join(' ');
      if (fabricHostFromNhiInput) {
        fabricHostFromNhiInput.value = nhiHostsStr;
        // Enable the input
        fabricHostFromNhiInput.disabled = false;
        fabricHostFromNhiInput.style.backgroundColor = '';
        fabricHostFromNhiInput.style.cursor = '';
        populateHostsFromInput(nhiHostsStr, 'fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus');
        // Update mismatch highlighting after populating
        updateNhiHostMismatches();
      }
      // Enable the NHI Credential radio button
      const hostSourceNhi = el('hostSourceNhi');
      if (hostSourceNhi) {
        hostSourceNhi.disabled = false;
      }
    } else {
      // Clear NHI hosts if credential has none
      if (fabricHostFromNhiInput) {
        fabricHostFromNhiInput.value = '';
        fabricHostFromNhiInput.disabled = true;
        fabricHostFromNhiInput.style.backgroundColor = '#f5f5f7';
        fabricHostFromNhiInput.style.cursor = 'not-allowed';
        populateHostsFromInput('', 'fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus');
      }
      // Disable the NHI Credential radio button if no hosts
      const hostSourceNhi = el('hostSourceNhi');
      if (hostSourceNhi) {
        hostSourceNhi.disabled = true;
        // If it was selected, switch to manual
        if (hostSourceNhi.checked) {
          const hostSourceManual = el('hostSourceManual');
          if (hostSourceManual) {
            hostSourceManual.checked = true;
          }
        }
      }
    }
    
    if (statusSpan) {
      statusSpan.textContent = '✓ Loaded';
      statusSpan.style.color = '#10b981';
    }
    
    // Auto-confirm hosts when NHI credential is loaded
    if (autoConfirmHosts()) {
      // Automatically acquire tokens
      if (await acquireTokens()) {
        // Enable Add Row button
        const addRowBtn = el('btnAddRow');
        if (addRowBtn) addRowBtn.disabled = false;
        showStatus('Hosts confirmed and tokens acquired.', { hideAfterMs: 1000 });
        updateCreateEnabled();
      } else {
        showStatus('Token acquisition failed. Please check credentials.');
      }
    }
    
    // Show final success message if no specific message was already shown above
    if (nhiHosts.length === 0) {
      showStatus(`NHI credential '${nhiData.name}' loaded successfully (no hosts in credential)`);
    }
    
    // Update fabric host list to show session status
    await renderFabricHostList();
  } catch (error) {
    if (statusSpan) {
      statusSpan.textContent = 'Error';
      statusSpan.style.color = '#f87171';
    }
    showStatus(`Error loading NHI credential: ${error.message || error}`);
    currentNhiId = null;
      sessionExpiresAt = null;
      // Session-based: tokens are managed server-side
    
    // Disable Run button on credential load error
    const runBtnError = el('btnInstallSelected');
    if (runBtnError) runBtnError.disabled = true;
    
    // Disable the NHI credential input and radio button on error
    const fabricHostFromNhiInput = el('fabricHostFromNhi');
    if (fabricHostFromNhiInput) {
      fabricHostFromNhiInput.disabled = true;
      fabricHostFromNhiInput.value = '';
      fabricHostFromNhiInput.style.backgroundColor = '#f5f5f7';
      fabricHostFromNhiInput.style.cursor = 'not-allowed';
      try {
        populateHostsFromInput('', 'fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus');
      } catch (e) {
      }
    }
    const hostSourceNhi = el('hostSourceNhi');
    if (hostSourceNhi) {
      hostSourceNhi.disabled = true;
      // If it was selected, switch to manual
      if (hostSourceNhi.checked) {
        const hostSourceManual = el('hostSourceManual');
        if (hostSourceManual) {
          hostSourceManual.checked = true;
        }
      }
    }
    
    // Disable Run button when credentials are cleared
    const runBtnCleared = el('btnInstallSelected');
    if (runBtnCleared) runBtnCleared.disabled = true;
  }
}

// Load selected NHI credential for edit view - no password required
async function loadSelectedNhiCredentialForEdit() {
  const select = el('editNhiCredentialSelect');
  
  if (!select) return;
  
  const nhiId = select.value;
  
  if (!nhiId) {
    return;
  }
  
  try {
    // No password required - uses FS_SERVER_SECRET
    const res = await api(`/nhi/get/${nhiId}`);
    
    if (!res.ok) {
      showStatus('Failed to load NHI credential');
      return;
    }
    
    const nhiData = await res.json();
    
    if (!nhiData || typeof nhiData !== 'object') {
      showStatus('Invalid response format from server');
      return;
    }
    
    const nhiHosts = [];
    // Session-based: tokens are stored server-side, backend returns hosts_with_tokens array
    if (nhiData.hosts_with_tokens && Array.isArray(nhiData.hosts_with_tokens) && nhiData.hosts_with_tokens.length > 0) {
      // Collect host list from hosts_with_tokens array (each item is a string host)
      nhiHosts.push(...nhiData.hosts_with_tokens);
    }
    
    // Populate editFabricHost with hosts from NHI credential
    const editFabricHostInput = el('editFabricHost');
    
    if (nhiHosts.length > 0) {
      // Populate the edit fabric host input
      // nhiHosts is an array of host strings
      const nhiHostsStr = nhiHosts.join(' ');
      if (editFabricHostInput) {
        editFabricHostInput.value = nhiHostsStr;
        
        // Parse and validate hosts
        const hosts = nhiHostsStr.split(/\s+/).filter(h => h.trim()).map(hostStr => {
          const parts = hostStr.split(':');
          return {
            host: parts[0],
            port: parts.length > 1 ? parts[1] : undefined,
            isValid: true
          };
        });
        
        // Store validated hosts
        window.editValidatedHosts = hosts;
        
        // Render host chips
        renderHostChipsForTarget('editFabricHost', 'editFabricHostChips', 'editFabricHostStatus', hosts);
      }
    } else {
      // Clear hosts if credential has none
      if (editFabricHostInput) {
        editFabricHostInput.value = '';
      }
      const editFabricHostChips = el('editFabricHostChips');
      if (editFabricHostChips) {
        editFabricHostChips.innerHTML = '';
      }
      window.editValidatedHosts = [];
      showStatus(`NHI credential '${nhiData.name}' loaded (no hosts in credential)`);
    }
  } catch (error) {
    logMsg(`Error loading NHI credential for edit: ${error.message || error}`);
    showStatus(`Error loading NHI credential: ${error.message || error}`);
  }
}

// Default API base to the current page origin to avoid cross-origin mismatches (localhost vs 127.0.0.1)
// Initialize global state variables
let validatedHosts = [];
let isRunInProgress = false;
if (!window.validatedNhiHosts) window.validatedNhiHosts = [];

const RUN_WARNING_ELEMENT_ID = 'runInProgressWarning';

function showRunInProgressWarning() {
  let warning = document.getElementById(RUN_WARNING_ELEMENT_ID);
  const actionStatus = el('actionStatus');

  if (!warning) {
    warning = document.createElement('div');
    warning.id = RUN_WARNING_ELEMENT_ID;
    warning.style.marginTop = '8px';
    warning.style.padding = '10px 12px';
    warning.style.border = '1px solid #d2d2d7';
    warning.style.background = '#f5f5f7';
    warning.style.color = '#1d1d1f';
    warning.style.fontSize = '13px';
    warning.style.fontWeight = '500';
    warning.style.borderRadius = '0';
    warning.style.display = 'none';
    warning.style.lineHeight = '1.5';
    warning.style.fontFamily = "'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'Liberation Sans', sans-serif";
    warning.style.boxSizing = 'border-box';
    warning.innerHTML = '<span style="color: #b45309; font-weight: 600;">⚠</span> Do not navigate away from this page while the installation is running.';

    // Place warning near actionStatus if it exists, otherwise near Run button
    if (actionStatus && actionStatus.parentElement) {
      actionStatus.parentElement.insertBefore(warning, actionStatus);
    } else {
      const runBtn = el('btnInstallSelected');
      if (runBtn && runBtn.parentElement) {
        runBtn.parentElement.appendChild(warning);
      } else {
        document.body.appendChild(warning);
      }
    }
  }

  // Match the width of actionStatus
  if (actionStatus) {
    const actionStatusWidth = actionStatus.offsetWidth || actionStatus.clientWidth;
    if (actionStatusWidth > 0) {
      warning.style.width = actionStatusWidth + 'px';
    } else {
      // If actionStatus is not visible yet, use its computed style
      const computedStyle = window.getComputedStyle(actionStatus);
      if (computedStyle.width && computedStyle.width !== 'auto') {
        warning.style.width = computedStyle.width;
      } else {
        // Fallback: match the container width
        if (actionStatus.parentElement) {
          warning.style.width = '100%';
        }
      }
    }
  } else {
    // Fallback if actionStatus doesn't exist
    warning.style.width = '100%';
  }

  warning.style.display = 'block';
}

function hideRunInProgressWarning() {
  const warning = document.getElementById(RUN_WARNING_ELEMENT_ID);
  if (warning) {
    warning.style.display = 'none';
  }
}

// Note: Preparation section initialization is now in initializePreparationSection()
// which is called when the preparation section is loaded

function logMsg(msg) {
  // Always log messages regardless of Expert Mode toggle status
  const out = el('out');
  if (out) {
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);
    out.textContent += `[${timestamp}] ${msg}\n`;
    // Auto-scroll to bottom
    out.scrollTop = out.scrollHeight;
  }
}

function showStatus(msg, opts = {}) {
  const box = el('actionStatus');
  const messageEl = el('actionStatusMessage');
  if (!box || !messageEl) return;
  
  messageEl.innerHTML = msg.replace(/\n/g, '<br>');
  box.style.display = '';
  
  // Show/hide progress section based on opts
  // If showProgress is not specified, preserve current visibility state
  const progressSection = el('actionStatusProgress');
  if (progressSection) {
    if (opts.showProgress === true) {
      progressSection.style.display = '';
    } else if (opts.showProgress === false) {
      progressSection.style.display = 'none';
    }
    // If showProgress is undefined, don't change the visibility (preserve current state)
  }
  
  // Add error styling if it's an error message
  if (opts.error || msg.toLowerCase().includes('error') || msg.toLowerCase().includes('failed')) {
    box.style.color = '#d32f2f';
    box.style.backgroundColor = '#ffebee';
    box.style.border = '1px solid #d32f2f';
  } else {
    box.style.color = '';
    box.style.backgroundColor = '';
    box.style.border = '';
  }
  logMsg(msg);
  if (opts.hideAfterMs) {
    const ms = opts.hideAfterMs;
    const messageHtml = msg.replace(/\n/g, '<br>');
    setTimeout(() => { 
      if (messageEl.innerHTML === messageHtml) {
        box.style.display = 'none';
        if (progressSection) progressSection.style.display = 'none';
      }
    }, ms);
  }
}

// NHI-specific status display function
function showNhiStatus(msg, opts = {}) {
  const box = el('nhiStatus');
  if (!box) {
    return;
  }
  // Replace newlines with <br> tags for HTML display
  box.innerHTML = msg.replace(/\n/g, '<br>');
  box.style.display = '';
  // Add error styling if it's an error message
  if (opts.error || msg.toLowerCase().includes('error') || msg.toLowerCase().includes('failed')) {
    box.style.color = '#d32f2f';
    box.style.backgroundColor = '#ffebee';
    box.style.border = '1px solid #d32f2f';
    box.style.padding = '12px';
    box.style.margin = '12px 0';
    box.style.borderRadius = '4px';
  } else {
    box.style.color = '#1976d2';
    box.style.backgroundColor = '#e3f2fd';
    box.style.border = '1px solid #1976d2';
    box.style.padding = '12px';
    box.style.margin = '12px 0';
    box.style.borderRadius = '4px';
  }
  if (opts.hideAfterMs) {
    const ms = opts.hideAfterMs;
    setTimeout(() => { if (box.innerHTML === msg.replace(/\n/g, '<br>')) box.style.display = 'none'; }, ms);
  }
}

function setActionsEnabled(enabled) {
  const idsToSkip = new Set(['btnInstallSelected','btnAddRow']);
  document.querySelectorAll('button').forEach(b => {
    if (!idsToSkip.has(b.id)) b.disabled = !enabled;
  });
  // Inputs for API config should remain enabled
  ['fabricHost'].forEach(id => {
    const i = el(id);
    if (i) i.disabled = false;
  });
  const runBtn = el('btnInstallSelected');
  if (runBtn) {
    if (!enabled) runBtn.disabled = true; else updateCreateEnabled();
  }
}
// Request cache to prevent duplicate calls (for GET requests only)
const _requestCache = new Map();
const _requestCacheTimeout = 5000; // Cache for 5 seconds
const _pendingRequests = new Map(); // Track in-flight requests to deduplicate
const _htmlCache = new Map(); // Cache for HTML section content
// Generic API wrapper with optional params - cookies are included automatically
async function api(path, options = {}) {
  // Always use current origin as base URL
  const base = '';
  
  // Separate params from headers - headers should never be in params
  const params = options.params || {};
  const headers = new Headers(options.headers || {});
  
  // For GET requests, check cache and pending requests to avoid duplicates
  const method = (options.method || 'GET').toUpperCase();
  const noCache = options.noCache === true; // Option to bypass cache
  if (method === 'GET' && !noCache) {
    const cacheKey = `${path}?${new URLSearchParams(params).toString()}`;
    const now = Date.now();
    
    // Check if we have a cached response
    if (_requestCache.has(cacheKey)) {
      const cached = _requestCache.get(cacheKey);
      if (now - cached.timestamp < _requestCacheTimeout) {
        // Return cached response (clone it since Response can only be read once)
        return new Response(JSON.stringify(cached.data), {
          status: 200,
          statusText: 'OK',
          headers: { 'Content-Type': 'application/json' }
        });
      } else {
        _requestCache.delete(cacheKey);
      }
    }
    
    // Check if there's already a pending request for this path
    if (_pendingRequests.has(cacheKey)) {
      // Wait for the pending request to complete and clone the response
      // since Response body can only be read once
      const pendingResponse = await _pendingRequests.get(cacheKey);
      // Clone the response so each caller gets their own readable stream
      return pendingResponse.clone();
    }
  }
  
  // Add CSRF token if available (for state-changing operations)
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const csrfToken = sessionStorage.getItem('csrf_token');
    if (csrfToken) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }
  
  // Get timeout from options or use default (30 seconds)
  const timeout = options.timeout || 30000; // Default 30 seconds
  
  // Always include credentials for cookie-based sessions
  const fetchOptions = {
    ...options,
    headers,
    credentials: 'include' // Always include cookies for session management
  };
  
  // Handle empty or invalid base URL
  if (!base) {
    // Try to use current origin as fallback
    const baseUrl = window.location.origin;
    const url = path.startsWith('http') ? new URL(path) : new URL(path, baseUrl);
    if (params && typeof params === 'object') {
      Object.entries(params).forEach(([k, v]) => {
        // Skip headers key if it somehow got into params
        if (k !== 'headers' && v !== null && v !== undefined) {
          url.searchParams.set(k, v);
        }
      });
    }
    // Disable browser cache
    headers.set('Cache-Control', 'no-cache');
    
    // Add timeout to fetch request
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    // For GET requests, create a promise and track it
    let requestPromise;
    if (method === 'GET') {
      const cacheKey = `${path}?${new URLSearchParams(params).toString()}`;
      requestPromise = (async () => {
        try {
          const response = await fetch(url.toString(), { 
            ...fetchOptions, 
            cache: 'no-store',
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          
          // Extract CSRF token from response headers if present (for all responses)
          const newCsrfToken = response.headers.get('X-CSRF-Token');
          if (newCsrfToken) {
            sessionStorage.setItem('csrf_token', newCsrfToken);
          }
          
          // Cache successful GET responses
          if (response.ok && response.status === 200) {
            try {
              const clonedResponse = response.clone();
              const data = await clonedResponse.json();
              _requestCache.set(cacheKey, { data, timestamp: Date.now() });
            } catch (e) {
              // Not JSON or can't cache, ignore
            }
          }
          
          return response;
        } finally {
          // Remove from pending requests when done
          _pendingRequests.delete(cacheKey);
        }
      })();
      _pendingRequests.set(cacheKey, requestPromise);
      return await requestPromise;
    }
    
    try {
      const response = await fetch(url.toString(), { 
        ...fetchOptions, 
        cache: 'no-store',
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      // Extract CSRF token from response headers if present (for all responses)
      const newCsrfToken = response.headers.get('X-CSRF-Token');
      if (newCsrfToken) {
        sessionStorage.setItem('csrf_token', newCsrfToken);
      }
      
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }
      throw error;
    }
  }
  
  try {
    const baseUrl = new URL(base);
    const url = path.startsWith('http') ? new URL(path) : new URL(path, baseUrl);
    if (params && typeof params === 'object') {
      Object.entries(params).forEach(([k, v]) => {
        // Skip headers key if it somehow got into params
        if (k !== 'headers' && v !== null && v !== undefined) {
          url.searchParams.set(k, v);
        }
      });
    }
    // Disable browser cache
    headers.set('Cache-Control', 'no-cache');
    
    // Add timeout to fetch request
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url.toString(), { 
        ...fetchOptions, 
        cache: 'no-store',
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      // Handle 401 responses by redirecting to login
      if (response.status === 401 && !window.location.pathname.includes('/login')) {
        window.location.href = '/login';
        throw new Error('Authentication required');
      }
      
      // Extract CSRF token from response headers if present
      const newCsrfToken = response.headers.get('X-CSRF-Token');
      if (newCsrfToken) {
        sessionStorage.setItem('csrf_token', newCsrfToken);
      }
      
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }
      throw error;
    }
  } catch (error) {
    // If base URL is invalid, try using current origin as fallback
    const baseUrl = window.location.origin;
    const url = path.startsWith('http') ? new URL(path) : new URL(path, baseUrl);
    if (params && typeof params === 'object') {
      Object.entries(params).forEach(([k, v]) => {
        // Skip headers key if it somehow got into params
        if (k !== 'headers' && v !== null && v !== undefined) {
          url.searchParams.set(k, v);
        }
      });
    }
    headers.set('Cache-Control', 'no-cache');
    
    // Add timeout to fetch request
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url.toString(), { 
        ...options, 
        headers, 
        cache: 'no-store',
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      // Handle 401 responses by redirecting to login
      if (response.status === 401 && !window.location.pathname.includes('/login')) {
        window.location.href = '/login';
        throw new Error('Authentication required');
      }
      
      // Extract CSRF token from response headers if present
      const newCsrfToken = response.headers.get('X-CSRF-Token');
      if (newCsrfToken) {
        sessionStorage.setItem('csrf_token', newCsrfToken);
      }
      
      return response;
    } catch (fetchError) {
      clearTimeout(timeoutId);
      if (fetchError.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }
      throw fetchError;
    }
  }
}

// API helper that surfaces errors to UI and throws on failure
async function apiJson(path, options = {}) {
  const res = await api(path, options);
  if (!res.ok) {
    const errText = await res.text().catch(() => `HTTP ${res.status}`);
    showStatus(`Error: ${errText}`);
    throw new Error(errText);
  }
  try {
    return await res.json();
  } catch (e) {
    showStatus('Error: Invalid JSON response');
    throw e;
  }
}

// Logging disabled for minimal output

// Reset Preparation UI/state so it can be reused for a new run
function resetPreparationForNewRun() {
  try {
    // Reset Authentication section
    const nhiSelect = el('nhiCredentialSelect');
    if (nhiSelect) nhiSelect.value = '';
    // Password field removed - no longer needed
    const nhiStatus = el('nhiLoadStatus');
    if (nhiStatus) nhiStatus.textContent = '';
    const hostSourceManual = el('hostSourceManual');
    if (hostSourceManual) hostSourceManual.checked = true;
    const hostSourceNhi = el('hostSourceNhi');
    if (hostSourceNhi) hostSourceNhi.checked = false;

    // Clear any stored credentials and tokens
    if (typeof currentNhiId !== 'undefined') currentNhiId = null;
    if (typeof showStatus === 'function') showStatus('Preparation reset');
    // Session-based: tokens are managed server-side, no need to clear local tokens

    // Clear templates array/state
    if (Array.isArray(templates)) templates.length = 0;

    // Clear rows
    const tplFormList = el('tplFormList');
    if (tplFormList) tplFormList.innerHTML = '';

    // Clear install dropdown and disable Run button
    const installSelect = el('installSelect');
    if (installSelect) {
      installSelect.innerHTML = '';
      installSelect.disabled = true;
    }
    const runBtn = el('btnInstallSelected');
    if (runBtn) runBtn.disabled = true;
    
    // Disable Add Row button
    const btnAddRow = el('btnAddRow');
    if (btnAddRow) btnAddRow.disabled = true;

    // Clear host inputs and chips/status
    const fabricHost = el('fabricHost');
    if (fabricHost) fabricHost.value = '';
    const fabricHostChips = el('fabricHostChips');
    if (fabricHostChips) fabricHostChips.innerHTML = '';
    const fabricHostStatus = el('fabricHostStatus');
    if (fabricHostStatus) fabricHostStatus.textContent = '';

    // Clear NHI derived hosts and status
    const fabricHostFromNhi = el('fabricHostFromNhi');
    if (fabricHostFromNhi) fabricHostFromNhi.value = '';
    const fabricHostFromNhiChips = el('fabricHostFromNhiChips');
    if (fabricHostFromNhiChips) fabricHostFromNhiChips.innerHTML = '';
    const fabricHostFromNhiStatus = el('fabricHostFromNhiStatus');
    if (fabricHostFromNhiStatus) fabricHostFromNhiStatus.textContent = '';

    // Reset confirmed hosts map
    if (Array.isArray(confirmedHosts)) confirmedHosts.length = 0;

    // Hide progress UI
    const runProgressContainer = el('runProgressContainer');
    if (runProgressContainer) runProgressContainer.style.display = 'none';
    const runProgressBar = el('runProgressBar');
    if (runProgressBar) runProgressBar.style.width = '0%';
    const runProgressText = el('runProgressText');
    if (runProgressText) runProgressText.textContent = '0%';
    const runProgressStatus = el('runProgressStatus');
    if (runProgressStatus) runProgressStatus.textContent = 'Initializing...';
    const runProgressTimer = el('runProgressTimer');
    if (runProgressTimer) runProgressTimer.textContent = '00:00';

    // Clear running tasks list
    const runningTasksContainer = el('runningTasksContainer');
    if (runningTasksContainer) runningTasksContainer.style.display = 'none';
    const tplList = el('tplList');
    if (tplList) tplList.innerHTML = '';

    // Re-enable inputs/buttons as initial state
    const addRowBtn = el('btnAddRow');
    if (addRowBtn) addRowBtn.disabled = false;

    // Clear status/notice area
    const actionStatus = el('actionStatus');
    if (actionStatus) actionStatus.style.display = 'none';
  } catch (e) {
    // Non-fatal; log only
  }
}

// Wire Reset button in Preparation UI
document.addEventListener('DOMContentLoaded', () => {
  const resetBtn = el('btnResetPreparation');
  if (resetBtn) {
    resetBtn.onclick = (e) => {
      e.preventDefault();
      resetPreparationForNewRun();
      if (typeof showStatus === 'function') showStatus('Preparation reset');
    };
  }
});
// Delegate reset click in case the button is injected after DOMContentLoaded
document.addEventListener('click', (e) => {
  const target = e.target;
  if (target && target.id === 'btnResetPreparation') {
    e.preventDefault();
    resetPreparationForNewRun();
    if (typeof showStatus === 'function') showStatus('Preparation reset');
  }
});
// Token acquisition function (now called from Install Workspace)
async function acquireTokens() {
  // Auto-confirm hosts if not already confirmed
  if (confirmedHosts.length === 0) {
    if (!autoConfirmHosts()) {
      showStatus('Please add at least one valid host');
      return false;
    }
  }
  
  // Check if NHI credential is loaded - if not, try to load it from the UI
  try {
    if (!currentNhiId) {
      const nhiSelect = el('nhiCredentialSelect');
      const selectedId = nhiSelect ? (nhiSelect.value || '') : '';
      if (selectedId) {
        // Load NHI credential which will create a session
        await loadSelectedNhiCredential();
      } else {
        showStatus('Please select NHI credential to acquire tokens');
        return false;
      }
    }
  } catch (e) {
    showStatus('Error loading NHI credential. Please try again.');
    return false;
  }
  
  // User is already authenticated via login - tokens are managed server-side
  await renderFabricHostList();
  return true;
}

function updateInstallSelect() {
  const select = el('installSelect');
  if (!select) return;
  
  const selVal = select.value;
  select.innerHTML = '';
  
  // First, collect templates from rows (workspaces that haven't been created yet)
  const rowTemplates = new Map();
  const allRows = document.querySelectorAll('.tpl-row');
  
  allRows.forEach((row, idx) => {
    const selects = row.querySelectorAll('select');
    const repoSelect = selects[0]; // Repo is the first select
    const templateFiltered = row._templateFiltered;
    // Version is the last select (index 2, because templateFiltered.container contains a hidden select at index 1)
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    const repo_name = repoSelect?.value || '';
    const template_name = templateFiltered ? templateFiltered.getValue() : '';
    const version = versionSelect?.value || '';
    
    
    // Require template_name and version to be non-empty (repo_name is optional but helpful)
    if (template_name && template_name.trim() && version && version.trim()) {
      const key = `${template_name}|||${version}`;
      if (!rowTemplates.has(key)) {
        rowTemplates.set(key, { template_name, version, repo_name });
      } else {
      }
    } else {
    }
  });
  
  // Only show templates from current rows (not from past runs)
  // Removed code that added templates from global 'templates' array to avoid showing past run templates
  
  // Convert to array and sort alphabetically
  const allOptions = Array.from(rowTemplates.values()).sort((a, b) => {
    const nameCompare = a.template_name.localeCompare(b.template_name);
    if (nameCompare !== 0) return nameCompare;
    return a.version.localeCompare(b.version);
  });
  
  // Add sorted options to dropdown
  allOptions.forEach(({template_name, version}) => {
    const opt = document.createElement('option');
    opt.value = `${template_name}|||${version}`;
    opt.textContent = `${template_name} (v${version})`;
    select.appendChild(opt);
  });
  
  // Restore selection if possible
  if (selVal) {
    const match = Array.from(select.options).find(o => o.value === selVal);
    if (match) select.value = selVal;
  } else if (select.options.length > 0) {
    select.value = select.options[0].value;
  }
  
  // Enable/disable controls
  const hasOptions = select.options.length > 0;
  const installBtn = el('btnInstallSelected');
  if (installBtn) {
    // If a run is in progress, always keep the button disabled
    if (isRunInProgress) {
      installBtn.disabled = true;
      return;
    }
    
    // Button should only be enabled if:
    // 1. Hosts are confirmed (auto-confirmed when available)
    // 2. AND (there are options OR all rows are filled)
    const hostsConfirmed = confirmedHosts && confirmedHosts.length > 0;
    const rows = Array.from(document.querySelectorAll('.tpl-row'));
    const allFilled = rows.length > 0 && rows.every(r => {
      const selects = r.querySelectorAll('select');
      const repoSelect = selects[0];
      const templateFiltered = r._templateFiltered;
      const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
      const repo_name = repoSelect?.value || '';
      const template_name = templateFiltered ? templateFiltered.getValue() : '';
      const version = versionSelect?.value || '';
      return Boolean(repo_name && template_name && version);
    });
    // Require hosts to be confirmed before enabling button
    installBtn.disabled = !hostsConfirmed || (!hasOptions && !allFilled);
  }
  select.disabled = !hasOptions;
}

function renderTemplates(showContainer = true) {
  const list = el('tplList');
  const container = el('runningTasksContainer');
  if (!list) return;
  
  list.innerHTML = '';
  
  // Filter to only show templates with progress (status === 'spin')
  const templatesWithProgress = templates.filter(t => t.status === 'spin');
  
  // Hide container if no tasks with progress
  if (container) {
    if (templatesWithProgress.length === 0) {
      container.style.display = 'none';
    } else if (showContainer) {
      container.style.display = '';
    }
  }
  
  if (templatesWithProgress.length === 0) {
    // Update install select dropdown even if no tasks to show
    updateInstallSelect();
    return;
  }
  
  // Sort templates alphabetically by template_name, then version for display
  const sortedTemplates = [...templatesWithProgress].sort((a, b) => {
    const nameCompare = a.template_name.localeCompare(b.template_name);
    if (nameCompare !== 0) return nameCompare;
    return a.version.localeCompare(b.version);
  });
  
  sortedTemplates.forEach((t, idx) => {
    const li = document.createElement('li');
    li.style.display = 'flex';
    li.style.alignItems = 'center';
    li.style.gap = '8px';
    li.style.marginBottom = '8px';
    li.style.padding = '6px 0';
    
    // Display: Host | Repo | Template Name | Version
    // Each template entry now represents one host, so show the single host
    // Get host from various possible fields (t.host, t.hosts array, or from confirmed hosts if available)
    let hostDisplay = t.host;
    if (!hostDisplay || hostDisplay === 'host' || hostDisplay === 'Host') {
      // Fallback to hosts array if available
      if (t.hosts && Array.isArray(t.hosts) && t.hosts.length > 0) {
        hostDisplay = t.hosts[0];
      } else {
        // Last resort: try to find host from confirmed hosts matching this template
        const allHosts = getAllConfirmedHosts();
        if (allHosts.length > 0) {
          // Use first host as fallback if we can't determine the specific host
          hostDisplay = allHosts[0].host;
        } else {
          hostDisplay = 'N/A';
        }
      }
    }
    
    // Task label
    const labelSpan = document.createElement('span');
    labelSpan.style.fontSize = '13px';
    labelSpan.style.fontWeight = '500';
    labelSpan.style.color = '#424245';
    labelSpan.style.minWidth = '200px';
    labelSpan.textContent = `${hostDisplay} | ${t.repo_name || 'N/A'} | ${t.template_name} | ${t.version}`;
    li.appendChild(labelSpan);
    
    // Determine task description based on progress type
    const progressVal = typeof t.createProgress === 'number' ? t.createProgress : (typeof t.installProgress === 'number' ? t.installProgress : 0);
    const isCreating = typeof t.createProgress === 'number' && t.createProgress !== undefined;
    const isInstalling = typeof t.installProgress === 'number' && t.installProgress !== undefined;
    
    let taskDescription = '';
    if (isCreating) {
      taskDescription = 'Creating workspace';
    } else if (isInstalling) {
      taskDescription = 'Installing workspace';
    } else {
      taskDescription = 'Processing';
    }
    
    // Task description
    const descSpan = document.createElement('span');
    descSpan.style.fontSize = '12px';
    descSpan.style.fontWeight = '400';
    descSpan.style.color = '#86868b';
    descSpan.style.minWidth = '120px';
    descSpan.textContent = taskDescription;
    li.appendChild(descSpan);
    
    // Progress bar container (matching overall progress bar style)
    const progressContainer = document.createElement('div');
    progressContainer.style.display = 'flex';
    progressContainer.style.alignItems = 'center';
    progressContainer.style.gap = '8px';
    progressContainer.style.flex = '1';
    
    const prog = document.createElement('div');
    prog.className = 'progress';
    prog.style.width = '400px';
    prog.style.height = '20px';
    prog.style.margin = '0';
    prog.style.background = '#e5e5e7';
    prog.style.border = '1px solid #d2d2d7';
    prog.style.borderRadius = '0';
    prog.style.overflow = 'hidden';
    prog.style.boxShadow = 'inset 0 1px 2px rgba(0,0,0,0.1)';
    prog.style.position = 'relative';
    
    const ind = document.createElement('span');
    ind.className = 'ind determinate';
    ind.style.background = 'linear-gradient(90deg, #34d399, #10b981)';
    ind.style.height = '100%';
    ind.style.borderRadius = '0';
    ind.style.transition = 'width 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
    ind.style.position = 'relative';
    ind.style.display = 'block';
    ind.style.boxShadow = '0 2px 8px rgba(16, 185, 129, 0.4)';
    
    const widthPct = Math.max(0, Math.min(100, progressVal || 0));
    
    // Force a reflow to ensure the transition is applied
    ind.style.width = '0%';
    ind.offsetHeight; // Force reflow
    ind.style.width = widthPct + '%';
    
    prog.appendChild(ind);
    progressContainer.appendChild(prog);
    
    // Percentage text
    const pct = document.createElement('span');
    pct.style.marginLeft = '0';
    pct.style.fontWeight = '600';
    pct.style.fontSize = '13px';
    pct.style.minWidth = '40px';
    pct.textContent = `${Math.round(widthPct)}%`;
    progressContainer.appendChild(pct);
    
    li.appendChild(progressContainer);
    list.appendChild(li);
  });
  
  // Update install select dropdown
  updateInstallSelect();
}

// Flag to bypass gating conditions after loading a configuration
let bypassGatingConditions = false;
// Flag to track if we're currently restoring a configuration
let isRestoringConfiguration = false;

function updateCreateEnabled() {
  const runBtn = el('btnInstallSelected');
  if (!runBtn) return;
  
  if (isRunInProgress) {
    runBtn.disabled = true;
    return;
  }
  
  // If we're bypassing gating conditions (configuration was loaded), always enable the button
  if (bypassGatingConditions) {
    runBtn.disabled = false;
    return;
  }
  
  // If we're restoring a configuration, always disable the button until restore is complete
  if (isRestoringConfiguration) {
    runBtn.disabled = true;
    return;
  }
  
  // Auto-confirm hosts if available
  if (confirmedHosts.length === 0) {
    autoConfirmHosts();
  }
  
  // Check if hosts are available
  const hostsConfirmed = confirmedHosts && confirmedHosts.length > 0;
  if (!hostsConfirmed) {
    runBtn.disabled = true;
    return;
  }
  
  // Check if NHI credentials are loaded
  const nhiLoaded = !!currentNhiId;
  if (!nhiLoaded) {
    runBtn.disabled = true;
    return;
  }
  
  // Both conditions are met, now check if rows are filled
  const rows = Array.from(document.querySelectorAll('.tpl-row'));
  const allNonEmpty = rows.length > 0 && rows.every(r => {
    const selects = r.querySelectorAll('select');
    const repoSelect = selects[0]; // Repo is the first select
    const templateFiltered = r._templateFiltered;
    // Version is the last select (hidden template select is at index 1)
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    const repo_name = repoSelect?.value || '';
    const template_name = templateFiltered ? templateFiltered.getValue() : '';
    const version = versionSelect?.value || '';
    return Boolean(repo_name && template_name && version);
  });
  // Enable Run button if all rows are filled AND credentials loaded AND hosts confirmed
  // The Run button will handle Install Workspace first
  runBtn.disabled = !allNonEmpty;
}
// Helper function to create filtered dropdown (input + datalist)
function createFilteredDropdown(placeholder, width = '130px') {
  const container = document.createElement('div');
  container.style.position = 'relative';
  container.style.display = 'inline-block';
  container.style.width = width;
  
  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = placeholder;
  input.style.width = '100%';
  input.style.margin = '0';
  input.style.padding = '6px 10px';
  input.style.border = '1px solid #d2d2d7';
  input.style.borderRadius = '0';
  input.style.fontSize = '13px';
  input.style.boxSizing = 'border-box';
  input.style.backgroundColor = 'white';
  input.autocomplete = 'off';
  
  const datalist = document.createElement('datalist');
  const datalistId = 'datalist-' + Math.random().toString(36).substr(2, 9);
  datalist.id = datalistId;
  input.setAttribute('list', datalistId);
  
  // Store all options and selected value
  let allOptions = [];
  let selectedValue = '';
  
  // Function to update datalist options
  function updateDatalist() {
    const filterText = input.value.toLowerCase().trim();
    
    // Clear existing options
    datalist.innerHTML = '';
    
    // If no filter, show all options
    if (!filterText) {
      allOptions.forEach(opt => {
        const option = document.createElement('option');
        option.value = opt.value || opt;
        option.textContent = opt.textContent || opt;
        datalist.appendChild(option);
      });
      return;
    }
    
    // Filter options
    allOptions.forEach(opt => {
      const text = (opt.textContent || opt).toLowerCase();
      if (text.includes(filterText)) {
        const option = document.createElement('option');
        option.value = opt.value || opt;
        option.textContent = opt.textContent || opt;
        datalist.appendChild(option);
      }
    });
  }
  
  // Create a hidden select for compatibility with existing code
  const hiddenSelect = document.createElement('select');
  hiddenSelect.style.display = 'none';
  
  // When input changes, update datalist
  input.addEventListener('input', () => {
    updateDatalist();
  });
  
  // When user selects from datalist or presses Enter
  input.addEventListener('change', () => {
    const value = input.value.trim();
    // Find matching option
    const matchedOption = allOptions.find(opt => {
      const optValue = opt.value || opt;
      const optText = opt.textContent || opt;
      return optValue === value || optText === value || optText.toLowerCase() === value.toLowerCase();
    });
    
    if (matchedOption) {
      selectedValue = matchedOption.value || matchedOption;
      input.value = matchedOption.textContent || matchedOption;
      // Update hidden select and dispatch change event for compatibility
      hiddenSelect.value = selectedValue;
      const changeEvent = new Event('change', { bubbles: true });
      hiddenSelect.dispatchEvent(changeEvent);
    }
  });
  
  // Handle Enter key to select from datalist
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      // Find first matching option
      const filterText = input.value.toLowerCase().trim();
      if (filterText) {
        const matchedOption = allOptions.find(opt => {
          const text = (opt.textContent || opt).toLowerCase();
          return text.includes(filterText);
        });
        if (matchedOption) {
          selectedValue = matchedOption.value || matchedOption;
          input.value = matchedOption.textContent || matchedOption;
          // Update hidden select and dispatch change event for compatibility
          hiddenSelect.value = selectedValue;
          const changeEvent = new Event('change', { bubbles: true });
          hiddenSelect.dispatchEvent(changeEvent);
          input.blur();
        }
      }
    }
  });
  
  // Populate options
  function populateOptions(options) {
    allOptions = [];
    hiddenSelect.innerHTML = ''; // Clear hidden select
    options.forEach(opt => {
      const option = opt.cloneNode ? opt.cloneNode(true) : {
        value: opt.value || opt,
        textContent: opt.textContent || opt
      };
      allOptions.push(option);
      
      // Also populate hidden select for compatibility
      const hiddenOpt = document.createElement('option');
      hiddenOpt.value = option.value || option;
      hiddenOpt.textContent = option.textContent || option;
      hiddenSelect.appendChild(hiddenOpt);
    });
    updateDatalist();
  }
  
  container.appendChild(input);
  container.appendChild(hiddenSelect);
  document.body.appendChild(datalist); // Append to body so datalist works
  
  return {
    container,
    select: hiddenSelect, // Expose hidden select for compatibility
    input,  // Expose input for direct access
    populateOptions,
    setValue: (value) => {
      const option = allOptions.find(opt => {
        const optValue = opt.value || opt;
        return optValue === value;
      });
      if (option) {
        selectedValue = option.value || option;
        input.value = option.textContent || option;
        hiddenSelect.value = value;
        const changeEvent = new Event('change', { bubbles: true });
        hiddenSelect.dispatchEvent(changeEvent);
      }
    },
    getValue: () => {
      if (selectedValue) return selectedValue;
      // Try to find matching value from input text
      const inputText = input.value.trim();
      const matched = allOptions.find(opt => {
        const optText = opt.textContent || opt;
        return optText === inputText || optText.toLowerCase() === inputText.toLowerCase();
      });
      return matched ? (matched.value || matched) : '';
    },
    disable: () => {
      input.disabled = true;
      input.style.backgroundColor = '#f5f5f7';
    },
    enable: () => {
      input.disabled = false;
      input.style.backgroundColor = 'white';
    }
  };
}

// Dynamic rows for template input
function addTplRow(prefill) {
  const container = el('tplFormList');
  const row = document.createElement('div');
  row.className = 'row tpl-row';
  
  // Repo is a regular dropdown (no filtering)
  const r = document.createElement('select');
  r.disabled = false; // Enable by default - will be populated from cache
  const optRepoPh = document.createElement('option');
  optRepoPh.value = '';
  optRepoPh.textContent = 'Select repo';
  r.appendChild(optRepoPh);
  
  // Populate repositories from cache
  const populateReposFromCache = () => {
    const cachedTemplates = window.cachedTemplates || [];
    const repos = Array.from(new Set(cachedTemplates.map(t => t.repo_name).filter(Boolean))).sort();
    repos.forEach(repoName => {
      const opt = document.createElement('option');
      opt.value = repoName;
      opt.textContent = repoName;
      r.appendChild(opt);
    });
  };
  
  // Load cache if not already loaded, then populate repos
  if (!window.cachedTemplates || window.cachedTemplates.length === 0) {
    // Load cache asynchronously, then populate
    (async () => {
      try {
        const cacheData = await apiJson('/cache/templates');
        window.cachedTemplates = cacheData.templates || [];
        populateReposFromCache();
      } catch (error) {
        console.error('Error loading cached templates:', error);
      }
    })();
  } else {
    // Cache already loaded - populate immediately
    populateReposFromCache();
  }
  
  // Template is a filtered dropdown with text input
  const templateFiltered = createFilteredDropdown('Select template', '250px');
  const t = templateFiltered.select;
  
  // Version stays as regular select
  const v = document.createElement('select');
  v.disabled = true;
  const optVerPh = document.createElement('option'); optVerPh.value = ''; optVerPh.textContent = 'Select version'; v.appendChild(optVerPh);
  
  const rm = document.createElement('button'); rm.textContent = 'Remove'; rm.onclick = (e) => { 
    e.preventDefault(); 
    row.remove(); 
    updateCreateEnabled();
    updateInstallSelect(); // Update dropdown when row is removed
  };
  
  row.appendChild(document.createTextNode('Repo'));
  row.appendChild(r);
  row.appendChild(document.createTextNode(' Template'));
  row.appendChild(templateFiltered.container);
  row.appendChild(document.createTextNode(' Version'));
  row.appendChild(v);
  row.appendChild(rm);
  container.appendChild(row);
  
  // Store filtered dropdown references in the row for later access
  row._templateFiltered = templateFiltered;

  // Add change listeners
  r.addEventListener('change', () => {
    updateCreateEnabled();
    updateInstallSelect();
  });
  t.addEventListener('change', () => {
    updateCreateEnabled();
    updateInstallSelect();
  });
  v.addEventListener('change', () => {
    updateCreateEnabled();
    updateInstallSelect();
  });

  // Handle repository change - populate templates from cache
  r.addEventListener('change', () => {
    const repo_name = r.value;
    templateFiltered.populateOptions([]);
    templateFiltered.disable();
    v.innerHTML = '';
    const vph = document.createElement('option');
    vph.value = '';
    vph.textContent = 'Select version';
    v.appendChild(vph);
    v.disabled = true;
    
    if (!repo_name) return;
    
    // Get unique template names for this repo from cache
    const cachedTemplates = window.cachedTemplates || [];
    const templatesForRepo = cachedTemplates.filter(t => t.repo_name === repo_name);
    const uniqueNames = Array.from(new Set(templatesForRepo.map(t => t.template_name).filter(Boolean))).sort();
    
    const templateOptions = uniqueNames.map(name => {
      const o = document.createElement('option');
      o.value = name;
      o.textContent = name;
      return o;
    });
    
    templateFiltered.populateOptions(templateOptions);
    templateFiltered.enable();
  });

  // Handle template change - populate versions from cache
  const handleTemplateChange = () => {
    const repo_name = r.value;
    const template_name = templateFiltered ? templateFiltered.getValue() : t.value;
    
    v.innerHTML = '';
    const vph = document.createElement('option');
    vph.value = '';
    vph.textContent = 'Select version';
    v.appendChild(vph);
    v.disabled = true;
    
    if (!repo_name || !template_name) {
      return;
    }
    
    // Get versions for this repo+template from cache
    const cachedTemplates = window.cachedTemplates || [];
    const matchingTemplates = cachedTemplates.filter(t => {
      return t.repo_name === repo_name && t.template_name === template_name && t.version;
    });
    
    const versions = matchingTemplates
      .map(t => t.version)
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    
    versions.forEach(ver => {
      const o = document.createElement('option');
      o.value = ver;
      o.textContent = ver;
      v.appendChild(o);
    });
    
    v.disabled = false;
    
    // Prefill version if provided
    if (prefill && prefill.version && v.options.length > 1) {
      const versionOpt = Array.from(v.options).find(opt => opt.value === prefill.version);
      if (versionOpt) v.value = prefill.version;
    }
  };
  
  // Listen to both the hidden select and the filtered input
  t.addEventListener('change', handleTemplateChange);
  if (templateFiltered.input) {
    templateFiltered.input.addEventListener('change', () => {
      setTimeout(() => {
        handleTemplateChange();
      }, 100);
    });
    templateFiltered.input.addEventListener('blur', () => {
      setTimeout(() => {
        handleTemplateChange();
      }, 100);
    });
  }
  
  // Prefill values if provided
  if (prefill) {
    // Wait for repos to load, then prefill
    setTimeout(async () => {
      if (prefill.repo_name && r.options.length > 1) {
        const repoOpt = Array.from(r.options).find(opt => opt.value === prefill.repo_name);
        if (repoOpt) {
          r.value = prefill.repo_name;
          r.dispatchEvent(new Event('change'));
          
          // Wait for templates to load
          setTimeout(async () => {
            if (prefill.template_name) {
              templateFiltered.setValue(prefill.template_name);
              t.dispatchEvent(new Event('change'));
              
              // Wait for versions to load
              setTimeout(() => {
                if (prefill.version && v.options.length > 1) {
                  const verOpt = Array.from(v.options).find(opt => opt.value === prefill.version);
                  if (verOpt) v.value = prefill.version;
                }
              }, 500);
            }
          }, 500);
        }
      }
    }, 300);
  }
}

// Button handlers are set up in initializePreparationSection() when elements are loaded

// Menu navigation
async function loadSection(sectionName) {
  const container = document.getElementById('content-container');
  if (!container) {
    return;
  }
  
  // Check cache first to avoid duplicate requests
  if (_htmlCache.has(sectionName)) {
    container.innerHTML = _htmlCache.get(sectionName);
    // Wait for DOM to update, then initialize section-specific functionality
    setTimeout(() => {
      initializeSection(sectionName);
    }, 50);
    return;
  }
  
  const url = `/${sectionName}.html`;
  
  try {
    // Fetch HTML from root path
    const response = await fetch(url);
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      container.innerHTML = `<div class="content-section"><p style="color: #f87171;">Error loading ${sectionName} section: ${response.status} ${response.statusText}</p><pre>${errorText}</pre></div>`;
      return;
    }
    
    const html = await response.text();
    // Cache the HTML content
    _htmlCache.set(sectionName, html);
    container.innerHTML = html;
    
    // Wait for DOM to update, then initialize section-specific functionality
    setTimeout(() => {
      initializeSection(sectionName);
    }, 50);
  } catch (error) {
    container.innerHTML = `<div class="content-section"><p style="color: #f87171;">Error loading ${sectionName} section: ${error.message}</p></div>`;
  }
}
function initializeSection(sectionName) {
  // Section-specific initialization
  if (sectionName === 'configurations') {
    // Unified configurations section - show list view by default
    const listView = el('configsListView');
    const editView = el('configEditView');
    const runView = el('configRunView');
    if (listView) listView.style.display = 'block';
    if (editView) editView.style.display = 'none';
    if (runView) runView.style.display = 'none';
    
    // Clear configuration name banner when navigating to configurations section
    // (unless we're in the middle of loading a configuration)
    if (!window.isLoadingConfiguration) {
      clearConfigName();
    }
    
    loadConfigurations();
    setupConfigButtons();
  } else if (sectionName === 'event-schedule') {
    initEventFormValidation();
    setupEventButtons();
    loadEventConfigs();
    loadEvents();
    setTimeout(() => updateCreateEventButton(), 100);
  } else if (sectionName === 'nhi-management') {
    initNhiFormValidation();
    setupNhiButtons();
    loadNhiCredentials();
    setTimeout(() => updateNhiButtons(), 100);
  } else if (sectionName === 'ssh-keys') {
    // SSH Keys section initialization
    initSshKeyFormValidation();
    setupSshKeyButtons();
    loadSshKeys();
  } else if (sectionName === 'ssh-command-profiles') {
    // SSH Command Profiles section initialization
    initSshCommandProfileFormValidation();
    setupSshCommandProfileButtons();
    loadSshCommandProfiles();
  } else if (sectionName === 'audit-logs') {
    // Audit Logs section initialization
    setupAuditLogsButtons();
    loadAuditLogs();
  } else if (sectionName === 'server-logs') {
    // Server Logs initialization
    setupServerLogsButtons();
    loadServerLogs();
  } else if (sectionName === 'reports') {
    // Reports section initialization
    setupReportsButtons();
    loadReports();
  } else if (sectionName === 'user-management') {
    // User Management section initialization
    setupUserManagement();
  }
}

function initializePreparationSection() {
  // Clear actionStatus when initializing preparation section
  const actionStatus = el('actionStatus');
  if (actionStatus) {
    actionStatus.style.display = 'none';
    const messageEl = el('actionStatusMessage');
    if (messageEl) messageEl.innerHTML = '';
    const progressSection = el('actionStatusProgress');
    if (progressSection) progressSection.style.display = 'none';
  }
  
  // Initialize validatedHosts array
  if (typeof validatedHosts === 'undefined') {
    validatedHosts = [];
  }
  if (!window.validatedNhiHosts) {
    window.validatedNhiHosts = [];
  }
  
  // Load cached templates for use in template rows
  if (!window.cachedTemplates || window.cachedTemplates.length === 0) {
    (async () => {
      try {
        const cacheData = await apiJson('/cache/templates');
        window.cachedTemplates = cacheData.templates || [];
      } catch (error) {
        console.error('Error loading cached templates:', error);
      }
    })();
  }
  
  // Initialize fabric host input listeners
  const fh = el('fabricHost');
  if (fh) {
    let lastValue = '';
    
    fh.addEventListener('input', (e) => {
      const value = e.target.value;
      if (value.length > lastValue.length && value.endsWith(' ')) {
        const spaceIndex = value.lastIndexOf(' ');
        const parts = value.substring(0, spaceIndex).split(/\s+/).filter(p => p.trim());
        if (parts.length > 0) {
          const lastHost = parts[parts.length - 1];
          const isValid = validateAndAddHost(lastHost);
          if (isValid) {
            const validatedStr = validatedHosts.map(({host, port}) => 
              host + (port !== undefined ? ':' + port : '')
            ).join(' ');
            e.target.value = validatedStr + ' ';
            
            setTimeout(() => {
              e.target.setSelectionRange(e.target.value.length, e.target.value.length);
            }, 0);
          } else {
            // Remove trailing space if host is invalid
            e.target.value = value.trimEnd();
          }
        }
        renderHostChips();
        updateValidationStatus();
      } else if (value.length < lastValue.length) {
        if (value.trim() === '' || value === '') {
          validatedHosts = [];
          renderHostChips();
          updateValidationStatus();
        } else {
          const currentParts = value.trim().split(/\s+/).filter(p => p.trim());
          const newValidatedHosts = [];
          currentParts.forEach(part => {
            const {host, port} = splitHostPort(part.trim());
            const existing = validatedHosts.find(vh => 
              vh.host === host && vh.port === port
            );
            if (existing) {
              newValidatedHosts.push(existing);
            }
          });
          validatedHosts = newValidatedHosts;
          renderHostChips();
          updateValidationStatus();
        }
      }
      
      lastValue = value;
    });
    
    fh.addEventListener('blur', () => {
      const currentValue = fh.value.trim();
      if (currentValue && !currentValue.endsWith(' ')) {
        const parts = currentValue.split(/\s+/).filter(p => p.trim());
        if (parts.length > 0) {
          const lastPart = parts[parts.length - 1];
          const exists = validatedHosts.some(vh => {
            const {host, port} = splitHostPort(lastPart);
            return vh.host === host && vh.port === port;
          });
          if (!exists) {
            validateAndAddHost(lastPart);
            renderHostChips();
            updateValidationStatus();
          }
        }
      }
      validateFabricHosts(true);
    });
    
    fh.addEventListener('dblclick', (e) => {
      if (e.target.readOnly) {
        validatedHosts = [];
        e.target.value = '';
        e.target.readOnly = false;
        e.target.style.backgroundColor = '';
        e.target.style.cursor = '';
        renderHostChips();
        updateValidationStatus();
        e.target.focus();
      }
    });
  }
  
  // Initialize NHI hosts input listeners
  const fhFromNhi = el('fabricHostFromNhi');
  if (fhFromNhi) {
    let lastValueNhi = '';
    
    fhFromNhi.addEventListener('input', (e) => {
      if (e.target.disabled) return;
      
      const value = e.target.value;
      const currentValue = value.trim();
      
      if (value.length > lastValueNhi.length && value.endsWith(' ')) {
        const spaceIndex = value.lastIndexOf(' ');
        const parts = value.substring(0, spaceIndex).split(/\s+/).filter(p => p.trim());
        if (parts.length > 0) {
          const lastHost = parts[parts.length - 1];
          const {host: parsedHost, port: parsedPort} = splitHostPort(lastHost);
          const alreadyExists = window.validatedNhiHosts.some(vh => 
            vh.host === parsedHost && vh.port === parsedPort
          );
          
          if (!alreadyExists) {
            const isValid = validateAndAddHostToArray(lastHost, window.validatedNhiHosts);
            if (isValid) {
              const validatedStr = window.validatedNhiHosts.map(({host, port}) => 
                host + (port !== undefined ? ':' + port : '')
              ).join(' ');
              e.target.value = validatedStr + ' ';
              
              setTimeout(() => {
                e.target.setSelectionRange(e.target.value.length, e.target.value.length);
              }, 0);
            } else {
              e.target.value = value.trimEnd();
              lastValueNhi = e.target.value;
              return;
            }
            
            renderHostChipsForTarget('fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus', window.validatedNhiHosts, (host, port) => !isHostInManualList(host, port));
          }
        }
      } else if (value.length < lastValueNhi.length) {
        if (currentValue === '' || value === '') {
          window.validatedNhiHosts = [];
          renderHostChipsForTarget('fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus', window.validatedNhiHosts, (host, port) => !isHostInManualList(host, port));
        } else {
          const currentParts = currentValue.split(/\s+/).filter(p => p.trim());
          const newValidatedHosts = [];
          currentParts.forEach(part => {
            const {host, port} = splitHostPort(part.trim());
            const existing = window.validatedNhiHosts.find(vh => 
              vh.host === host && vh.port === port
            );
            if (existing) {
              newValidatedHosts.push(existing);
            }
          });
          window.validatedNhiHosts = newValidatedHosts;
          renderHostChipsForTarget('fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus', window.validatedNhiHosts, (host, port) => !isHostInManualList(host, port));
        }
      }
      
      lastValueNhi = value;
    });
    
    fhFromNhi.addEventListener('blur', () => {
      const currentValue = fhFromNhi.value.trim();
      if (currentValue && !currentValue.endsWith(' ')) {
        populateHostsFromInput(currentValue, 'fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus');
      }
    });
    
    fhFromNhi.addEventListener('dblclick', (e) => {
      if (e.target.readOnly && !e.target.disabled) {
        window.validatedNhiHosts = [];
        e.target.value = '';
        e.target.readOnly = false;
        e.target.style.backgroundColor = '';
        e.target.style.cursor = '';
        renderHostChipsForTarget('fabricHostFromNhi', 'fabricHostFromNhiChips', 'fabricHostFromNhiStatus', window.validatedNhiHosts, (host, port) => !isHostInManualList(host, port));
        e.target.focus();
      }
    });
  }
  
  // Load NHI credentials and SSH profiles in parallel to avoid duplicate calls
  Promise.all([
    loadNhiCredentialsForAuth(),
    loadSshProfilesForPreparation()
  ]).catch(err => {
    console.error('Error loading preparation data:', err);
  });
  
  // Set up expert mode toggle
  const exp = el('expertMode');
  if (exp) {
    exp.addEventListener('change', () => {
      const out = el('out');
      if (out) {
        if (exp.checked) {
          out.style.display = '';
        } else {
          out.style.display = 'none';
          // Clear output when disabling Expert Mode
          out.textContent = '';
        }
      }
    });
  }
  
  // Set up button handlers for preparation section
  // Auto-load NHI credential when selected
  const nhiSelect = el('nhiCredentialSelect');
  if (nhiSelect) {
    nhiSelect.addEventListener('change', async () => {
      if (nhiSelect.value) {
        await loadSelectedNhiCredential();
      }
    });
  }
  
  // Confirm button removed - hosts are automatically confirmed when available
  
  // Set up button handlers for preparation section
  const addRowBtn = el('btnAddRow');
  if (addRowBtn) {
    addRowBtn.onclick = async (e) => {
      e.preventDefault();
      // Ensure cache is loaded before adding row
      if (!window.cachedTemplates || window.cachedTemplates.length === 0) {
        try {
          const cacheRes = await api('/cache/templates');
          if (cacheRes.ok) {
            const cacheData = await cacheRes.json();
            window.cachedTemplates = cacheData.templates || [];
          }
        } catch (error) {
          console.error('Error loading cached templates:', error);
        }
      }
      addTplRow();
      updateCreateEnabled();
    };
  }
  
  // Attach run button handler (defined below at module level)
  const runBtn = el('btnInstallSelected');
  if (runBtn) {
    // Handler will be attached by the module-level assignment below
    // But we need to ensure it's set here since element may not exist when module loads
    attachRunButtonHandler();
  }
  
  // Attach save button handler (defined below at module level)
  const saveBtn = el('btnSaveConfig');
  if (saveBtn) {
    attachSaveButtonHandler();
  }
  
  // Attach cancel button handler
  const cancelBtn = el('btnCancelConfig');
  if (cancelBtn) {
    cancelBtn.onclick = (e) => {
      e.preventDefault();
      clearConfigName();
      resetPreparationSection();
      showStatus('Configuration cancelled. Form reset.');
    };
  }
  
  updateCreateEnabled();
  updateInstallSelect();
  renderTemplates(false);
}
function initMenu() {
  const menuItems = document.querySelectorAll('.menu-item');
  
  if (menuItems.length === 0) {
    return;
  }
  
  // Handle parent menu items (with submenus)
  const menuGroups = document.querySelectorAll('.menu-group');
  menuGroups.forEach(group => {
    const parentButton = group.querySelector('.menu-parent');
    if (parentButton) {
      parentButton.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // Toggle submenu expansion
        const isExpanded = group.classList.contains('expanded');
        group.classList.toggle('expanded');
        
        if (!isExpanded) {
          // Expanding: load the first submenu item
          const firstSubmenuItem = group.querySelector('.submenu-item');
          if (firstSubmenuItem) {
            // Remove active class from all items
            document.querySelectorAll('.menu-item').forEach(mi => mi.classList.remove('active'));
            // Add active class to first submenu item
            firstSubmenuItem.classList.add('active');
            // Load the section
            const section = firstSubmenuItem.getAttribute('data-section');
            if (section) {
              loadSection(section);
            }
          }
        }
        // If collapsing, do nothing - just let the menu collapse
      });
    }
  });
  
  // Handle all menu item clicks (including submenu items)
  menuItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      // Skip if this is a parent menu item (let the group handler handle it)
      if (item.classList.contains('menu-parent')) {
        return;
      }
      
      const section = item.getAttribute('data-section');
      
      if (!section) {
        return;
      }
      
      // Remove active class from all items
      menuItems.forEach(mi => mi.classList.remove('active'));
      
      // Add active class to clicked item
      item.classList.add('active');
      
      // Expand parent menu group if this is a submenu item
      const menuGroup = item.closest('.menu-group');
      if (menuGroup) {
        menuGroup.classList.add('expanded');
      }
      
      // Load the section HTML file
      loadSection(section);
    });
  });
  
  // Expand NHI Management menu by default if it's the active section
  const nhiManagementGroup = document.querySelector('#nhi-management-menu')?.closest('.menu-group');
  if (nhiManagementGroup) {
    const activeSubmenuItem = nhiManagementGroup.querySelector('.submenu-item.active');
    if (activeSubmenuItem) {
      nhiManagementGroup.classList.add('expanded');
    }
  }
  
  // Handle logout button
  const logoutBtn = el('btnLogout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      try {
        const res = await api('/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        
        if (res.ok) {
          // Clear any cached data
          sessionStorage.clear();
          // Redirect to login page
          window.location.href = '/login';
        } else {
          showStatus('Failed to logout. Please try again.', { error: true });
        }
      } catch (error) {
        console.error('Logout error:', error);
        // Even if there's an error, try to redirect to login
        sessionStorage.clear();
        window.location.href = '/login';
      }
    });
  }
  
  // Expand Logs menu by default if it's the active section
  const logsGroup = document.querySelector('#logs-menu')?.closest('.menu-group');
  if (logsGroup) {
    const activeSubmenuItem = logsGroup.querySelector('.submenu-item.active');
    if (activeSubmenuItem) {
      logsGroup.classList.add('expanded');
    }
  }
  
  // Expand Preparation menu by default if it's the active section
  // This now includes: Run Configuration, Saved Configurations, SSH Commands Profile, Reports
  const preparationGroup = document.querySelector('#preparation-menu')?.closest('.menu-group');
  if (preparationGroup) {
    const activeSubmenuItem = preparationGroup.querySelector('.submenu-item.active');
    if (activeSubmenuItem) {
      preparationGroup.classList.add('expanded');
    }
    // If the parent is active but no submenu item is active, activate the first one
    const parentButton = preparationGroup.querySelector('.menu-parent');
    if (parentButton && parentButton.classList.contains('active')) {
      const firstSubmenuItem = preparationGroup.querySelector('.submenu-item');
      if (firstSubmenuItem && !firstSubmenuItem.classList.contains('active')) {
        firstSubmenuItem.classList.add('active');
        parentButton.classList.remove('active');
        preparationGroup.classList.add('expanded');
      }
    }
  }
  
  // Load the default section (preparation) on initial load
  const activeItem = document.querySelector('.menu-item.active');
  if (activeItem) {
    const defaultSection = activeItem.getAttribute('data-section');
    if (defaultSection) {
      loadSection(defaultSection);
    }
  } else {
    loadSection('preparation');
  }
}

// Display configuration name at top of page
function displayConfigName(name) {
  const display = el('configNameDisplay');
  const value = el('configNameValue');
  if (display && value) {
    if (name && name.trim()) {
      value.textContent = name.trim();
      display.style.display = 'block';
    } else {
      display.style.display = 'none';
    }
  }
}

// Clear configuration name display
function clearConfigName() {
  displayConfigName(null);
}

// Reset all inputs in FabricStudio Runs section
function resetPreparationSection() {
  // Reset bypass flag when resetting section
  bypassGatingConditions = false;
  
  // Reset all input fields
  const fabricHost = el('fabricHost');
  if (fabricHost) {
    fabricHost.value = '';
    fabricHost.readOnly = false;
    fabricHost.style.backgroundColor = '';
    fabricHost.style.cursor = '';
  }
  
  // Clear host chips
  const fabricHostChips = el('fabricHostChips');
  if (fabricHostChips) fabricHostChips.innerHTML = '';
  const fabricHostStatus = el('fabricHostStatus');
  if (fabricHostStatus) {
    fabricHostStatus.textContent = '';
    fabricHostStatus.className = 'status';
  }
  
  // Reset NHI credential inputs
  const nhiCredentialSelect = el('nhiCredentialSelect');
  if (nhiCredentialSelect) nhiCredentialSelect.value = '';
  // Password field removed - no longer needed
  const nhiLoadStatus = el('nhiLoadStatus');
  if (nhiLoadStatus) {
    nhiLoadStatus.textContent = '';
    nhiLoadStatus.style.color = '';
  }
  
  // Reset NHI credential host field
  const fabricHostFromNhi = el('fabricHostFromNhi');
  if (fabricHostFromNhi) {
    fabricHostFromNhi.value = '';
    fabricHostFromNhi.disabled = true;
    fabricHostFromNhi.style.backgroundColor = '#f5f5f7';
    fabricHostFromNhi.style.cursor = 'not-allowed';
  }
  const fabricHostFromNhiChips = el('fabricHostFromNhiChips');
  if (fabricHostFromNhiChips) fabricHostFromNhiChips.innerHTML = '';
  const fabricHostFromNhiStatus = el('fabricHostFromNhiStatus');
  if (fabricHostFromNhiStatus) {
    fabricHostFromNhiStatus.textContent = '';
    fabricHostFromNhiStatus.className = 'status';
  }
  
  // Reset host source radio buttons
  const hostSourceManual = el('hostSourceManual');
  if (hostSourceManual) hostSourceManual.checked = true;
  const hostSourceNhi = el('hostSourceNhi');
  if (hostSourceNhi) {
    hostSourceNhi.checked = false;
    hostSourceNhi.disabled = true;
  }
  
  // Reset other fields
  const newHostname = el('newHostname');
  if (newHostname) newHostname.value = '';
  const chgPass = el('chgPass');
  if (chgPass) chgPass.value = '';
  const expertMode = el('expertMode');
  if (expertMode) expertMode.checked = false;
  
  // Hide expert mode output
  const out = el('out');
  if (out) out.style.display = 'none';
  
  // Clear template rows
  const tplFormList = el('tplFormList');
  if (tplFormList) tplFormList.innerHTML = '';
  
  // Clear install select
  const installSelect = el('installSelect');
  if (installSelect) {
    installSelect.innerHTML = '';
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Select template';
    installSelect.appendChild(placeholder);
    installSelect.disabled = true;
  }
  
  // Reset state variables
  confirmedHosts = [];
  validatedHosts = [];
  if (window.validatedNhiHosts) window.validatedNhiHosts = [];
  // Session-based: tokens are managed server-side, no need to clear local tokens
  currentNhiId = null;
  
  // Clear fabric host list
  const fabricHostList = el('fabricHostList');
  if (fabricHostList) fabricHostList.innerHTML = '';
  
  // Reset buttons
  // Confirm button removed - hosts are auto-confirmed
  // Disable Add Row button
  const btnAddRow = el('btnAddRow');
  if (btnAddRow) btnAddRow.disabled = true;
  const btnInstallSelected = el('btnInstallSelected');
  if (btnInstallSelected) btnInstallSelected.disabled = true;
  
  // Clear templates array
  templates = [];
  renderTemplates();
}

// Load configurations for event schedule dropdown
async function loadEventConfigs() {
  const select = el('eventConfigSelect');
  if (!select) return;
  
  try {
    const res = await api('/config/list');
    if (!res.ok) {
      return;
    }
    
    const data = await res.json();
    select.innerHTML = '<option value="">Select a configuration...</option>';
    
    if (data.configurations && data.configurations.length > 0) {
      data.configurations.forEach(config => {
        const option = document.createElement('option');
        option.value = config.id;
        option.textContent = config.name || `Configuration ${config.id}`;
        select.appendChild(option);
      });
    }
  } catch (error) {
  }
}

// Helper function to format date/time as DD/MM/YYYY HH:MM
function formatDateTime(dateString) {
  if (!dateString) return 'N/A';
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return dateString; // Return original if invalid
    
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    
    return `${day}/${month}/${year} ${hours}:${minutes}`;
  } catch (e) {
    return dateString;
  }
}

// Helper function to format date only as DD/MM/YYYY
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return dateString; // Return original if invalid
    
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    
    return `${day}/${month}/${year}`;
  } catch (e) {
    return dateString;
  }
}

// Helper functions for UTC/local timezone conversion using dayjs
// Falls back to native Date if dayjs is not available
function localToUTC(dateStr, timeStr) {
  // Convert local date/time to UTC
  // dateStr: YYYY-MM-DD, timeStr: HH:MM
  if (!dateStr) return { date: null, time: null };
  
  try {
    // Use dayjs if available, otherwise fall back to native Date
    if (typeof dayjs !== 'undefined' && dayjs.utc) {
      const timePart = (timeStr && timeStr.trim()) ? timeStr.trim() + ':00' : '00:00';
      const localDateTime = dayjs(`${dateStr}T${timePart}`);
      
      if (!localDateTime.isValid()) {
        return { date: dateStr, time: timeStr || null };
      }
      
      const utcDateTime = localDateTime.utc();
      const utcDate = utcDateTime.format('YYYY-MM-DD');
      const utcTime = timeStr ? utcDateTime.format('HH:mm') : null;
      
      return { date: utcDate, time: utcTime };
    } else {
      // Fallback to native Date
      const localDateTime = new Date(dateStr + (timeStr ? 'T' + timeStr + ':00' : 'T00:00:00'));
      const utcDate = localDateTime.toISOString().split('T')[0];
      const utcTime = localDateTime.toISOString().split('T')[1].substring(0, 5);
      return { date: utcDate, time: timeStr ? utcTime : null };
    }
  } catch (e) {
    return { date: dateStr, time: timeStr || null };
  }
}

function utcToLocal(dateStr, timeStr) {
  // Convert UTC date/time to local
  // dateStr: YYYY-MM-DD, timeStr: HH:MM (UTC)
  if (!dateStr) return { date: null, time: null };
  
  try {
    // Use dayjs if available, otherwise fall back to native Date
    if (typeof dayjs !== 'undefined' && dayjs.utc) {
      const timePart = (timeStr && timeStr.trim()) ? timeStr.trim() + ':00' : '00:00';
      const utcDateTime = dayjs.utc(`${dateStr}T${timePart}`);
      
      if (!utcDateTime.isValid()) {
        return { date: dateStr, time: timeStr || null };
      }
      
      const localDateTime = utcDateTime.local();
      const localDate = localDateTime.format('YYYY-MM-DD');
      const localTime = (timeStr && timeStr.trim()) ? localDateTime.format('HH:mm') : null;
      
      return { date: localDate, time: localTime };
    } else {
      // Fallback to native Date
      const timePart = (timeStr && timeStr.trim()) ? timeStr.trim() + ':00:00' : '00:00:00';
      const utcDateTime = new Date(dateStr + 'T' + timePart + 'Z');
      
      if (isNaN(utcDateTime.getTime())) {
        return { date: dateStr, time: timeStr || null };
      }
      
      const year = utcDateTime.getFullYear();
      const month = String(utcDateTime.getMonth() + 1).padStart(2, '0');
      const day = String(utcDateTime.getDate()).padStart(2, '0');
      const hours = String(utcDateTime.getHours()).padStart(2, '0');
      const minutes = String(utcDateTime.getMinutes()).padStart(2, '0');
      
      return { 
        date: `${year}-${month}-${day}`, 
        time: (timeStr && timeStr.trim()) ? `${hours}:${minutes}` : null 
      };
    }
  } catch (e) {
    return { date: dateStr, time: timeStr || null };
  }
}
// Load and display events
async function loadEvents() {
  if (!eventsList) return;
  
  eventsList.innerHTML = '<p>Loading events...</p>';
  
  try {
    const res = await api('/event/list');
    if (!res.ok) {
      eventsList.innerHTML = '<p style="color: #f87171;">Error loading events</p>';
      return;
    }
    
    const data = await res.json();
    const events = data.events || [];
    
    // Fallback: if has_executions is undefined, fetch executions to determine it
    const enrichedEvents = await Promise.all(events.map(async (ev) => {
      if (ev && ev.auto_run && typeof ev.has_executions === 'undefined') {
        try {
          const exRes = await api(`/event/executions/${ev.id}`);
          if (exRes.ok) {
            const exData = await exRes.json();
            const exCount = (exData && Array.isArray(exData.executions)) ? exData.executions.length : 0;
            ev.has_executions = exCount > 0;
          } else {
            ev.has_executions = false;
          }
        } catch (_) {
          ev.has_executions = false;
        }
      }
      return ev;
    }));

    if (enrichedEvents.length === 0) {
      eventsList.innerHTML = '<p>No events scheduled.</p>';
      return;
    }
    
    // Add "Select All" / "Deselect All" functionality
    let html = `
      <div style="margin-bottom: 12px; padding: 8px; border: 1px solid #d2d2d7; background: #fafafa; border-radius: 4px;">
        <button id="btnSelectAllEvents" style="padding: 4px 12px; font-size: 12px; margin-right: 8px;">Select All</button>
        <button id="btnDeselectAllEvents" style="padding: 4px 12px; font-size: 12px;">Deselect All</button>
      </div>
    `;
    html += '<div style="display: flex; flex-direction: column; gap: 12px;">';
    enrichedEvents.forEach(event => {
      // Convert UTC date/time from backend to local time for display using dayjs
      let dateTimeDisplay;
      try {
        if (event.event_date) {
          // Backend stores date/time in UTC, convert to local for display
          if (typeof dayjs !== 'undefined' && dayjs.utc) {
            const timePart = (event.event_time && event.event_time.trim()) ? event.event_time.trim() + ':00' : '00:00';
            const utcDateTime = dayjs.utc(`${event.event_date}T${timePart}`);
            
            if (utcDateTime.isValid()) {
              const localDateTime = utcDateTime.local();
              const localDate = localDateTime.format('DD/MM/YYYY');
              
              if (event.event_time && event.event_time.trim()) {
                const displayHours = localDateTime.format('h');
                const displayMinutes = localDateTime.format('mm');
                const ampm = localDateTime.format('A');
                dateTimeDisplay = `${localDate} at ${displayHours}:${displayMinutes} ${ampm}`;
              } else {
                dateTimeDisplay = localDate;
              }
            } else {
              dateTimeDisplay = event.event_date + (event.event_time ? ` ${event.event_time} UTC` : '');
            }
          } else {
            // Fallback to native Date
            const utcTimePart = (event.event_time && event.event_time.trim()) ? event.event_time.trim() + ':00:00' : '00:00:00';
            const utcDateTimeStr = event.event_date + 'T' + utcTimePart + 'Z';
            const utcDateObj = new Date(utcDateTimeStr);
            
            if (!isNaN(utcDateObj.getTime())) {
              const day = String(utcDateObj.getDate()).padStart(2, '0');
              const month = String(utcDateObj.getMonth() + 1).padStart(2, '0');
              const year = utcDateObj.getFullYear();
              const localDate = `${day}/${month}/${year}`;
              
              if (event.event_time && event.event_time.trim()) {
                const hours = utcDateObj.getHours();
                const minutes = utcDateObj.getMinutes();
                const ampm = hours >= 12 ? 'PM' : 'AM';
                const displayHours = hours % 12 || 12;
                dateTimeDisplay = `${localDate} at ${displayHours}:${String(minutes).padStart(2, '0')} ${ampm}`;
              } else {
                dateTimeDisplay = localDate;
              }
            } else {
              dateTimeDisplay = event.event_date + (event.event_time ? ` ${event.event_time} UTC` : '');
            }
          }
        } else {
          dateTimeDisplay = 'No date set';
        }
      } catch (e) {
        dateTimeDisplay = event.event_date + (event.event_time ? ` ${event.event_time} UTC` : '');
      }
      
      const createdDate = formatDateTime(event.created_at);
      const updatedDate = formatDateTime(event.updated_at);
      
      // Determine badge color: orange if auto_run and has_executions, green if auto_run without executions
      let autoRunBadge = '';
      if (event.auto_run) {
        const badgeColor = (event.has_executions === true || event.has_executions === 1) ? '#f97316' : '#34d399';
        autoRunBadge = `<span style="font-size: 12px; color: ${badgeColor}; margin-left: 12px; font-weight: 600;">[Auto Run]</span>`;
      }
      
      html += `
        <div class="event-item" data-event-id="${event.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <input type="checkbox" class="event-checkbox" value="${event.id}" id="event-${event.id}" style="margin: 0;">
            <label for="event-${event.id}" style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">
              <span style="font-size: 16px;">${event.name}</span>
              <span style="font-size: 14px; color: #86868b; margin-left: 12px;">- ${dateTimeDisplay}</span>
              ${autoRunBadge}
            </label>
            <button class="btn-event-view" data-event-id="${event.id}" style="padding: 4px 12px; font-size: 12px; background: #34d399; border-color: #34d399; color: white;">View</button>
            <button class="btn-event-edit" data-event-id="${event.id}" style="padding: 4px 12px; font-size: 12px; background: #60a5fa; border-color: #60a5fa; color: white;">Edit</button>
            <button class="btn-event-delete" data-event-id="${event.id}" style="padding: 4px 12px; font-size: 12px; background: #f87171; border-color: #f87171;">Delete</button>
          </div>
          <div style="font-size: 12px; color: #86868b; margin-left: 24px;">
            <div>Configuration: ${event.configuration_name}</div>
            <div>Created: ${createdDate}</div>
            <div>Updated: ${updatedDate}</div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    eventsList.innerHTML = html;
    
    // Add event listeners for view buttons
    document.querySelectorAll('.btn-event-view').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const eventId = parseInt(btn.getAttribute('data-event-id'));
        await viewEventExecutions(eventId);
      });
    });
    
    // Add event listeners for edit buttons
    document.querySelectorAll('.btn-event-edit').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const eventId = parseInt(btn.getAttribute('data-event-id'));
        await editEvent(eventId);
      });
    });
    
    // Add event listeners for delete buttons
    document.querySelectorAll('.btn-event-delete').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const eventId = parseInt(btn.getAttribute('data-event-id'));
        if (confirm('Are you sure you want to delete this event?')) {
          await deleteEvent(eventId);
        }
      });
    });
    
    // Checkbox selection for multiple delete
    document.querySelectorAll('.event-checkbox').forEach(checkbox => {
      checkbox.addEventListener('change', () => {
        updateEventDeleteButtonVisibility();
      });
    });
    
    // Set up Select All / Deselect All buttons
    const selectAllBtn = el('btnSelectAllEvents');
    const deselectAllBtn = el('btnDeselectAllEvents');
    
    if (selectAllBtn) {
      selectAllBtn.onclick = () => {
        document.querySelectorAll('.event-checkbox').forEach(cb => cb.checked = true);
        updateEventDeleteButtonVisibility();
      };
    }
    
    if (deselectAllBtn) {
      deselectAllBtn.onclick = () => {
        document.querySelectorAll('.event-checkbox').forEach(cb => cb.checked = false);
        updateEventDeleteButtonVisibility();
      };
    }
    
    function updateEventDeleteButtonVisibility() {
      const deleteBtn = el('btnDeleteEvent');
      if (deleteBtn) {
        const checked = document.querySelectorAll('.event-checkbox:checked');
        deleteBtn.style.display = checked.length > 0 ? 'inline-block' : 'none';
        if (checked.length > 0) {
          deleteBtn.textContent = `Delete Selected (${checked.length})`;
        } else {
          deleteBtn.textContent = 'Delete Selected';
        }
      }
    }
    
  } catch (error) {
    eventsList.innerHTML = `<p style="color: #f87171;">Error loading events: ${error.message || error}</p>`;
  }
}

async function deleteEvent(eventId) {
  try {
    const res = await api(`/event/delete/${eventId}`, { method: 'DELETE' });
    if (!res.ok) {
      showStatus('Failed to delete event');
      return;
    }
    showStatus('Event deleted successfully');
    loadEvents();
  } catch (error) {
    showStatus(`Error deleting event: ${error.message || error}`);
  }
}

async function viewEventExecutions(eventId) {
  try {
    const res = await api(`/event/executions/${eventId}`);
    if (!res.ok) {
      showStatus('Failed to load execution records');
      return;
    }
    
    const data = await res.json();
    showExecutionModal(data);
  } catch (error) {
    showStatus(`Error loading execution records: ${error.message || error}`);
  }
}
function showExecutionModal(data) {
  const { event_id, event_name, executions } = data;
  
  // Create modal overlay
  const overlay = document.createElement('div');
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  `;
  
  // Create modal content
  const modal = document.createElement('div');
  modal.style.cssText = `
    background: white;
    border-radius: 8px;
    padding: 24px;
    max-width: 900px;
    width: 100%;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
  `;
  
  let html = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
      <h2 style="margin: 0;">Execution History: ${event_name || `Event #${event_id}`}</h2>
      <button id="btnCloseExecutionModal" style="padding: 8px 16px; background: #86868b; border: none; border-radius: 4px; color: white; cursor: pointer; font-size: 14px;">Close</button>
    </div>
  `;
  
  if (!executions || executions.length === 0) {
    html += '<p style="color: #86868b; padding: 20px; text-align: center;">No execution records found for this event.</p>';
  } else {
    html += `<div style="display: flex; flex-direction: column; gap: 16px;">`;
    
    executions.forEach((exec, index) => {
      const statusColor = exec.status === 'success' ? '#34d399' : exec.status === 'error' ? '#f87171' : '#60a5fa';
      const statusIcon = exec.status === 'success' ? '✓' : exec.status === 'error' ? '✗' : '⟳';
      
      const startedDate = formatDateTime(exec.started_at);
      const completedDate = exec.completed_at ? formatDateTime(exec.completed_at) : 'In Progress...';
      const duration = exec.completed_at && exec.execution_details?.duration_seconds 
        ? `${Math.round(exec.execution_details.duration_seconds)}s` 
        : exec.completed_at ? 'N/A' : '';
      
      html += `
        <div style="border: 1px solid #d2d2d7; border-radius: 6px; padding: 16px; background: #fafafa;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 18px; color: ${statusColor}; font-weight: bold;">${statusIcon}</span>
              <span style="font-weight: 600; font-size: 16px; text-transform: capitalize;">${exec.status}</span>
              ${duration ? `<span style="font-size: 12px; color: #86868b;">(${duration})</span>` : ''}
            </div>
            <span style="font-size: 12px; color: #86868b;">Execution #${executions.length - index}</span>
          </div>
          
          ${exec.message ? `<div style="margin-bottom: 8px; font-size: 14px; color: #1d1d1f;">${exec.message}</div>` : ''}
          
          <div style="font-size: 12px; color: #86868b; margin-bottom: 12px;">
            <div>Started: ${startedDate}</div>
            <div>Completed: ${completedDate}</div>
            ${Array.isArray(exec.execution_details?.hosts) && exec.execution_details.hosts.length > 0 
              ? `<div>Hosts: ${exec.execution_details.hosts.map(h => `<code>${h}</code>`).join(', ')}</div>` 
              : (exec.execution_details?.hosts_count !== undefined ? `<div>Hosts: ${exec.execution_details.hosts_count}</div>` : '')}
            ${Array.isArray(exec.execution_details?.templates) && exec.execution_details.templates.length > 0 
              ? `<div style="margin-top: 8px; padding: 8px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px;">
                  <div style="font-weight: 600; color: #047857; margin-bottom: 4px; font-size: 13px;">Templates:</div>
                  <ul style="margin: 4px 0 0 16px; font-size: 11px; color: #047857;">
                    ${exec.execution_details.templates.map(t => `<li>${t.repo_name ? `<code>${t.repo_name}</code>/` : ''}<strong>${t.template_name || ''}</strong> v${t.version || ''}</li>`).join('')}
                  </ul>
                </div>`
              : (exec.execution_details?.templates_count !== undefined ? `<div style="margin-top: 8px; padding: 8px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px; font-size: 11px; color: #047857;">Templates: ${exec.execution_details.templates_count}</div>` : '')}
            ${exec.execution_details?.install_executed === true && Array.isArray(exec.execution_details?.installations) && exec.execution_details.installations.length > 0
              ? `<div style="margin-top: 8px; padding: 8px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px;">
                  <div style="font-weight: 600; color: #047857; margin-bottom: 4px; font-size: 13px;">Installation Executed:</div>
                  <ul style="margin: 4px 0 0 16px; font-size: 11px; color: #047857;">
                    ${exec.execution_details.installations.map(inst => {
                      const successIcon = inst.success ? '✓' : '✗';
                      const successColor = inst.success ? '#047857' : '#dc2626';
                      const duration = inst.duration_seconds ? ` (${Math.round(inst.duration_seconds)}s)` : '';
                      const errors = inst.errors && inst.errors.length > 0 ? ` - ${inst.errors.join('; ')}` : '';
                      return `<li style="color: ${successColor}; margin-bottom: 2px;">
                        ${successIcon} <strong>${inst.template_name || ''}</strong> v${inst.version || ''} on ${inst.host || 'N/A'}${duration}${errors}
                      </li>`;
                    }).join('')}
                  </ul>
                </div>`
              : exec.execution_details?.install_select && exec.execution_details?.install_executed === false
              ? `<div style="margin-top: 8px; padding: 8px; background: #fef3c7; border-left: 3px solid #f59e0b; border-radius: 4px; font-size: 11px; color: #92400e;">
                  <div style="font-weight: 600; margin-bottom: 4px;">Installation Selected (Not Executed):</div>
                  <div style="margin-left: 8px;">${exec.execution_details.install_select.split('|||').join(' v')}</div>
                </div>`
              : exec.execution_details?.installed 
              ? `<div style="margin-top: 8px; padding: 8px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px;">
                  <div style="font-weight: 600; color: #047857; margin-bottom: 4px; font-size: 13px;">Installed:</div>
                  <div style="font-size: 11px; color: #047857; margin-left: 8px;">
                    ${exec.execution_details.installed.repo_name ? `<code>${exec.execution_details.installed.repo_name}</code>/` : ''}<strong>${exec.execution_details.installed.template_name || ''}</strong> v${exec.execution_details.installed.version || ''}
                  </div>
                </div>`
              : ''}
            ${exec.execution_details?.hostname_changes && exec.execution_details.hostname_changes.length > 0
              ? `<div style="margin-top: 8px; padding: 8px; background: #fef3c7; border-left: 3px solid #f59e0b; border-radius: 4px;">
                  <div style="font-weight: 600; color: #92400e; margin-bottom: 4px; font-size: 13px;">Hostname Changes:</div>
                  <ul style="margin: 4px 0 0 16px; font-size: 11px; color: #92400e;">
                    ${exec.execution_details.hostname_changes.map(h => {
                      const statusIcon = h.success ? '✓' : '✗';
                      const statusColor = h.success ? '#047857' : '#dc2626';
                      return `<li style="color: ${statusColor}; margin-bottom: 2px;">
                        <span style="font-weight: bold;">${statusIcon}</span>
                        <code>${h.host}</code>: Changed to <strong>${h.new_hostname || 'N/A'}</strong>${h.error ? ` - ${h.error}` : ''}
                      </li>`;
                    }).join('')}
                  </ul>
                </div>`
              : ''}
            ${exec.execution_details?.password_changes && exec.execution_details.password_changes.length > 0
              ? `<div style="margin-top: 8px; padding: 8px; background: #fef3c7; border-left: 3px solid #f59e0b; border-radius: 4px;">
                  <div style="font-weight: 600; color: #92400e; margin-bottom: 4px; font-size: 13px;">Password Changes:</div>
                  <ul style="margin: 4px 0 0 16px; font-size: 11px; color: #92400e;">
                    ${exec.execution_details.password_changes.map(p => {
                      const statusIcon = p.success ? '✓' : '✗';
                      const statusColor = p.success ? '#047857' : '#dc2626';
                      return `<li style="color: ${statusColor}; margin-bottom: 2px;">
                        <span style="font-weight: bold;">${statusIcon}</span>
                        <code>${p.host}</code>: Changed password for user <strong>${p.username || 'guest'}</strong>${p.error ? ` - ${p.error}` : ''}
                      </li>`;
                    }).join('')}
                  </ul>
                </div>`
              : ''}
            ${exec.execution_details?.ssh_profile 
              ? `<div style="margin-top: 8px; padding: 8px; background: #f0f9ff; border-left: 3px solid #3b82f6; border-radius: 4px;">
                  <div style="font-weight: 600; color: #1e40af; margin-bottom: 4px; font-size: 13px;">SSH Profile Execution:</div>
                  <div style="font-size: 11px; color: #1e40af; margin-left: 8px;">
                    <div><strong>Profile:</strong> ${exec.execution_details.ssh_profile.profile_name || 'N/A'} (ID: ${exec.execution_details.ssh_profile.profile_id || 'N/A'})</div>
                    <div><strong>Wait Time:</strong> ${exec.execution_details.ssh_profile.wait_time_seconds || 0} seconds</div>
                    <div><strong>Commands:</strong> ${exec.execution_details.ssh_profile.commands ? exec.execution_details.ssh_profile.commands.length : 0} command(s)</div>
                    ${exec.execution_details.ssh_profile.hosts && exec.execution_details.ssh_profile.hosts.length > 0
                      ? `<div style="margin-top: 4px;"><strong>Host Results:</strong><ul style="margin: 4px 0 0 16px;">${exec.execution_details.ssh_profile.hosts.map(h => {
                          const statusIcon = h.success ? '✓' : '✗';
                          const statusColor = h.success ? '#10b981' : '#ef4444';
                          return `<li style="margin-bottom: 2px;">
                            <span style="color: ${statusColor}; font-weight: bold;">${statusIcon}</span>
                            <code>${h.host}</code>: ${h.commands_executed} executed, ${h.commands_failed} failed${h.error ? ` - ${h.error}` : ''}
                          </li>`;
                        }).join('')}</ul></div>`
                      : ''}
                  </div>
                </div>`
              : ''}
          </div>
          
          ${exec.errors && exec.errors.length > 0 ? `
            <div style="margin-top: 12px; padding: 12px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 4px;">
              <div style="font-weight: 600; color: #dc2626; margin-bottom: 8px; font-size: 13px;">Errors:</div>
              <ul style="margin: 0; padding-left: 20px; color: #991b1b; font-size: 12px;">
                ${exec.errors.map(err => `<li style="margin-bottom: 4px;">${err}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
        </div>
      `;
    });
    
    html += `</div>`;
  }
  
  modal.innerHTML = html;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  
  // Close button handler
  const closeBtn = modal.querySelector('#btnCloseExecutionModal');
  const closeModal = () => {
    document.body.removeChild(overlay);
  };
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      closeModal();
    }
  });
  
  // Escape key to close
  const escapeHandler = (e) => {
    if (e.key === 'Escape') {
      closeModal();
      document.removeEventListener('keydown', escapeHandler);
    }
  };
  document.addEventListener('keydown', escapeHandler);
}

// Load and display configurations from database
async function loadConfigurations() {
  // Ensure we're showing the list view (not edit view)
  const listView = el('configsListView');
  const editView = el('configEditView');
  if (listView) listView.style.display = 'block';
  if (editView) editView.style.display = 'none';
  
  const configsList = el('configsList');
  if (!configsList) return;
  
  configsList.innerHTML = '<p>Loading...</p>';
  
  try {
    // Clear cache and pending requests before fetching to ensure fresh data
    const cacheKey = '/config/list?';
    if (_requestCache.has(cacheKey)) {
      _requestCache.delete(cacheKey);
    }
    if (_pendingRequests.has(cacheKey)) {
      _pendingRequests.delete(cacheKey);
    }
    
    // Force a fresh request by bypassing cache
    const res = await api('/config/list', { noCache: true });
    if (!res.ok) {
      configsList.innerHTML = '<p style="color: #f87171;">Failed to load configurations</p>';
      return;
    }
    
    const data = await res.json();
    const configs = data.configurations || [];
    
    if (configs.length === 0) {
      configsList.innerHTML = '<p>No saved configurations found. Click "New Configuration" to create one.</p>';
      return;
    }
    
    // Create table/list of configurations
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';
    configs.forEach((config, idx) => {
      const createdDate = formatDateTime(config.created_at);
      const updatedDate = formatDateTime(config.updated_at);
      html += `
        <div class="config-item" data-config-id="${config.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7; cursor: pointer;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <input type="checkbox" class="config-checkbox" value="${config.id}" id="config-${config.id}" style="margin: 0;">
            <label for="config-${config.id}" style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">${config.name}</label>
            <button type="button" class="btn-config-run" data-config-id="${config.id}" style="padding: 4px 12px; font-size: 12px; cursor: pointer; background: #10b981; border-color: #10b981; color: white; border: 1px solid #10b981; border-radius: 0; box-shadow: 0 2px 4px rgba(16, 185, 129, 0.3); font-weight: 600;">Run</button>
            <button type="button" class="btn-config-edit" data-config-id="${config.id}" style="padding: 4px 12px; font-size: 12px; background: #da291c; border-color: #da291c; color: white; cursor: pointer; border: 1px solid #da291c; border-radius: 0; box-shadow: 0 2px 4px rgba(218, 41, 28, 0.3);">Edit</button>
            <button type="button" class="btn-config-delete" data-config-id="${config.id}" style="padding: 4px 12px; font-size: 12px; background: #da291c; border-color: #da291c; color: white; cursor: pointer; border: 1px solid #da291c; border-radius: 0; box-shadow: 0 2px 4px rgba(218, 41, 28, 0.3);">Delete</button>
          </div>
          <div style="font-size: 12px; color: #86868b; margin-left: 24px;">
            <div>Created: ${createdDate}</div>
            <div>Updated: ${updatedDate}</div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    configsList.innerHTML = html;
    
    // Add event listeners for run, edit, and delete buttons
    document.querySelectorAll('.btn-config-run').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const configIdStr = btn.getAttribute('data-config-id');
        const configId = parseInt(configIdStr);
        if (isNaN(configId)) {
          showStatus('Error: Invalid configuration ID');
          return;
        }
        await runConfigurationById(configId);
      });
    });
    
    document.querySelectorAll('.btn-config-edit').forEach(btn => {
      btn.disabled = false;
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const configIdStr = btn.getAttribute('data-config-id');
        const configId = parseInt(configIdStr);
        if (isNaN(configId)) {
          showStatus('Error: Invalid configuration ID');
          return;
        }
        await editConfiguration(configId);
      });
    });
    
    document.querySelectorAll('.btn-config-delete').forEach(btn => {
      btn.disabled = false;
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const configIdStr = btn.getAttribute('data-config-id');
        const configId = parseInt(configIdStr);
        if (isNaN(configId)) {
          showStatus('Error: Invalid configuration ID');
          return;
        }
        if (confirm('Are you sure you want to delete this configuration?')) {
          await deleteConfiguration(configId);
        }
      });
    });
    
    // Checkbox selection for multiple delete
    document.querySelectorAll('.config-checkbox').forEach(checkbox => {
      checkbox.addEventListener('change', () => {
        updateDeleteButtonVisibility();
      });
    });
    
    // Add "Select All" / "Deselect All" functionality
    const selectAllHtml = `
      <div style="margin-bottom: 12px; padding: 8px; border: 1px solid #d2d2d7; background: #fafafa; border-radius: 4px;">
        <button id="btnSelectAllConfigs" style="padding: 4px 12px; font-size: 12px; margin-right: 8px;">Select All</button>
        <button id="btnDeselectAllConfigs" style="padding: 4px 12px; font-size: 12px;">Deselect All</button>
      </div>
    `;
    configsList.insertAdjacentHTML('afterbegin', selectAllHtml);
    
    el('btnSelectAllConfigs').onclick = () => {
      document.querySelectorAll('.config-checkbox').forEach(cb => cb.checked = true);
      updateDeleteButtonVisibility();
    };
    
    el('btnDeselectAllConfigs').onclick = () => {
      document.querySelectorAll('.config-checkbox').forEach(cb => cb.checked = false);
      updateDeleteButtonVisibility();
    };
    
    function updateDeleteButtonVisibility() {
      const deleteBtn = el('btnDeleteConfig');
      if (deleteBtn) {
        const checked = document.querySelectorAll('.config-checkbox:checked');
        deleteBtn.style.display = checked.length > 0 ? 'inline-block' : 'none';
        if (checked.length > 0) {
          deleteBtn.textContent = `Delete Selected (${checked.length})`;
        } else {
          deleteBtn.textContent = 'Delete Selected';
        }
      }
    }
    
  } catch (error) {
    configsList.innerHTML = `<p style="color: #f87171;">Error loading configurations: ${error.message || error}</p>`;
    logMsg(`Error loading configurations: ${error.message || error}`);
  }
}

function showLoadingScreen(message = 'Loading configuration...') {
  // Try multiple ways to find the element
  let overlay = document.getElementById('loadingOverlay');
  if (!overlay) {
    overlay = document.querySelector('#loadingOverlay');
  }
  if (!overlay) {
    overlay = el('loadingOverlay');
  }
  
  if (!overlay) {
    // Create the overlay if it doesn't exist
    overlay = document.createElement('div');
    overlay.id = 'loadingOverlay';
    overlay.className = 'loading-overlay';
    overlay.innerHTML = `
      <div class="loading-logo-container">
        <img src="/images/Fortinet-logomark-rgb-red.svg" alt="Fortinet" class="loading-logo" id="loadingLogo">
        <div class="loading-text" id="loadingText">${message}</div>
        <div class="loading-spinner"></div>
      </div>
    `;
    document.body.appendChild(overlay);
  }
  
  const loadingText = document.getElementById('loadingText');
  if (loadingText && message) {
    loadingText.textContent = message;
  }
  
  // Force show
  overlay.style.display = 'flex';
  overlay.style.opacity = '1';
  overlay.style.visibility = 'visible';
  overlay.classList.add('show');
}

function hideLoadingScreen() {
  let overlay = document.getElementById('loadingOverlay');
  if (!overlay) {
    overlay = document.querySelector('#loadingOverlay');
  }
  if (!overlay) {
    overlay = el('loadingOverlay');
  }
  
  if (overlay) {
    overlay.classList.remove('show');
    overlay.style.opacity = '0';
    overlay.style.visibility = 'hidden';
    // Hide after transition
    setTimeout(() => {
      overlay.style.display = 'none';
    }, 300);
  }
}

async function runConfigurationById(configId) {
  // Set flag to prevent clearing config name during section load
  window.isLoadingConfiguration = true;
  
  showLoadingScreen('Loading configuration...');
  try {
    // Clear cache for this specific config to ensure fresh data
    const cacheKey = `/config/get/${configId}?`;
    if (_requestCache.has(cacheKey)) {
      _requestCache.delete(cacheKey);
    }
    if (_pendingRequests.has(cacheKey)) {
      _pendingRequests.delete(cacheKey);
    }
    
    const getRes = await api(`/config/get/${configId}`, { noCache: true });
    if (!getRes.ok) {
      showStatus('Failed to retrieve configuration');
      hideLoadingScreen();
      window.isLoadingConfiguration = false;
      return;
    }
    
    const configData = await getRes.json();
    if (!configData || !configData.config_data) {
      showStatus('Invalid configuration data received');
      hideLoadingScreen();
      window.isLoadingConfiguration = false;
      return;
    }
    
    // Clear edit mode
    editingConfigId = null;
    
    // Get the configuration name first
    const configName = configData.name || 'Unknown Configuration';
    
    // Display configuration name at top
    displayConfigName(configName);
    
    // Show run view and hide other views
    const listView = el('configsListView');
    const editView = el('configEditView');
    const runView = el('configRunView');
    if (listView) listView.style.display = 'none';
    if (editView) editView.style.display = 'none';
    if (runView) runView.style.display = 'block';
    
    // Update run view title
    const runTitle = el('configRunTitle');
    if (runTitle) runTitle.textContent = `Running: ${configName}`;
    
    // Wait for run view elements to be available (uses same IDs as preparation section)
    let attempts = 0;
    const maxAttempts = 20;
    while (attempts < maxAttempts && !el('fabricHost')) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    
    if (!el('fabricHost')) {
      showStatus('Error: Run view not loaded properly');
      hideLoadingScreen();
      window.isLoadingConfiguration = false;
      return;
    }
    
    // Initialize run view handlers (sets up preparation section logic)
    initializeRunView();
    
    // Restore configuration to run view (uses same element IDs as preparation section)
    await restoreConfiguration(configData.config_data);
    
    // Wait a bit to ensure everything is set up, then ensure button is enabled
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Verify the Run button handler is set up
    const runBtn = el('btnInstallSelected');
    if (runBtn) {
      // Ensure handler is attached
      if (!runBtn.onclick) {
        runBtn.onclick = handleTrackedRunButton;
      }
      
      // Force enable the button if configuration was loaded successfully
      // The button should be enabled since hosts are confirmed and tokens are acquired
      // Update button state
      updateCreateEnabled();
      
      // If button is still disabled after updateCreateEnabled, force enable it
      // since we know the configuration was loaded successfully
      if (runBtn.disabled) {
        runBtn.disabled = false;
      }
    }
    hideLoadingScreen();
  } catch (error) {
    showStatus(`Error loading configuration: ${error.message || error}`);
    logMsg(`Error loading configuration: ${error.message || error}`);
    hideLoadingScreen();
  } finally {
    // Clear the flag after configuration loading is complete
    window.isLoadingConfiguration = false;
  }
}

async function editConfiguration(configId) {
  showLoadingScreen('Loading configuration for editing...');
  try {
    // Clear cache for this specific config to ensure fresh data
    const cacheKey = `/config/get/${configId}?`;
    if (_requestCache.has(cacheKey)) {
      _requestCache.delete(cacheKey);
    }
    if (_pendingRequests.has(cacheKey)) {
      _pendingRequests.delete(cacheKey);
    }
    
    const getRes = await api(`/config/get/${configId}`, { noCache: true });
    if (!getRes.ok) {
      showStatus('Failed to retrieve configuration');
      hideLoadingScreen();
      return;
    }
    
    const configData = await getRes.json();
    if (!configData || !configData.config_data) {
      showStatus('Invalid configuration data received');
      hideLoadingScreen();
      return;
    }
    
    // Set edit mode
    editingConfigId = configId;
    
    // Get the configuration name and data
    const configName = configData.name || 'Unknown Configuration';
    const config = configData.config_data;
    
    
    // Show edit view and hide list view
    const listView = el('configsListView');
    const editView = el('configEditView');
    const runView = el('configRunView');
    if (listView) listView.style.display = 'none';
    if (editView) editView.style.display = 'block';
    if (runView) runView.style.display = 'none';
    
    // Update title
    const title = el('configEditTitle');
    if (title) title.textContent = `Edit: ${configName}`;
    
    // Populate edit form (async function)
    await populateConfigEditForm(configName, config);
    
    // Wait for any remaining async operations in populateConfigEditForm to complete
    // The function uses setTimeout for template row initialization, so wait for that
    const templatesCount = config.templates ? config.templates.length : 0;
    if (templatesCount > 0) {
      const waitTime = Math.max(2000, templatesCount * 1200) + 500; // Wait for setTimeout + buffer
      await new Promise(resolve => setTimeout(resolve, waitTime));
    } else {
      // Still wait a bit for form to settle
      await new Promise(resolve => setTimeout(resolve, 300));
    }
    
    showStatus(`Configuration '${configName}' loaded for editing`);
    hideLoadingScreen();
  } catch (error) {
    showStatus(`Error loading configuration for editing: ${error.message || error}`);
    logMsg(`Error loading configuration for editing: ${error.message || error}`);
    hideLoadingScreen();
  }
}
async function populateConfigEditForm(name, config) {
  
  // Set configuration name
  const nameInput = el('editConfigName');
  if (nameInput) nameInput.value = name || '';
  
  // Set basic fields
  // API Base field removed
  
  // Initialize editValidatedHosts globally for chips
  if (!window.editValidatedHosts) {
    window.editValidatedHosts = [];
  }
  window.editValidatedHosts = [];
  
  const fabricHostInput = el('editFabricHost');
  if (fabricHostInput) {
    if (config.confirmedHosts && config.confirmedHosts.length > 0) {
      // Show confirmed hosts as space-separated string and populate chips
      const hostString = config.confirmedHosts.map(h => 
        h.host + (h.port !== undefined ? ':' + h.port : '')
      ).join(' ');
      fabricHostInput.value = hostString;
      // Create validated hosts array for chips
      window.editValidatedHosts = config.confirmedHosts.map(h => ({
        host: h.host,
        port: h.port,
        isValid: true
      }));
    } else if (config.fabricHost) {
      fabricHostInput.value = config.fabricHost;
      // Parse hosts from string if available
      const hosts = config.fabricHost.split(/\s+/).filter(h => h.trim()).map(hostStr => {
        const parts = hostStr.split(':');
        return {
          host: parts[0],
          port: parts.length > 1 ? parts[1] : undefined,
          isValid: true
        };
      });
      window.editValidatedHosts = hosts;
    } else {
      fabricHostInput.value = '';
    }
  }
  
  // Render host chips - use the global array
  const chipsContainer = el('editFabricHostChips');
  const statusSpan = el('editFabricHostStatus');
  if (window.editValidatedHosts && window.editValidatedHosts.length > 0) {
    renderHostChipsForTarget('editFabricHost', 'editFabricHostChips', 'editFabricHostStatus', window.editValidatedHosts);
  } else {
    if (chipsContainer) chipsContainer.innerHTML = '';
    if (chipsContainer) chipsContainer.style.display = 'none';
    if (statusSpan) statusSpan.textContent = '';
  }
  
  // Initialize editFabricHost input listeners (same logic as preparation section)
  // Wait a bit to ensure DOM is ready
  setTimeout(() => {
    initializeEditFabricHostInput();
  }, 100);
  
  // Load NHI credentials into dropdown and set selected value
  const nhiCredentialSelect = el('editNhiCredentialSelect');
  const nhiCredentialId = config.nhiCredentialId;
  
  // Store NHI credential ID for saving (will be updated when dropdown changes)
  window.editNhiCredentialId = nhiCredentialId || '';
  
  if (nhiCredentialSelect) {
    try {
      const res = await api('/nhi/list');
      if (res.ok) {
        const data = await res.json();
        const credentials = data.credentials || [];
        
        // Clear and rebuild dropdown
        nhiCredentialSelect.innerHTML = '<option value="">Select NHI credential...</option>';
        credentials.forEach(cred => {
          const option = document.createElement('option');
          option.value = cred.id.toString();
          option.textContent = `${cred.name} (${cred.client_id})`;
          nhiCredentialSelect.appendChild(option);
        });
        
        // Set selected value to the credential from configuration
        if (nhiCredentialId) {
          const credential = credentials.find(c => c.id.toString() === nhiCredentialId.toString());
          if (credential) {
            nhiCredentialSelect.value = nhiCredentialId.toString();
          } else {
            // Keep the value as empty or show a message
          }
        } else {
          nhiCredentialSelect.value = '';
        }
      } else {
        nhiCredentialSelect.innerHTML = '<option value="">Error loading credentials</option>';
      }
    } catch (err) {
      nhiCredentialSelect.innerHTML = '<option value="">Error loading credentials</option>';
    }
    
    // Update stored ID and load hosts when dropdown changes (only add listener once)
    if (!nhiCredentialSelect.hasAttribute('data-listener-added')) {
      nhiCredentialSelect.addEventListener('change', async () => {
        window.editNhiCredentialId = nhiCredentialSelect.value || '';
        // Load the NHI credential and populate hosts
        if (nhiCredentialSelect.value) {
          await loadSelectedNhiCredentialForEdit();
        } else {
          // Clear hosts if no credential selected
          const editFabricHostInput = el('editFabricHost');
          if (editFabricHostInput) {
            editFabricHostInput.value = '';
          }
          const editFabricHostChips = el('editFabricHostChips');
          if (editFabricHostChips) {
            editFabricHostChips.innerHTML = '';
          }
          window.editValidatedHosts = [];
        }
      });
      nhiCredentialSelect.setAttribute('data-listener-added', 'true');
    }
  }
  
  const newHostnameInput = el('editNewHostname');
  if (newHostnameInput) newHostnameInput.value = config.newHostname || '';
  
  const chgPassInput = el('editChgPass');
  if (chgPassInput) chgPassInput.value = config.chgPass || '';
  
  const expertModeInput = el('editExpertMode');
  if (expertModeInput) expertModeInput.checked = config.expertMode || false;
  
  // Load and populate SSH profile fields
  const editSshProfileSelect = el('editSshProfileSelect');
  if (editSshProfileSelect) {
    try {
      const sshRes = await api('/ssh-command-profiles/list');
      if (sshRes.ok) {
        const sshData = await sshRes.json();
        const profiles = sshData.profiles || [];
        
        // Clear existing options except the first one
        editSshProfileSelect.innerHTML = '<option value="">None (select SSH profile)</option>';
        
        // Add SSH profiles to dropdown
        profiles.forEach(profile => {
          const option = document.createElement('option');
          option.value = profile.id;
          option.textContent = profile.name;
          editSshProfileSelect.appendChild(option);
        });
        
        // Set selected value from config
        if (config.sshProfileId !== undefined) {
          editSshProfileSelect.value = config.sshProfileId || '';
        }
      }
    } catch (err) {
    }
  }
  
  const editSshWaitTimeInput = el('editSshWaitTime');
  if (editSshWaitTimeInput && config.sshWaitTime !== undefined) {
    editSshWaitTimeInput.value = config.sshWaitTime || 60;
  }
  
  // Restore Run Workspace toggle
  const editRunWorkspaceEnabledInput = el('editRunWorkspaceEnabled');
  if (editRunWorkspaceEnabledInput && config.runWorkspaceEnabled !== undefined) {
    editRunWorkspaceEnabledInput.checked = config.runWorkspaceEnabled !== false; // Default to true if not specified
  }
  
  // Create template rows and populate install select
  const tplFormList = el('editTplFormList');
  if (tplFormList) tplFormList.innerHTML = '';
  
  // Build cached templates structure from config templates
  // This allows us to populate dropdowns for existing rows without calling the cache endpoint
  window.editCachedTemplates = [];
  if (config.templates && config.templates.length > 0) {
    // Build a structure similar to cached templates from the config data
    config.templates.forEach(t => {
      if (t.repo_name && t.template_name && t.version) {
        window.editCachedTemplates.push({
          repo_name: t.repo_name,
          template_name: t.template_name,
          version: t.version
        });
      }
    });
  }
  
  // Load full cache if not already loaded (needed for adding new rows)
  if (!window.cachedTemplates || window.cachedTemplates.length === 0) {
    (async () => {
      try {
        const cacheData = await apiJson('/cache/templates');
        window.cachedTemplates = cacheData.templates || [];
      } catch (error) {
        console.error('Error loading cached templates for edit form:', error);
      }
    })();
  }
  
  // Enable Add Row button
  const addEditRowBtn = el('btnAddEditRow');
  if (addEditRowBtn) {
    addEditRowBtn.disabled = false;
  }
  
  if (config.templates && config.templates.length > 0) {
    // Add template rows (editable, using templates from config)
    // Add all rows first, then wait for values to be set
    let rowsAdded = 0;
    for (const template of config.templates) {
      addEditTplRow({
        repo_name: template.repo_name,
        template_name: template.template_name,
        version: template.version
      });
      rowsAdded++;
    }
    
    // Populate install select dropdown from existing templates
    // Wait longer to ensure all rows are fully initialized and values are set
    // Each row takes time to populate dropdowns and set values (about 1-1.5 seconds per row)
    const waitTime = Math.max(2000, rowsAdded * 1200); // 1.2 seconds per row
    
    // Get the stored installSelect value before waiting, so we can set it during initial population
    const storedInstallSelect = config.installSelect || '';
    
    setTimeout(() => {
      // Pass the stored value - this will populate the dropdown AND set the stored value in one go
      // No visual flicker because the correct value is set during initial population
      updateEditInstallSelectFromRows(storedInstallSelect);
      
      // Verify the value was set correctly
      setTimeout(() => {
        const select = el('editInstallSelect');
        if (select && storedInstallSelect) {
          if (select.value === storedInstallSelect) {
          } else {
            // Try to set it one more time if it didn't match
            const match = Array.from(select.options).find(o => o.value === storedInstallSelect);
            if (match) {
              select.value = storedInstallSelect;
            }
          }
        }
      }, 200);
    }, waitTime);
  } else {
    updateEditInstallSelect([], '');
  }
}

// Initialize editFabricHost input with same logic as fabricHost in preparation section
function initializeEditFabricHostInput() {
  let fh = el('editFabricHost');
  if (!fh) {
    return;
  }
  
  
  // Remove existing listeners if already initialized (clone to remove all listeners)
  if (fh.hasAttribute('data-listener-added')) {
    const newInput = fh.cloneNode(true);
    fh.parentNode.replaceChild(newInput, fh);
    // Get reference to new element
    fh = el('editFabricHost');
    if (!fh) {
      return;
    }
  }
  
  // Ensure window.editValidatedHosts exists
  if (!window.editValidatedHosts) {
    window.editValidatedHosts = [];
  }
  
  // Store lastValue on the element to persist across scope
  fh._lastEditValue = fh.value || '';
  
  // Helper function to render edit host chips
  function renderEditHostChips() {
    if (!window.editValidatedHosts) {
      window.editValidatedHosts = [];
    }
    renderHostChipsForTarget('editFabricHost', 'editFabricHostChips', 'editFabricHostStatus', window.editValidatedHosts);
  }
  
  // Helper function to update validation status for edit field
  function updateEditValidationStatus() {
    const status = el('editFabricHostStatus');
    const input = el('editFabricHost');
    if (!status || !input) return;
    
    if (window.editValidatedHosts && window.editValidatedHosts.length > 0) {
      status.textContent = `${window.editValidatedHosts.length} host(s) valid`;
      status.className = 'status';
      status.style.color = '#10b981';
      input.style.borderColor = '#10b981';
    } else {
      status.textContent = '';
      status.className = 'status';
      input.style.borderColor = '';
    }
  }
  
  // Helper function to validate and add host to editValidatedHosts
  function validateAndAddEditHost(hostText) {
    if (!hostText || !hostText.trim()) {
      return false;
    }
    
    const {host, port} = splitHostPort(hostText.trim());
    
    const hostOk = isValidIp(host) || isValidDomain(host);
    const portOk = port === undefined || (port >= 1 && port <= 65535);
    const isValid = hostOk && portOk;
    
    
    // Only add to validated hosts if valid
    if (isValid) {
      // Ensure window.editValidatedHosts exists
      if (!window.editValidatedHosts) {
        window.editValidatedHosts = [];
      }
      
      // Check if already exists to avoid duplicates
      const exists = window.editValidatedHosts.some(vh => 
        vh.host === host && vh.port === port
      );
      if (!exists) {
        window.editValidatedHosts.push({host, port, isValid: true});
      } else {
      }
    } else {
    }
    
    return isValid;
  }
  
  fh.addEventListener('input', (e) => {
    const value = e.target.value;
    const storedLastValue = e.target._lastEditValue || '';
    
    if (value.length > storedLastValue.length && value.endsWith(' ')) {
      const spaceIndex = value.lastIndexOf(' ');
      const parts = value.substring(0, spaceIndex).split(/\s+/).filter(p => p.trim());
      if (parts.length > 0) {
        const lastHost = parts[parts.length - 1];
        const isValid = validateAndAddEditHost(lastHost);
        if (isValid) {
          const validatedStr = window.editValidatedHosts.map(({host, port}) => 
            host + (port !== undefined ? ':' + port : '')
          ).join(' ');
          e.target.value = validatedStr + ' ';
          
          setTimeout(() => {
            e.target.setSelectionRange(e.target.value.length, e.target.value.length);
          }, 0);
        } else {
          // Remove trailing space if host is invalid
          e.target.value = value.trimEnd();
        }
      }
      renderEditHostChips();
      updateEditValidationStatus();
    } else if (value.length < storedLastValue.length) {
      if (value.trim() === '' || value === '') {
        window.editValidatedHosts = [];
        renderEditHostChips();
        updateEditValidationStatus();
      } else {
        const currentParts = value.trim().split(/\s+/).filter(p => p.trim());
        const newValidatedHosts = [];
        currentParts.forEach(part => {
          const {host, port} = splitHostPort(part.trim());
          const existing = window.editValidatedHosts.find(vh => 
            vh.host === host && vh.port === port
          );
          if (existing) {
            newValidatedHosts.push(existing);
          }
        });
        window.editValidatedHosts = newValidatedHosts;
        renderEditHostChips();
        updateEditValidationStatus();
      }
    }
    
    e.target._lastEditValue = value;
  });
  
  fh.addEventListener('blur', () => {
    const currentValue = fh.value.trim();
    if (currentValue && !currentValue.endsWith(' ')) {
      const parts = currentValue.split(/\s+/).filter(p => p.trim());
      if (parts.length > 0) {
        const lastPart = parts[parts.length - 1];
        const exists = window.editValidatedHosts.some(vh => {
          const {host, port} = splitHostPort(lastPart);
          return vh.host === host && vh.port === port;
        });
        if (!exists) {
          validateAndAddEditHost(lastPart);
          renderEditHostChips();
          updateEditValidationStatus();
        }
      }
    }
    // Force validation on blur
    if (fh.value.trim()) {
      const parts = fh.value.trim().split(/\s+/).filter(p => p.trim());
      parts.forEach(part => {
        const {host, port} = splitHostPort(part.trim());
        const exists = window.editValidatedHosts.some(vh => 
          vh.host === host && vh.port === port
        );
        if (!exists) {
          validateAndAddEditHost(part.trim());
        }
      });
      renderEditHostChips();
      updateEditValidationStatus();
    }
  });
  
  fh.addEventListener('dblclick', (e) => {
    if (e.target.readOnly) {
      window.editValidatedHosts = [];
      e.target.value = '';
      e.target.readOnly = false;
      e.target.style.backgroundColor = '';
      e.target.style.cursor = '';
      renderEditHostChips();
      updateEditValidationStatus();
      e.target.focus();
    }
  });
  
  fh.setAttribute('data-listener-added', 'true');
}

// Add template row in edit form using cached templates
function addEditTplRow(prefill) {
  const container = el('editTplFormList');
  if (!container) return;
  
  const row = document.createElement('div');
  row.className = 'row tpl-row';
  
  // Repo dropdown - populate from cached templates
  const r = document.createElement('select');
  r.disabled = false; // ensure repo is selectable
  const optRepoPh = document.createElement('option');
  optRepoPh.value = '';
  optRepoPh.textContent = 'Select repo';
  r.appendChild(optRepoPh);
  
  // Populate repositories from cache
  const populateReposFromCache = () => {
    const cachedTemplates = window.cachedTemplates || [];
    const repos = Array.from(new Set(cachedTemplates.map(t => t.repo_name).filter(Boolean))).sort();
    repos.forEach(repoName => {
      const opt = document.createElement('option');
      opt.value = repoName;
      opt.textContent = repoName;
      r.appendChild(opt);
    });
  };
  
  // Load cache if not already loaded, then populate repos
  if (!window.cachedTemplates || window.cachedTemplates.length === 0) {
    // Load cache asynchronously, then populate
    (async () => {
      try {
        const cacheData = await apiJson('/cache/templates');
        window.cachedTemplates = cacheData.templates || [];
        populateReposFromCache();
      } catch (error) {
        console.error('Error loading cached templates:', error);
      }
    })();
  } else {
    // Cache already loaded - populate immediately
    populateReposFromCache();
  }
  
  // Template filtered dropdown
  const templateFiltered = createFilteredDropdown('Select template', '250px');
  const t = templateFiltered.select;
  // allow template selection once repo is chosen
  templateFiltered.enable();
  
  // Version dropdown
  const v = document.createElement('select');
  v.disabled = true;
  const optVerPh = document.createElement('option');
  optVerPh.value = '';
  optVerPh.textContent = 'Select version';
  v.appendChild(optVerPh);
  
  // Remove button
  const rm = document.createElement('button');
  rm.textContent = 'Remove';
  rm.onclick = (e) => {
    e.preventDefault();
    row.remove();
    updateEditInstallSelectFromRows();
  };
  
  row.appendChild(document.createTextNode('Repo'));
  row.appendChild(r);
  row.appendChild(document.createTextNode(' Template'));
  row.appendChild(templateFiltered.container);
  row.appendChild(document.createTextNode(' Version'));
  row.appendChild(v);
  row.appendChild(rm);
  container.appendChild(row);
  
  // Store filtered dropdown reference
  row._templateFiltered = templateFiltered;
  
  // Handle repository change - populate templates from cache
  r.addEventListener('change', () => {
    const repoName = r.value;
    templateFiltered.populateOptions([]);
    templateFiltered.disable();
    v.innerHTML = '';
    v.appendChild(optVerPh.cloneNode(true));
    v.disabled = true;
    
    if (!repoName) return;
    
    // Get unique template names for this repo from cache
    // Use window.cachedTemplates (full cache) to show all available templates
    const cacheToUse = window.cachedTemplates || [];
    const templatesForRepo = cacheToUse.filter(t => t.repo_name === repoName);
    const uniqueNames = Array.from(new Set(templatesForRepo.map(t => t.template_name).filter(Boolean))).sort();
    
    const templateOptions = uniqueNames.map(name => {
      const o = document.createElement('option');
      o.value = name;
      o.textContent = name;
      return o;
    });
    
    templateFiltered.populateOptions(templateOptions);
    templateFiltered.enable();
    // Add a small delay to ensure dropdown is populated
    setTimeout(() => {
      updateEditInstallSelectFromRows();
    }, 100);
  });
  
  // Handle template change - populate versions from cache
  const handleTemplateChange = () => {
    const repoName = r.value;
    const templateName = templateFiltered ? templateFiltered.getValue() : t.value;
    
    
    v.innerHTML = '';
    v.appendChild(optVerPh.cloneNode(true));
    v.disabled = true;
    
    if (!repoName || !templateName) {
      updateEditInstallSelectFromRows();
      return;
    }
    
    // Get versions for this repo+template from cache
    // Use window.cachedTemplates (full cache) to show all available versions
    const cacheToUse = window.cachedTemplates || [];
    
    const matchingTemplates = cacheToUse.filter(t => {
      const repoMatch = t.repo_name === repoName;
      const templateMatch = t.template_name === templateName;
      return repoMatch && templateMatch && t.version;
    });
    
    
    const versions = matchingTemplates
      .map(t => t.version)
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    
    
    versions.forEach(ver => {
      const o = document.createElement('option');
      o.value = ver;
      o.textContent = ver;
      v.appendChild(o);
    });
    
    v.disabled = false;
    
    // Add a small delay to ensure dropdowns are fully updated
    setTimeout(() => {
      updateEditInstallSelectFromRows();
    }, 100);
  };
  
  // Listen to both the hidden select and the filtered input
  t.addEventListener('change', handleTemplateChange);
  if (templateFiltered.input) {
    templateFiltered.input.addEventListener('change', () => {
      setTimeout(() => {
        handleTemplateChange();
      }, 100);
    });
    templateFiltered.input.addEventListener('blur', () => {
      setTimeout(() => {
        handleTemplateChange();
      }, 100);
    });
  }
  
  // Handle version change - update install select dropdown
  v.addEventListener('change', () => {
    // Add a small delay to ensure value is properly set
    setTimeout(() => {
      updateEditInstallSelectFromRows();
    }, 100);
  });
  
  // Prefill if provided
  if (prefill) {
    setTimeout(() => {
      if (prefill.repo_name && r.options.length > 1) {
        r.value = prefill.repo_name;
        r.dispatchEvent(new Event('change'));
        
        setTimeout(() => {
          if (prefill.template_name) {
            templateFiltered.setValue(prefill.template_name);
            
            // Also set the hidden select value
            if (templateFiltered.select) {
              templateFiltered.select.value = prefill.template_name;
            }
            
            // Trigger change event to populate versions
            t.dispatchEvent(new Event('change'));
            
            // Manually trigger handleTemplateChange to ensure versions are populated
            setTimeout(() => {
              handleTemplateChange();
              
              // Wait for handleTemplateChange to populate versions dropdown
              setTimeout(() => {
                if (v.options.length > 1) {
                }
                
                if (prefill.version && v.options.length > 1) {
                  const verOpt = Array.from(v.options).find(opt => opt.value === prefill.version);
                  if (verOpt) {
                    v.value = prefill.version;
                    v.dispatchEvent(new Event('change'));
                  } else {
                    // Select first version if available
                    if (v.options.length > 1) {
                      v.value = v.options[1].value;
                    }
                  }
                } else {
                  // Select first version if available
                  if (v.options.length > 1) {
                    v.value = v.options[1].value;
                  }
                }
                
                // Wait a bit more to ensure all values are set, then update
                setTimeout(() => {
                  updateEditInstallSelectFromRows();
                }, 300);
              }, 500); // Wait for versions to be populated
            }, 200);
          } else {
            // Even if no template_name, still update after delay
            setTimeout(() => {
              updateEditInstallSelectFromRows();
            }, 500);
          }
        }, 600); // Wait for template dropdown to populate
      } else {
        // Even if no repo_name, still update after delay
        setTimeout(() => {
          updateEditInstallSelectFromRows();
        }, 500);
      }
    }, 200);
  } else {
    // Update immediately if no prefill (for new rows)
    setTimeout(() => {
      updateEditInstallSelectFromRows();
    }, 100);
  }
}

// Update install select dropdown from template rows in edit form
function updateEditInstallSelectFromRows(preserveValue) {
  const select = el('editInstallSelect');
  if (!select) {
    return;
  }
  
  const rows = document.querySelectorAll('#editTplFormList .tpl-row');
  
  if (rows.length === 0) {
    updateEditInstallSelect([], select.value);
    return;
  }
  
  const templates = [];
  
  rows.forEach((row) => {
    const selects = row.querySelectorAll('select');
    const repoSelect = selects[0];
    const templateFiltered = row._templateFiltered;
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    
    if (!repoSelect || !templateFiltered || !versionSelect) {
      return; // Skip rows that don't have all required elements yet
    }
    
    // Get template name - try multiple methods
    let template_name = '';
    
    // Method 1: getValue() method
    if (templateFiltered.getValue) {
      try {
        template_name = (templateFiltered.getValue() || '').trim();
      } catch (e) {
        // Ignore errors
      }
    }
    
    // Method 2: Check input field value
    if (!template_name && templateFiltered.input) {
      const inputVal = (templateFiltered.input.value || '').trim();
      if (inputVal) {
        // Try to match with datalist options
        if (templateFiltered.datalist) {
          const datalistOptions = templateFiltered.datalist.querySelectorAll('option');
          const match = Array.from(datalistOptions).find(opt => opt.value === inputVal);
          if (match) {
            template_name = inputVal;
          }
        } else {
          template_name = inputVal;
        }
      }
    }
    
    // Method 3: Check hidden select value
    if (!template_name && templateFiltered.select) {
      const selectVal = (templateFiltered.select.value || '').trim();
      if (selectVal) template_name = selectVal;
    }
    
    // Method 4: Check if input has a matching option (user typed it)
    if (!template_name && templateFiltered.input && templateFiltered.datalist) {
      const inputText = templateFiltered.input.value.trim();
      if (inputText) {
        const options = templateFiltered.datalist.querySelectorAll('option');
        for (const opt of options) {
          if (opt.value.toLowerCase() === inputText.toLowerCase() || opt.value === inputText) {
            template_name = opt.value;
            break;
          }
        }
      }
    }
    
    // Get version
    const version = (versionSelect.value || '').trim();
    
    // Add if both template name and version are present
    // Silently skip rows without complete data (they're still loading)
    if (template_name && version) {
      templates.push({ template_name, version });
    }
  });
  
  // Update the dropdown
  const valueToPreserve = preserveValue !== undefined ? preserveValue : select.value;
  updateEditInstallSelect(templates, valueToPreserve);
}
function updateEditInstallSelect(templates, selectedValue) {
  const select = el('editInstallSelect');
  if (!select) {
    return;
  }
  
  const currentValue = select.value;
  select.innerHTML = '';
  
  if (!templates || templates.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No templates available (add templates in Create Workspace above)';
    select.appendChild(opt);
    select.disabled = false;
    return;
  }
  
  // Create unique template entries and sort
  const uniqueTemplates = new Map();
  templates.forEach(t => {
    if (t.template_name && t.version) {
      const key = `${t.template_name}|||${t.version}`;
      if (!uniqueTemplates.has(key)) {
        uniqueTemplates.set(key, { template_name: t.template_name, version: t.version });
      }
    }
  });
  
  // Sort templates alphabetically
  let allOptions = Array.from(uniqueTemplates.values()).sort((a, b) => {
    const nameCompare = a.template_name.localeCompare(b.template_name);
    if (nameCompare !== 0) return nameCompare;
    return a.version.localeCompare(b.version);
  });
  
  // If a stored selection is provided, move it to the first position
  if (selectedValue && selectedValue !== '') {
    const selectedIndex = allOptions.findIndex(t => `${t.template_name}|||${t.version}` === selectedValue);
    if (selectedIndex > 0) {
      // Move the selected template to the beginning
      const selectedTemplate = allOptions[selectedIndex];
      allOptions.splice(selectedIndex, 1);
      allOptions.unshift(selectedTemplate);
    }
  }
  
  // Only add placeholder option if list is empty
  if (allOptions.length === 0) {
    const placeholderOpt = document.createElement('option');
    placeholderOpt.value = '';
    placeholderOpt.textContent = 'Select workspace to run...';
    select.appendChild(placeholderOpt);
  } else {
    // Add template options directly (no placeholder), with stored selection first
    allOptions.forEach(({template_name, version}) => {
      const opt = document.createElement('option');
      opt.value = `${template_name}|||${version}`;
      opt.textContent = `${template_name} (v${version})`;
      select.appendChild(opt);
    });
  }
  
  
  // Restore selection if possible
  select.disabled = false;
  
  // If a selectedValue was provided (e.g., stored value from config), prioritize it
  // Otherwise, try to preserve the current selection
  const valueToRestore = selectedValue !== undefined && selectedValue !== '' ? selectedValue : (currentValue || '');
  
  if (valueToRestore) {
    const match = Array.from(select.options).find(o => o.value === valueToRestore);
    if (match) {
      select.value = valueToRestore;
    } else {
      // If stored value not found, log a warning
      // If we have options (no placeholder), select the first one
      if (select.options.length > 0) {
        select.value = select.options[0].value;
      }
    }
  } else if (select.options.length > 0) {
    // No stored value - if we have options (no placeholder), select the first one
    select.value = select.options[0].value;
  }
}

function collectConfigFromEditForm() {
  // Get NHI credential ID from dropdown
  const nhiCredentialSelect = el('editNhiCredentialSelect');
  const nhiCredentialId = nhiCredentialSelect ? (nhiCredentialSelect.value || '') : (window.editNhiCredentialId || '');
  
  const config = {
    // API Base removed
    fabricHost: el('editFabricHost')?.value || '',
    nhiCredentialId: nhiCredentialId,
    expertMode: el('editExpertMode')?.checked || false,
    newHostname: el('editNewHostname')?.value || '',
    chgPass: el('editChgPass')?.value || '',
    installSelect: el('editInstallSelect')?.value || '',
    runWorkspaceEnabled: el('editRunWorkspaceEnabled') ? el('editRunWorkspaceEnabled').checked : true,
    sshProfileId: el('editSshProfileSelect')?.value || '',
    sshWaitTime: el('editSshWaitTime') ? (parseInt(el('editSshWaitTime').value) || 60) : 60,
    confirmedHosts: [],
    templates: []
  };
  
  // Parse confirmed hosts from fabricHost input or use validated hosts
  if (window.editValidatedHosts && window.editValidatedHosts.length > 0) {
    config.confirmedHosts = window.editValidatedHosts.map(h => ({ host: h.host, port: h.port }));
  } else {
    const fabricHostValue = config.fabricHost;
    if (fabricHostValue) {
      const hosts = fabricHostValue.split(/\s+/).filter(h => h.trim()).map(hostStr => {
        const parts = hostStr.split(':');
        return {
          host: parts[0],
          port: parts.length > 1 ? parts[1] : undefined
        };
      });
      config.confirmedHosts = hosts;
    }
  }
  
  // Collect templates from edit form rows
  const rows = document.querySelectorAll('#editTplFormList .tpl-row');
  rows.forEach(row => {
    const selects = row.querySelectorAll('select');
    const repoSelect = selects[0];
    const templateFiltered = row._templateFiltered;
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    
    if (repoSelect && templateFiltered && versionSelect) {
      const repo_name = repoSelect.value;
      const template_name = templateFiltered ? templateFiltered.getValue() : '';
      const version = versionSelect.value;
      
      if (repo_name && template_name && version) {
        config.templates.push({ repo_name, template_name, version });
      }
    }
  });
  
  return config;
}

async function handleSaveEditConfig() {
  try {
    const nameInput = el('editConfigName');
    if (!nameInput || !nameInput.value.trim()) {
      showStatus('Configuration name is required');
      return;
    }
    
    // Validate guest password if provided
    const editChgPassInput = el('editChgPass');
    if (editChgPassInput && editChgPassInput.value.trim()) {
      const passwordValidation = validateGuestPassword(editChgPassInput.value.trim());
      if (!passwordValidation.valid) {
        showStatus(`Password policy violation: Missing ${passwordValidation.errors.join(', ')}`);
        validateGuestPasswordField('editChgPass', 'editChgPassError');
        return;
      }
    }
    
    const name = nameInput.value.trim();
    
    // Get the original config for fallback data
    let originalConfigData = null;
    if (editingConfigId) {
      try {
        const getRes = await api(`/config/get/${editingConfigId}`);
        if (getRes.ok) {
          const originalData = await getRes.json();
          originalConfigData = originalData.config_data || null;
        }
      } catch (err) {
      }
    }
    
    const config = collectConfigFromEditForm();
    
    // Templates are now collected from the form rows, so no need to preserve from original
    
    // If confirmedHosts are not parsed from fabricHost input, preserve from original
    if ((!config.confirmedHosts || config.confirmedHosts.length === 0) && 
        originalConfigData && originalConfigData.confirmedHosts) {
      config.confirmedHosts = originalConfigData.confirmedHosts;
    }
    
    const payload = {
      name: name,
      config_data: config,
      id: editingConfigId
    };
    
    const res = await api('/config/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (!res.ok) {
      const errorText = await res.text();
      showStatus(`Failed to save configuration: ${errorText}`);
      return;
    }
    
    const data = await res.json();
    showStatus(data.message || 'Configuration updated successfully');
    logMsg(`Configuration updated: ${name} (ID: ${editingConfigId})`);
    
    // Clear edit mode
    const savedConfigId = editingConfigId;
    editingConfigId = null;
    
    // Clear API cache and pending requests for configurations list
    const cacheKey = '/config/list?';
    if (_requestCache.has(cacheKey)) {
      _requestCache.delete(cacheKey);
    }
    if (_pendingRequests.has(cacheKey)) {
      _pendingRequests.delete(cacheKey);
    }
    
    // Clear cache for the saved configuration to ensure fresh data on next load
    if (savedConfigId) {
      const configCacheKey = `/config/get/${savedConfigId}?`;
      if (_requestCache.has(configCacheKey)) {
        _requestCache.delete(configCacheKey);
      }
      if (_pendingRequests.has(configCacheKey)) {
        _pendingRequests.delete(configCacheKey);
      }
    }
    
    // Return to list view (this will call showConfigsListView which calls loadConfigurations)
    cancelEditConfig();
    
    // Note: cancelEditConfig() already calls showConfigsListView() which calls loadConfigurations()
    // No need to click menu item or call loadConfigurations() again
  } catch (error) {
    showStatus(`Error saving configuration: ${error.message || error}`);
    logMsg(`Error saving configuration: ${error.message || error}`);
  }
}

function showConfigsListView() {
  const listView = el('configsListView');
  const editView = el('configEditView');
  const runView = el('configRunView');
  if (listView) listView.style.display = 'block';
  if (editView) editView.style.display = 'none';
  if (runView) runView.style.display = 'none';
  clearConfigName();
  loadConfigurations();
}

function showNewConfigView() {
  // Clear edit mode
  editingConfigId = null;
  
  // Show edit view and hide list view
  const listView = el('configsListView');
  const editView = el('configEditView');
  const runView = el('configRunView');
  if (listView) listView.style.display = 'none';
  if (editView) editView.style.display = 'block';
  if (runView) runView.style.display = 'none';
  
  // Update title
  const title = el('configEditTitle');
  if (title) title.textContent = 'New Configuration';
  
  // Clear form
  const inputs = ['editConfigName', 'editFabricHost', 'editNewHostname', 'editChgPass', 'editSshWaitTime'];
  inputs.forEach(id => {
    const input = el(id);
    if (input) input.value = '';
  });
  
  // Clear NHI credential dropdown
  const nhiCredentialSelect = el('editNhiCredentialSelect');
  if (nhiCredentialSelect) nhiCredentialSelect.value = '';
  
  // Clear SSH profile dropdown
  const editSshProfileSelect = el('editSshProfileSelect');
  if (editSshProfileSelect) editSshProfileSelect.value = '';
  
  const expertModeInput = el('editExpertMode');
  if (expertModeInput) expertModeInput.checked = false;
  
  const runWorkspaceEnabled = el('editRunWorkspaceEnabled');
  if (runWorkspaceEnabled) runWorkspaceEnabled.checked = true;
  
  const fabricHostChips = el('editFabricHostChips');
  if (fabricHostChips) fabricHostChips.innerHTML = '';
  
  const fabricHostStatus = el('editFabricHostStatus');
  if (fabricHostStatus) fabricHostStatus.textContent = '';
  
  const tplFormList = el('editTplFormList');
  if (tplFormList) tplFormList.innerHTML = '';
  
  // Clear install select dropdown
  const editInstallSelect = el('editInstallSelect');
  if (editInstallSelect) editInstallSelect.innerHTML = '';
  
  window.editNhiCredentialId = '';
  window.editValidatedHosts = [];
  
  // Load NHI credentials and SSH profiles for the edit form
  loadNhiCredentialsForEdit();
  loadSshProfilesForEdit();
  
  // Ensure NHI credential change handler is set up (in case it wasn't set up yet)
  if (nhiCredentialSelect && !nhiCredentialSelect.hasAttribute('data-listener-added')) {
    nhiCredentialSelect.addEventListener('change', async () => {
      window.editNhiCredentialId = nhiCredentialSelect.value || '';
      // Load the NHI credential and populate hosts
      if (nhiCredentialSelect.value) {
        await loadSelectedNhiCredentialForEdit();
      } else {
        // Clear hosts if no credential selected
        const editFabricHostInput = el('editFabricHost');
        if (editFabricHostInput) {
          editFabricHostInput.value = '';
        }
        const editFabricHostChips = el('editFabricHostChips');
        if (editFabricHostChips) {
          editFabricHostChips.innerHTML = '';
        }
        window.editValidatedHosts = [];
      }
    });
    nhiCredentialSelect.setAttribute('data-listener-added', 'true');
  }
  
  showStatus('Creating new configuration');
}

// Load NHI credentials for edit form
async function loadNhiCredentialsForEdit() {
  const nhiSelect = el('editNhiCredentialSelect');
  if (!nhiSelect) return;
  
  try {
    const res = await api('/nhi/list');
    if (res.ok) {
      const data = await res.json();
      const credentials = data.credentials || [];
      
      nhiSelect.innerHTML = '<option value="">Select NHI credential...</option>';
      credentials.forEach(cred => {
        const option = document.createElement('option');
        option.value = cred.id.toString();
        option.textContent = `${cred.name} (${cred.client_id})`;
        nhiSelect.appendChild(option);
      });
    }
  } catch (error) {
    logMsg(`Error loading NHI credentials for edit: ${error.message || error}`);
  }
}

// Load SSH profiles for edit form
async function loadSshProfilesForEdit() {
  const sshSelect = el('editSshProfileSelect');
  if (!sshSelect) return;
  
  try {
    const res = await api('/ssh-command-profiles/list');
    if (res.ok) {
      const data = await res.json();
      const profiles = data.profiles || [];
      
      sshSelect.innerHTML = '<option value="">None (select SSH profile)</option>';
      profiles.forEach(profile => {
        const option = document.createElement('option');
        option.value = profile.id.toString();
        option.textContent = profile.name || `Profile ${profile.id}`;
        sshSelect.appendChild(option);
      });
    }
  } catch (error) {
    logMsg(`Error loading SSH profiles for edit: ${error.message || error}`);
  }
}

function cancelEditConfig() {
  // Clear edit mode
  editingConfigId = null;
  
  // Show list view and hide edit view
  showConfigsListView();
  
  // Clear form
  const inputs = ['editConfigName', 'editFabricHost', 'editNewHostname', 'editChgPass', 'editSshWaitTime'];
  inputs.forEach(id => {
    const input = el(id);
    if (input) input.value = '';
  });
  
  // Clear NHI credential dropdown
  const nhiCredentialSelect = el('editNhiCredentialSelect');
  if (nhiCredentialSelect) nhiCredentialSelect.value = '';
  
  // Clear SSH profile dropdown
  const editSshProfileSelect = el('editSshProfileSelect');
  if (editSshProfileSelect) editSshProfileSelect.value = '';
  
  const expertModeInput = el('editExpertMode');
  if (expertModeInput) expertModeInput.checked = false;
  
  const fabricHostChips = el('editFabricHostChips');
  if (fabricHostChips) fabricHostChips.innerHTML = '';
  
  const fabricHostStatus = el('editFabricHostStatus');
  if (fabricHostStatus) fabricHostStatus.textContent = '';
  
  const tplFormList = el('editTplFormList');
  if (tplFormList) tplFormList.innerHTML = '';
  
  // Clear install select dropdown
  const editInstallSelect = el('editInstallSelect');
  if (editInstallSelect) editInstallSelect.innerHTML = '';
  
  window.editNhiCredentialId = '';
  window.editValidatedHosts = [];
  
  showStatus('Edit cancelled');
}

async function deleteConfiguration(configId) {
  try {
    const res = await api(`/config/delete/${configId}`, { method: 'DELETE' });
    if (!res.ok) {
      if (res.status === 404) {
        // Configuration doesn't exist - might have been already deleted
        showStatus('Configuration not found (may have been already deleted)');
        logMsg(`Configuration ${configId} not found - may have been already deleted`);
        // Still reload the list to refresh the UI
        loadConfigurations();
      } else {
        const errorText = await res.text().catch(() => `HTTP ${res.status}`);
        showStatus(`Failed to delete configuration: ${errorText}`);
        logMsg(`Failed to delete configuration ${configId}: ${errorText}`);
      }
      return;
    }
    
    showStatus('Configuration deleted successfully');
    logMsg(`Configuration ${configId} deleted`);
    
    // Clear API cache for config list to ensure fresh data
    const cacheKey = '/config/list?';
    if (_requestCache.has(cacheKey)) {
      _requestCache.delete(cacheKey);
    }
    
    // Reload configurations list
    loadConfigurations();
  } catch (error) {
    showStatus(`Error deleting configuration: ${error.message || error}`);
    logMsg(`Error deleting configuration: ${error.message || error}`);
  }
}

// Login and authentication handling
async function checkAuth() {
  try {
    const res = await api('/user/current');
    if (res.ok) {
      return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

async function showLoginModal() {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(0,0,0,0.6)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '10000';

    const dialog = document.createElement('div');
    dialog.style.background = 'white';
    dialog.style.border = '1px solid #d2d2d7';
    dialog.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
    dialog.style.width = '400px';
    dialog.style.maxWidth = '90%';
    dialog.style.padding = '24px';
    dialog.style.borderRadius = '0';

    const title = document.createElement('h2');
    title.textContent = 'Login Required';
    title.style.margin = '0 0 20px 0';
    title.style.fontSize = '20px';
    title.style.fontWeight = '600';
    dialog.appendChild(title);

    const usernameLabel = document.createElement('label');
    usernameLabel.textContent = 'Username:';
    usernameLabel.style.display = 'block';
    usernameLabel.style.marginBottom = '6px';
    dialog.appendChild(usernameLabel);

    const usernameInput = document.createElement('input');
    usernameInput.type = 'text';
    usernameInput.autocomplete = 'username';
    usernameInput.style.width = '100%';
    usernameInput.style.boxSizing = 'border-box';
    usernameInput.style.margin = '0 0 16px 0';
    usernameInput.style.padding = '8px 12px';
    usernameInput.style.border = '1px solid #d2d2d7';
    usernameInput.style.minHeight = '36px';
    dialog.appendChild(usernameInput);

    const passwordLabel = document.createElement('label');
    passwordLabel.textContent = 'Password:';
    passwordLabel.style.display = 'block';
    passwordLabel.style.marginBottom = '6px';
    dialog.appendChild(passwordLabel);

    const passwordInput = document.createElement('input');
    passwordInput.type = 'password';
    passwordInput.autocomplete = 'current-password';
    passwordInput.style.width = '100%';
    passwordInput.style.boxSizing = 'border-box';
    passwordInput.style.margin = '0 0 20px 0';
    passwordInput.style.padding = '8px 12px';
    passwordInput.style.border = '1px solid #d2d2d7';
    passwordInput.style.minHeight = '36px';
    dialog.appendChild(passwordInput);

    const errorMsg = document.createElement('div');
    errorMsg.style.color = '#f87171';
    errorMsg.style.marginBottom = '16px';
    errorMsg.style.display = 'none';
    dialog.appendChild(errorMsg);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '12px';
    actions.style.justifyContent = 'flex-end';

    const loginBtn = document.createElement('button');
    loginBtn.textContent = 'Login';
    loginBtn.className = 'btn btn-primary';
    loginBtn.onclick = async () => {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      
      if (!username || !password) {
        errorMsg.textContent = 'Please enter username and password';
        errorMsg.style.display = 'block';
        return;
      }
      
      loginBtn.disabled = true;
      loginBtn.textContent = 'Logging in...';
      
      try {
        const res = await api('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        if (res.ok) {
          document.body.removeChild(overlay);
          resolve(true);
        } else {
          const data = await res.json().catch(() => ({ detail: 'Login failed' }));
          errorMsg.textContent = data.detail || 'Invalid username or password';
          errorMsg.style.display = 'block';
          loginBtn.disabled = false;
          loginBtn.textContent = 'Login';
        }
      } catch (e) {
        errorMsg.textContent = 'Login failed. Please try again.';
        errorMsg.style.display = 'block';
        loginBtn.disabled = false;
        loginBtn.textContent = 'Login';
      }
    };
    
    passwordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        loginBtn.click();
      }
    });
    
    actions.appendChild(loginBtn);
    dialog.appendChild(actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    usernameInput.focus();
  });
}

// User Management functions
function setupUserManagement() {
  const form = document.getElementById('changePasswordForm');
  if (!form) return;
  
  // Load users list
  loadUsers();
  
  // Setup create user button
  const createUserBtn = el('btnCreateUser');
  if (createUserBtn) {
    createUserBtn.addEventListener('click', () => {
      showCreateUserDialog();
    });
  }
  
  // Add real-time password match validation
  const newPasswordInput = el('newPassword');
  const confirmPasswordInput = el('confirmPassword');
  const passwordMatchError = el('passwordMatchError');
  
  const validatePasswordMatch = () => {
    if (passwordMatchError) {
      const newPwd = newPasswordInput ? newPasswordInput.value : '';
      const confirmPwd = confirmPasswordInput ? confirmPasswordInput.value : '';
      if (confirmPwd && newPwd !== confirmPwd) {
        passwordMatchError.textContent = 'Passwords do not match';
        passwordMatchError.style.display = 'inline';
      } else {
        passwordMatchError.style.display = 'none';
      }
    }
  };
  
  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    confirmPasswordInput.addEventListener('blur', validatePasswordMatch);
  }
  if (newPasswordInput) {
    newPasswordInput.addEventListener('input', validatePasswordMatch);
  }
  
  form.onsubmit = async (e) => {
    e.preventDefault();
    
    // Hide previous errors
    if (passwordMatchError) {
      passwordMatchError.style.display = 'none';
    }
    
    const currentPassword = el('currentPassword') ? el('currentPassword').value : '';
    const newPassword = newPasswordInput ? newPasswordInput.value : '';
    const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : '';
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      showUserManagementStatus('Please fill in all fields', true);
      return;
    }
    
    if (newPassword !== confirmPassword) {
      if (passwordMatchError) {
        passwordMatchError.textContent = 'Passwords do not match';
        passwordMatchError.style.display = 'inline';
      }
      showUserManagementStatus('New passwords do not match', true);
      return;
    }
    
    if (newPassword.length < 7) {
      showUserManagementStatus('Password must be at least 7 characters long', true);
      return;
    }
    
    const hasNumber = /\d/.test(newPassword);
    if (!hasNumber) {
      showUserManagementStatus('Password must contain at least one number', true);
      return;
    }
    
    const specialChars = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(newPassword);
    if (!specialChars) {
      showUserManagementStatus('Password must contain at least one special character', true);
      return;
    }
    
    const changeBtn = el('btnChangePassword');
    if (changeBtn) {
      changeBtn.disabled = true;
      changeBtn.textContent = 'Changing...';
    }
    
    try {
      const res = await api('/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });
      
      if (res.ok) {
        const data = await res.json();
        showUserManagementStatus(data.message || 'Password changed successfully');
        form.reset();
        if (passwordMatchError) {
          passwordMatchError.style.display = 'none';
        }
      } else {
        const error = await res.json().catch(() => ({ detail: 'Failed to change password' }));
        showUserManagementStatus(error.detail || 'Failed to change password', true);
      }
    } catch (e) {
      showUserManagementStatus('Error changing password: ' + (e.message || e), true);
    } finally {
      if (changeBtn) {
        changeBtn.disabled = false;
        changeBtn.textContent = 'Change Password';
      }
    }
  };
}

async function loadUsers() {
  const usersListEl = el('usersList');
  if (!usersListEl) return;
  
  try {
    usersListEl.innerHTML = '<p style="color: #86868b; font-size: 13px;">Loading users...</p>';
    
    const res = await api('/user/list');
    if (!res.ok) {
      usersListEl.innerHTML = '<p style="color: #f87171; font-size: 13px;">Failed to load users</p>';
      return;
    }
    
    const data = await res.json();
    const users = data.users || [];
    
    if (users.length === 0) {
      usersListEl.innerHTML = '<p style="color: #86868b; font-size: 13px;">No users found</p>';
      return;
    }
    
    // Get current user to highlight
    let currentUserId = null;
    try {
      const currentUserRes = await api('/user/current');
      if (currentUserRes.ok) {
        const currentUserData = await currentUserRes.json();
        currentUserId = currentUserData.id;
      }
    } catch (e) {
      // Ignore errors
    }
    
    let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';
    users.forEach(user => {
      const isCurrentUser = user.id === currentUserId;
      const createdDate = formatDateTime(user.created_at);
      html += `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: white; border: 1px solid #d2d2d7; border-radius: 4px;">
          <div>
            <div style="font-weight: 600; font-size: 14px; color: #1d1d1f;">
              ${user.username}${isCurrentUser ? ' <span style="color: #86868b; font-weight: normal; font-size: 12px;">(You)</span>' : ''}
            </div>
            <div style="font-size: 12px; color: #86868b; margin-top: 4px;">
              Created: ${createdDate}
            </div>
          </div>
          ${!isCurrentUser ? `<button type="button" class="btn-delete-user" data-user-id="${user.id}" data-username="${user.username}" style="padding: 4px 12px; font-size: 12px; background: #f87171; color: white; border: none; cursor: pointer; border-radius: 0; font-weight: 600;">Delete</button>` : ''}
        </div>
      `;
    });
    html += '</div>';
    
    usersListEl.innerHTML = html;
    
    // Add event listeners for delete buttons
    usersListEl.querySelectorAll('.btn-delete-user').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const userId = parseInt(btn.getAttribute('data-user-id'));
        const username = btn.getAttribute('data-username');
        await deleteUser(userId, username);
      });
    });
  } catch (error) {
    usersListEl.innerHTML = `<p style="color: #f87171; font-size: 13px;">Error loading users: ${error.message || error}</p>`;
  }
}
function showCreateUserDialog() {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.5);
      z-index: 10000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    `;
    
    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: white;
      border-radius: 0;
      padding: 24px;
      max-width: 500px;
      width: 100%;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    `;
    
    dialog.innerHTML = `
      <h3 style="margin: 0 0 20px 0; font-size: 18px; font-weight: 600; color: #1d1d1f;">Create New User</h3>
      
      <form id="createUserForm">
        <div style="margin-bottom: 16px;">
          <label for="newUsername" style="display: block; margin-bottom: 6px; font-weight: 500; color: #1d1d1f; font-size: 14px;">Username:</label>
          <input 
            type="text" 
            id="newUsername" 
            name="username" 
            required
            autocomplete="username"
            style="width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #d2d2d7; border-radius: 0; font-size: 14px; min-height: 40px; font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'Liberation Sans', sans-serif;"
            placeholder="Enter username"
          />
          <div style="font-size: 12px; color: #86868b; margin-top: 4px;">Alphanumeric characters, dashes, and underscores only</div>
        </div>
        
        <div style="margin-bottom: 16px;">
          <label for="newUserPassword" style="display: block; margin-bottom: 6px; font-weight: 500; color: #1d1d1f; font-size: 14px;">Password:</label>
          <input 
            type="password" 
            id="newUserPassword" 
            name="password" 
            required
            autocomplete="new-password"
            style="width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #d2d2d7; border-radius: 0; font-size: 14px; min-height: 40px; font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'Liberation Sans', sans-serif;"
            placeholder="Enter password"
          />
          <div style="font-size: 12px; color: #86868b; margin-top: 4px;">Must be at least 7 characters with 1 number and 1 special character</div>
        </div>
        
        <div style="margin-bottom: 20px;">
          <label for="newUserConfirmPassword" style="display: block; margin-bottom: 6px; font-weight: 500; color: #1d1d1f; font-size: 14px;">Confirm Password:</label>
          <input 
            type="password" 
            id="newUserConfirmPassword" 
            name="confirmPassword" 
            required
            autocomplete="new-password"
            style="width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #d2d2d7; border-radius: 0; font-size: 14px; min-height: 40px; font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'Liberation Sans', sans-serif;"
            placeholder="Confirm password"
          />
          <div id="createUserPasswordMatchError" style="font-size: 12px; color: #f87171; margin-top: 4px; display: none;"></div>
        </div>
        
        <div id="createUserError" style="color: #f87171; margin-bottom: 16px; display: none; font-size: 14px;"></div>
        
        <div style="display: flex; gap: 8px; justify-content: flex-end;">
          <button type="button" id="btnCancelCreateUser" style="padding: 8px 16px; border: 1px solid #d2d2d7; background: white; color: #1d1d1f; cursor: pointer; font-size: 14px; border-radius: 0;">Cancel</button>
          <button type="submit" id="btnSubmitCreateUser" style="padding: 8px 16px; background: #da291c; color: white; border: none; cursor: pointer; font-size: 14px; font-weight: 600; border-radius: 0; box-shadow: 0 2px 4px rgba(218, 41, 28, 0.3);">Create User</button>
        </div>
      </form>
    `;
    
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    const form = dialog.querySelector('#createUserForm');
    const usernameInput = dialog.querySelector('#newUsername');
    const passwordInput = dialog.querySelector('#newUserPassword');
    const confirmPasswordInput = dialog.querySelector('#newUserConfirmPassword');
    const passwordMatchError = dialog.querySelector('#createUserPasswordMatchError');
    const errorDiv = dialog.querySelector('#createUserError');
    const cancelBtn = dialog.querySelector('#btnCancelCreateUser');
    const submitBtn = dialog.querySelector('#btnSubmitCreateUser');
    
    const closeDialog = () => {
      document.body.removeChild(overlay);
      resolve(null);
    };
    
    const validatePasswordMatch = () => {
      const password = passwordInput.value;
      const confirmPassword = confirmPasswordInput.value;
      if (confirmPassword && password !== confirmPassword) {
        passwordMatchError.textContent = 'Passwords do not match';
        passwordMatchError.style.display = 'block';
        return false;
      } else {
        passwordMatchError.style.display = 'none';
        return true;
      }
    };
    
    confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    confirmPasswordInput.addEventListener('blur', validatePasswordMatch);
    
    cancelBtn.addEventListener('click', closeDialog);
    
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      errorDiv.style.display = 'none';
      passwordMatchError.style.display = 'none';
      
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      const confirmPassword = confirmPasswordInput.value;
      
      if (!username) {
        errorDiv.textContent = 'Username is required';
        errorDiv.style.display = 'block';
        return;
      }
      
      if (!password || !confirmPassword) {
        errorDiv.textContent = 'Password and confirmation are required';
        errorDiv.style.display = 'block';
        return;
      }
      
      if (!validatePasswordMatch()) {
        return;
      }
      
      if (password.length < 7) {
        errorDiv.textContent = 'Password must be at least 7 characters long';
        errorDiv.style.display = 'block';
        return;
      }
      
      const hasNumber = /\d/.test(password);
      if (!hasNumber) {
        errorDiv.textContent = 'Password must contain at least one number';
        errorDiv.style.display = 'block';
        return;
      }
      
      const specialChars = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);
      if (!specialChars) {
        errorDiv.textContent = 'Password must contain at least one special character';
        errorDiv.style.display = 'block';
        return;
      }
      
      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating...';
      submitBtn.style.opacity = '0.7';
      submitBtn.style.cursor = 'not-allowed';
      
      try {
        const res = await api('/user/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username,
            password: password
          })
        });
        
        if (res.ok) {
          const data = await res.json();
          showUserManagementStatus(data.message || 'User created successfully');
          closeDialog();
          // Clear API cache for /user/list to ensure fresh data
          const cacheKey = '/user/list?';
          _requestCache.delete(cacheKey);
          _pendingRequests.delete(cacheKey);
          await loadUsers(); // Refresh users list
          resolve({ username, password });
        } else {
          const error = await res.json().catch(() => ({ detail: 'Failed to create user' }));
          errorDiv.textContent = error.detail || 'Failed to create user';
          errorDiv.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create User';
          submitBtn.style.opacity = '1';
          submitBtn.style.cursor = 'pointer';
        }
      } catch (e) {
        errorDiv.textContent = 'Error creating user: ' + (e.message || e);
        errorDiv.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create User';
        submitBtn.style.opacity = '1';
        submitBtn.style.cursor = 'pointer';
      }
    });
    
    // Focus username field
    setTimeout(() => usernameInput.focus(), 100);
    
    // Close on overlay click
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        closeDialog();
      }
    });
    
    // Close on Escape key
    const escapeHandler = (e) => {
      if (e.key === 'Escape') {
        closeDialog();
        document.removeEventListener('keydown', escapeHandler);
      }
    };
    document.addEventListener('keydown', escapeHandler);
  });
}

function showUserManagementStatus(message, isError = false) {
  const statusEl = el('userManagementStatus');
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.style.display = 'block';
    statusEl.style.background = isError ? '#fee' : '#efe';
    statusEl.style.border = `1px solid ${isError ? '#f87171' : '#10b981'}`;
    statusEl.style.color = isError ? '#dc2626' : '#059669';
    statusEl.style.padding = '12px';
    statusEl.style.borderRadius = '4px';
    statusEl.style.margin = '12px 0';
  }
  showStatus(message, isError ? { error: true } : {});
}

async function deleteUser(userId, username) {
  if (!confirm(`Are you sure you want to delete user '${username}'? This action cannot be undone.`)) {
    return;
  }
  
  try {
    const res = await api(`/user/${userId}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (res.ok) {
      const data = await res.json();
      showUserManagementStatus(data.message || `User '${username}' deleted successfully`);
      // Clear API cache for /user/list to ensure fresh data
      const cacheKey = '/user/list?';
      _requestCache.delete(cacheKey);
      _pendingRequests.delete(cacheKey);
      await loadUsers(); // Refresh users list
    } else {
      const error = await res.json().catch(() => ({ detail: 'Failed to delete user' }));
      showUserManagementStatus(error.detail || 'Failed to delete user', true);
    }
  } catch (e) {
    showUserManagementStatus('Error deleting user: ' + (e.message || e), true);
  }
}

// Initialize without default rows
document.addEventListener('DOMContentLoaded', async () => {
  // Check authentication first - redirect to login if not authenticated
  const isAuthenticated = await checkAuth();
  if (!isAuthenticated) {
    // Redirect to login page
    window.location.href = '/login';
    return;
  }
  
  initMenu();
  // initEventFormValidation() and initNhiFormValidation() are called when sections load
  initGuestPasswordValidation();
  // Disable actions until token is acquired
  setActionsEnabled(true);
  // Ensure install controls start disabled before any user action
  const sel = el('installSelect');
  const btn = el('btnInstallSelected');
  if (sel) sel.disabled = true;
  if (btn) btn.disabled = true;
  const exp = el('expertMode');
  if (exp) {
    exp.checked = false;
    exp.addEventListener('change', () => {
      const out = el('out');
      if (out) {
        if (exp.checked) {
          out.style.display = '';
        } else {
          out.style.display = 'none';
          // Clear output when disabling Expert Mode
          out.textContent = '';
        }
      }
    });
  }
  updateCreateEnabled();
  updateInstallSelect(); // Initialize dropdown with any existing rows
  renderTemplates(false); // Initialize install controls state (don't show container on load)
});

let runStartTime = null;
let runTimerInterval = null;

function formatTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function startRunTimer() {
  runStartTime = Date.now();
  const timerEl = el('runProgressTimer');
  const actionStatusTimer = el('actionStatusTimer');
  
  if (runTimerInterval) clearInterval(runTimerInterval);
  runTimerInterval = setInterval(() => {
    if (runStartTime) {
      const elapsed = Math.floor((Date.now() - runStartTime) / 1000);
      const formatted = formatTime(elapsed);
      if (timerEl) timerEl.textContent = formatted;
      if (actionStatusTimer) actionStatusTimer.textContent = formatted;
    }
  }, 1000);
}

function stopRunTimer() {
  if (runTimerInterval) {
    clearInterval(runTimerInterval);
    runTimerInterval = null;
  }
}

function updateRunProgress(percent, status) {
  const container = el('runProgressContainer');
  const bar = el('runProgressBar');
  const text = el('runProgressText');
  const statusEl = el('runProgressStatus');
  
  // Also update actionStatus progress if it exists
  const actionStatusProgressBar = el('actionStatusProgressBar');
  const actionStatusProgressText = el('actionStatusProgressText');
  const actionStatusProgress = el('actionStatusProgress');
  const actionStatusBox = el('actionStatus');
  
  if (container) container.style.display = '';
  if (bar) {
    const clampedPercent = Math.max(0, Math.min(100, percent));
    // Use CSS custom property for reliable updates
    bar.style.setProperty('--progress', clampedPercent + '%');
    // Also set width directly as fallback
    bar.style.width = clampedPercent + '%';
  }
  if (text) text.textContent = Math.round(Math.max(0, Math.min(100, percent))) + '%';
  if (statusEl) statusEl.textContent = status || '';
  
  // Update actionStatus progress bar
  if (actionStatusProgressBar) {
    const clampedPercent = Math.max(0, Math.min(100, percent));
    actionStatusProgressBar.style.width = clampedPercent + '%';
    actionStatusProgressBar.style.setProperty('--progress', clampedPercent + '%');
  }
  if (actionStatusProgressText) {
    actionStatusProgressText.textContent = Math.round(Math.max(0, Math.min(100, percent))) + '%';
  }
  
  // Always show actionStatus and progress section when updateRunProgress is called
  if (actionStatusBox) {
    actionStatusBox.style.display = '';
  }
  if (actionStatusProgress) {
    actionStatusProgress.style.display = '';
  }
  
  // Update status message if provided
  if (status) {
    const messageEl = el('actionStatusMessage');
    if (messageEl) {
      messageEl.innerHTML = status.replace(/\n/g, '<br>');
    }
  }
}

function hideRunProgress() {
  const container = el('runProgressContainer');
  const bar = el('runProgressBar');
  const actionStatusProgress = el('actionStatusProgress');
  const actionStatusProgressBar = el('actionStatusProgressBar');
  
  if (container) container.style.display = 'none';
  if (bar) {
    // Reset progress when hiding
    bar.style.setProperty('--progress', '0%');
    bar.style.width = '0%';
  }
  if (actionStatusProgress) {
    actionStatusProgress.style.display = 'none';
  }
  if (actionStatusProgressBar) {
    actionStatusProgressBar.style.width = '0%';
    actionStatusProgressBar.style.setProperty('--progress', '0%');
  }
  stopRunTimer();
  runStartTime = null;
}
// Handler function for run button
async function handleRunButton() {
  clearConfigName();
  const hosts = getAllConfirmedHosts();
  if (hosts.length === 0) {
    // Auto-confirm hosts if available
    if (autoConfirmHosts()) {
      // Hosts are now confirmed, continue
    } else {
      showStatus('No hosts configured. Please add at least one valid host.');
      return;
    }
    return;
  }
  
  runBtn = runBtn || el('btnInstallSelected');
  if (runBtn) runBtn.disabled = true;
  
  isRunInProgress = true;
  showRunInProgressWarning();
  
  updateRunProgress(0, 'Starting...');
  startRunTimer();
  
  // Show Running Tasks section
  const runningTasksContainer = el('runningTasksContainer');
  if (runningTasksContainer) {
    runningTasksContainer.style.display = '';
  }
  
  try {
    // STEP 1: Install Workspace (if not already installed)
    // User is already authenticated via login - proceed
    const hosts = parseFabricHosts();
    
    // Build templates list from ALL rows (with deduplication)
    updateRunProgress(5, 'Collecting templates...');
    const allRowTemplates = [];
    const seenTemplates = new Set(); // Track seen templates to avoid duplicates
    document.querySelectorAll('.tpl-row').forEach(row => {
      const selects = row.querySelectorAll('select');
      const repoSelect = selects[0]; // Repo is the first select
      const templateFiltered = row._templateFiltered;
      // Version is the last select (hidden template select is at index 1)
      const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
      const repo_name = repoSelect?.value || '';
      const template_name = templateFiltered ? templateFiltered.getValue() : '';
      const version = versionSelect?.value || '';
      if (template_name && repo_name && version) {
        // Create a unique key for this template
        const templateKey = `${repo_name}|||${template_name}|||${version}`;
        // Only add if we haven't seen this exact template before
        if (!seenTemplates.has(templateKey)) {
          seenTemplates.add(templateKey);
          allRowTemplates.push({ template_name, repo_name, version });
        }
      }
    });
    
    if (allRowTemplates.length === 0) {
      showStatus('No workspace templates found in rows. Please add and fill template rows.');
      hideRunProgress();
      stopRunTimer();
      return;
    }
    
    // Sort templates alphabetically by template_name, then by version
    allRowTemplates.sort((a, b) => {
      const nameCompare = a.template_name.localeCompare(b.template_name);
      if (nameCompare !== 0) return nameCompare;
      return a.version.localeCompare(b.version);
    });
    
    // Ensure ALL templates from rows are in the templates array for tracking
    allRowTemplates.forEach(({template_name, repo_name, version}) => {
      const exists = templates.find(t => t.template_name === template_name && t.version === version);
      if (!exists) {
        // Add to templates array if not already there (will be created or tracked)
        templates.push({ template_name, repo_name, version, status: '', createProgress: 0, hosts: [] });
      }
    });
    
    // Check which templates need to be created (compare with existing templates that are created/installed)
    const existingTemplates = templates.filter(t => t.status === 'created' || t.status === 'installed');
    const existingKeys = new Set(existingTemplates.map(t => `${t.template_name}|||${t.version}`));
    const templatesToCreate = allRowTemplates.filter(({template_name, version}) => 
      !existingKeys.has(`${template_name}|||${version}`)
    );
    
    // Track failed hosts across all operations (declared at function scope)
    const failedHosts = new Set();
    
    // If we need to create templates, run preparation steps first
    if (templatesToCreate.length > 0) {
      // Execute preparation steps (5-20%)
      updateRunProgress(7, 'Executing preparation steps...');
      
      // Refresh repositories
      updateRunProgress(9, 'Refreshing repositories...');
      logMsg('Refreshing repositories...');
      await executeOnAllHosts('Refresh Repositories', async (fabric_host) => {
        const res = await api('/repo/refresh', { method: 'POST', params: { fabric_host } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Uninstall workspaces (reset)
      updateRunProgress(11, 'Uninstalling workspaces...');
      logMsg('Uninstalling workspaces...');
      await executeOnAllHosts('Uninstall Workspaces', async (fabric_host) => {
        const res = await api('/runtime/reset', { method: 'POST', params: { fabric_host } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Remove workspaces (batch delete)
      updateRunProgress(13, 'Removing workspaces...');
      logMsg('Removing workspaces...');
      await executeOnAllHosts('Remove Workspaces', async (fabric_host) => {
        const res = await api('/model/fabric/batch', { method: 'DELETE', params: { fabric_host } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Change hostname (if provided)
      const hostnameBase = el('newHostname').value.trim();
      if (hostnameBase) {
        updateRunProgress(15, 'Changing hostnames...');
        // Check for running tasks before changing hostname
        await waitForNoRunningTasks(hosts, 'Change Hostname');
        const hostnamePromises = hosts.map(async ({host}, index) => {
          try {
            const hostname = hostnameBase + (index + 1);
            const res = await api('/system/hostname', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ fabric_host: host, hostname })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            logMsg(`Hostname changed to ${hostname} for ${host}`);
          } catch (error) {
            logMsg(`Change hostname failed on ${host}: ${error.message || error}`);
          }
        });
        await Promise.all(hostnamePromises);
      }
      
      // Change password (if provided)
      const new_password = el('chgPass').value.trim();
      if (new_password) {
        updateRunProgress(17, 'Changing guest user password...');
        const username = 'guest';
        await executeOnAllHosts('Change password', async (fabric_host) => {
          const res = await api('/user/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fabric_host, username, new_password })
          });
          if (!res.ok) {
            let errorMessage = `HTTP ${res.status}`;
            try {
              const errorData = await res.json();
              errorMessage = errorData.detail || errorData.message || errorMessage;
            } catch (e) {
              // If JSON parsing fails, try to get text
              try {
                const errorText = await res.text();
                if (errorText) {
                  errorMessage = errorText;
                }
              } catch (e2) {
                // Use default error message
              }
            }
            logMsg(`Password change error on ${fabric_host}: ${errorMessage}`);
            throw new Error(errorMessage);
          }
        });
      }
      
      // Add templates to create to the templates array
      updateRunProgress(20, 'Preparing templates...');
      templatesToCreate.forEach(({template_name, repo_name, version}) => {
        // Check if template already exists in templates array
        const exists = templates.find(t => t.template_name === template_name && t.version === version);
        if (!exists) {
          templates.push({ template_name, repo_name, version, status: 'spin', createProgress: 0, hosts: [] });
        }
      });
      renderTemplates();
      
      updateRunProgress(22, `Creating ${templatesToCreate.length} workspace template(s)...`);
      showStatus(`Creating ${templatesToCreate.length} workspace template(s)...`);
      logMsg(`Creating ${templatesToCreate.length} workspace template(s): ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      
      // Check for running tasks before creating templates
      await waitForNoRunningTasks(hosts, 'Create Templates');
      
      // Process templates sequentially (one at a time)
      const totalTemplates = templatesToCreate.length;
      logMsg(`Starting sequential creation of ${totalTemplates} templates: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      
      let createdCount = 0;
      
      // Process each template one at a time
      for (let i = 0; i < templatesToCreate.length; i++) {
        const rowTemplate = templatesToCreate[i];
        logMsg(`[${i + 1}/${totalTemplates}] Starting creation process for ${rowTemplate.template_name} v${rowTemplate.version}`);
        
        // Check if all hosts have failed before processing this template
        const availableHostsBeforeTemplate = hosts.filter(({host}) => !failedHosts.has(host));
        if (availableHostsBeforeTemplate.length === 0) {
          const errorMsg = `All hosts have failed. Stopping execution before processing template '${rowTemplate.template_name}'.`;
          showStatus(errorMsg);
          logMsg(errorMsg);
          updateRunProgress(100, `Execution stopped - all hosts failed`);
          renderTemplates();
          stopRunTimer();
          return;
        }
        
        // Check for running tasks before creating this template
        await waitForNoRunningTasks(hosts, `Create Template ${rowTemplate.template_name}`);
        
        // Create separate template entry for each host
        hosts.forEach(({host}) => {
          // Find or create template entry for this specific host
          let t = templates.find(t => 
            t.template_name === rowTemplate.template_name && 
            t.version === rowTemplate.version && 
            t.host === host
          );
          if (!t) {
            // Create new entry with explicit host field
            t = { 
              template_name: rowTemplate.template_name,
              repo_name: rowTemplate.repo_name,
              version: rowTemplate.version,
              host: host, // Explicitly set host (not from spread to avoid issues)
              status: 'spin', 
              createProgress: 0, 
              hosts: [host] 
            };
            templates.push(t);
          } else {
            t.status = 'spin';
            t.createProgress = 0;
            t.hosts = [host];
            // Ensure host field is set correctly if it was missing or incorrect
            if (!t.host || t.host === 'host' || t.host === 'Host') {
              t.host = host;
            }
          }
        });
        renderTemplates();
        
        // Update progress for starting this template
        const templateProgress = 20 + (i / totalTemplates) * 40;
        updateRunProgress(templateProgress, `Creating template ${i + 1}/${totalTemplates}: ${rowTemplate.template_name}`);
        
        // Process all hosts for this template in parallel
        const hostPromises = hosts.map(async ({host}) => {
          // Skip hosts that have already failed
          if (failedHosts.has(host)) {
            return {host, success: false, error: 'Host failed during previous template creation', skipped: true};
          }
          
          // Find the template entry for this specific host
          let t = templates.find(t => 
            t.template_name === rowTemplate.template_name && 
            t.version === rowTemplate.version && 
            t.host === host
          );
          if (!t) {
            // Create entry if not found - ensure host is set properly
            t = { 
              template_name: rowTemplate.template_name,
              repo_name: rowTemplate.repo_name,
              version: rowTemplate.version,
              host: host, // Explicitly set host (not from spread to avoid issues)
              status: 'spin', 
              createProgress: 0, 
              hosts: [host] 
            };
            templates.push(t);
          } else {
            // Ensure host field is set correctly if it was missing
            if (!t.host || t.host === 'host' || t.host === 'Host') {
              t.host = host;
            }
          }
          
          try {
            // 1) get template id
            const { template_id } = await apiJson('/repo/template', {
              params: {
              fabric_host: host,
              template_name: t.template_name,
              repo_name: t.repo_name,
              version: t.version,
              }
            });
            logMsg(`Template located on ${host}`);

            // 2) create fabric
            logMsg(`Creating fabric ${t.template_name} v${t.version} on ${host} (template_id: ${template_id})`);
            
            res = await api('/model/fabric', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                fabric_host: host,
                template_id,
                template_name: t.template_name,
                version: t.version,
              }),
            });
            
            if (!res.ok) {
              const errorText = await res.text().catch(() => `HTTP ${res.status}`);
              // Try to parse JSON error response to extract detail
              let errorDetail = errorText;
              try {
                const errorJson = JSON.parse(errorText);
                if (errorJson.detail) {
                  errorDetail = errorJson.detail;
                }
              } catch (e) {
                // Not JSON, use errorText as is
              }
              const errorMsg = `Failed to create fabric '${t.template_name}' v${t.version} on ${host}: ${errorDetail}`;
              showStatus(errorMsg);
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
              return {host, success: false, error: errorDetail || 'Create failed'};
            }
            
            const responseData = await res.json().catch(() => ({}));
            logMsg(`Fabric creation request submitted on ${host} for ${t.template_name} v${t.version} (template_id: ${template_id})`);

            // 3) live poll running task count until zero or timeout for creation
            const createStart = Date.now();
            const timeoutMs = 15 * 60 * 1000; // 15 minutes
            t.createProgress = 5; // Start with 5% to show immediate feedback
            renderTemplates();
            
            const progressInterval = setInterval(() => {
              const elapsed = Date.now() - createStart;
              const pct = Math.min(95, Math.max(5, Math.floor((elapsed / timeoutMs) * 100)));
              if (t.createProgress !== pct) {
                t.createProgress = pct;
                renderTemplates();
              }
            }, 500); // Update every 500ms for smoother animation

            while (Date.now() - createStart < timeoutMs) {
              const sres = await api('/tasks/status', { params: { fabric_host: host } });
              if (!sres.ok) { clearInterval(progressInterval); break; }
              const sdata = await sres.json();
              const cnt = sdata.running_count ?? 0;
              if (cnt === 0) { clearInterval(progressInterval); break; }
              await new Promise(r => setTimeout(r, 2000));
            }
            clearInterval(progressInterval);

            // mark status
            const done = await api('/tasks/status', { params: { fabric_host: host } });
            if (done.ok) {
              const d = await done.json();
              if ((d.running_count ?? 0) === 0) {
                // Check for task errors after tasks complete
                try {
                  // Capture timestamp and template name for filtering
                  const createStartTime = new Date(createStart).toISOString();
                  const errorsRes = await api('/tasks/errors', { 
                    params: { 
                      fabric_host: host, 
                      limit: 20,
                      fabric_name: t.template_name,
                      since_timestamp: createStartTime
                    } 
                  });
                  if (errorsRes.ok) {
                    const errorsData = await errorsRes.json();
                    if (errorsData.errors && errorsData.errors.length > 0) {
                      const errorMessages = errorsData.errors.map(err => `Task '${err.task_name}': ${err.error}`).join('; ');
                      const errorMsg = `Template '${t.template_name}' v${t.version} creation completed on ${host} but with errors: ${errorMessages}`;
                      showStatus(errorMsg);
                      t.status = 'err';
                      t.createProgress = 0;
                      renderTemplates();
                      return {host, success: false, error: errorMessages};
                    }
                  }
                } catch (error) {
                  // Continue anyway - this is not critical
                }
                
                // showStatus already calls logMsg internally, so don't duplicate
                showStatus(`Template '${t.template_name}' v${t.version} created successfully on ${host}`);
                t.status = 'created';
                t.createProgress = 100;
                renderTemplates();
                return {host, success: true};
              } else {
                const errorMsg = `Template '${t.template_name}' v${t.version} creation timeout on ${host} - tasks still running`;
                showStatus(errorMsg);
                t.status = 'err';
                t.createProgress = 0;
                renderTemplates();
                return {host, success: false, error: 'Timeout - tasks still running'};
              }
            } else {
              const errorText = await done.text().catch(() => 'Unknown error');
              const errorMsg = `Failed to check task status on ${host} for '${t.template_name}' v${t.version}: ${errorText}`;
              showStatus(errorMsg);
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
              return {host, success: false, error: 'Status check failed'};
            }
          } catch (error) {
            const errorMsg = `Error processing template '${rowTemplate.template_name}' v${rowTemplate.version} on ${host}: ${error.message || error}`;
            showStatus(errorMsg);
            if (t) {
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
            }
            return {host, success: false, error: error.message || error};
          }
        });

        const results = await Promise.allSettled(hostPromises);
        const settledResults = results.map(r => r.status === 'fulfilled' ? r.value : {host: 'unknown', success: false, error: r.reason?.message || 'Promise rejected'});
        const successCount = settledResults.filter(r => r.success).length;
        
        // Collect error details for failed hosts (excluding skipped ones)
        const failedHostsForTemplate = settledResults.filter(r => !r.success && !r.skipped);
        
        // Track failed hosts to skip installation later
        failedHostsForTemplate.forEach(f => failedHosts.add(f.host));
        
        // Check if all hosts failed for this template
        const availableHostsForTemplate = hosts.filter(({host}) => !failedHosts.has(host));
        
        // Stop execution if this template failed on all remaining hosts
        if (successCount === 0 && failedHostsForTemplate.length > 0) {
          const errorDetails = failedHostsForTemplate.map(f => `${f.host}: ${f.error || 'Unknown error'}`).join('; ');
          const errorMsg = `Template '${rowTemplate.template_name}' v${rowTemplate.version} creation failed on all hosts: ${errorDetails}`;
          showStatus(errorMsg);
          logMsg(`Stopping execution - template creation failed on all hosts`);
          updateRunProgress(100, `Execution stopped - template creation failed`);
          renderTemplates();
          stopRunTimer();
          return;
        }
        
        // Also stop if all hosts have failed (from previous templates)
        if (availableHostsForTemplate.length === 0) {
          const errorMsg = `All hosts have failed. Stopping execution.`;
          showStatus(errorMsg);
          logMsg(errorMsg);
          logMsg(`Stopping execution - all hosts failed`);
          updateRunProgress(100, `Execution stopped - all hosts failed`);
          renderTemplates();
          stopRunTimer();
          return;
        }
        
        // Status is already updated per host in the promise handlers above
        // Just update summary messages
        if (successCount > 0) {
          createdCount++;
          if (successCount < hosts.length) {
            const failedHostNames = failedHostsForTemplate.map(f => f.host).join(', ');
            showStatus(`Template '${rowTemplate.template_name}' created on ${successCount}/${hosts.length} host(s). Failed on: ${failedHostNames}`);
          }
        }
        renderTemplates();
        
        if (successCount > 0) {
          logMsg(`Template '${rowTemplate.template_name}' v${rowTemplate.version} creation completed on ${successCount}/${hosts.length} host(s)`);
        }
        
        // Wait for all running tasks to complete on all hosts before proceeding to next template
        logMsg(`Waiting for all running tasks to complete before proceeding to next template...`);
        await waitForNoRunningTasks(hosts, `After creating ${rowTemplate.template_name}`);
        
        // Update overall progress
        const completedProgress = 20 + ((i + 1) / totalTemplates) * 40;
        updateRunProgress(completedProgress, `Template ${i + 1}/${totalTemplates} created: ${rowTemplate.template_name}`);
      }
      
      updateRunProgress(60, `All workspace templates processed: ${createdCount}/${totalTemplates} created successfully`);
      renderTemplates();
      
      if (createdCount === totalTemplates) {
        showStatus(`Created all ${templatesToCreate.length} workspace template(s) successfully: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      } else {
        showStatus(`Created ${createdCount}/${templatesToCreate.length} workspace template(s) successfully: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      }
    } else {
      // All templates already exist, skip creation
      updateRunProgress(60, 'All workspace templates already exist');
      logMsg('All workspace templates already created, skipping creation phase');
      showStatus('All workspace templates already exist');
    }
    
    // STEP 1: Execute SSH Profiles (if selected) BEFORE Install Workspace
    const sshProfileSelect = el('sshProfileSelect');
    const sshProfileId = sshProfileSelect ? sshProfileSelect.value : '';
    const sshWaitTimeInput = el('sshWaitTime');
    const sshWaitTime = sshWaitTimeInput ? (parseInt(sshWaitTimeInput.value) || 60) : 60;
    
    if (sshProfileId) {
      updateRunProgress(61, 'Executing SSH profiles...');
      showStatus('Executing SSH profiles on all hosts...');
      
      // No encryption password required - uses FS_SERVER_SECRET
      try {
        // Filter out failed hosts before SSH execution
        const availableHostsForSsh = hosts.filter(({host}) => !failedHosts.has(host));
        
        if (availableHostsForSsh.length === 0) {
          showStatus('Skipping SSH profile execution - all hosts failed during template creation.');
          logMsg('Skipping SSH profile execution - all hosts failed during template creation');
        } else {
          if (failedHosts.size > 0) {
            const failedHostNames = Array.from(failedHosts).join(', ');
            logMsg(`Skipping SSH execution on failed hosts: ${failedHostNames}. Executing on ${availableHostsForSsh.length} remaining host(s).`);
          }
          
          // Capture SSH profile metadata for reporting
          const sshProfileOption = sshProfileSelect?.options[sshProfileSelect.selectedIndex];
          let sshProfileNameForRun = sshProfileOption ? sshProfileOption.text : 'N/A';
          let sshCommandsList = [];
          try {
            const sshProfileDetails = await getSshProfileDetailsById(sshProfileId);
            if (sshProfileDetails) {
              if (sshProfileDetails.name) {
                sshProfileNameForRun = sshProfileDetails.name;
              }
              if (typeof sshProfileDetails.commands === 'string') {
                sshCommandsList = sshProfileDetails.commands
                  .split('\n')
                  .map(cmd => cmd.trim())
                  .filter(Boolean);
              }
            }
          } catch (metaError) {
            logMsg(`Warning: Unable to fetch SSH profile details: ${metaError.message || metaError}`);
          }

          executionDetails.ssh_profile_info = {
            profile_id: parseInt(sshProfileId, 10) || null,
            profile_name: sshProfileNameForRun,
            wait_time_seconds: sshWaitTime,
            commands: sshCommandsList
          };

          const sshResults = await executeSshProfiles(availableHostsForSsh, sshProfileId, sshWaitTime);
          const sshSuccessCount = sshResults.filter(r => r.success).length;
          
          if (sshSuccessCount === availableHostsForSsh.length) {
            updateRunProgress(63, 'SSH profiles executed successfully!');
            showStatus(`SSH profiles executed successfully on all ${availableHostsForSsh.length} host(s)`);
          } else {
            updateRunProgress(63, `SSH profiles executed on ${sshSuccessCount}/${availableHostsForSsh.length} host(s)`);
            showStatus(`SSH profiles executed on ${sshSuccessCount}/${availableHostsForSsh.length} host(s)`);
            
            // Report errors but continue with installation
            const errors = sshResults.filter(r => !r.success).map(r => `${r.host}: ${r.error || 'Unknown error'}`);
            if (errors.length > 0) {
              showStatus(`SSH profile errors (continuing with installation):\n${errors.join('\n')}`, { error: true });
              logMsg(`SSH profile errors: ${errors.join('; ')}`);
            }
          }
        }
      } catch (error) {
        logMsg(`SSH profile execution error: ${error.message || error}`);
        showStatus(`Error executing SSH profiles: ${error.message || error}`, { error: true });
        // Continue with installation even if SSH fails
      }
    }
    
    // STEP 2: Install the selected workspace (after SSH profiles execute)
    updateRunProgress(64, 'Preparing to install selected workspace...');
    const opt = el('installSelect').value;
    
    let template_name, version, repo_name;
    if (!opt) {
      // Auto-select first option from dropdown or first created template
      const select = el('installSelect');
      if (select && select.options.length > 0 && select.options[0].value) {
        [template_name, version] = select.options[0].value.split('|||');
      } else {
        const created = templates.filter(t => t.status === 'created' || t.status === 'installed');
        if (created.length === 0) {
          showStatus('No templates available to install. Please create templates first.');
          logMsg('No templates available to install. Skipping installation phase.');
          updateRunProgress(100, 'No templates available to install');
          renderTemplates();
          stopRunTimer();
          return;
        }
        const first = created[0];
        template_name = first.template_name;
        version = first.version;
      }
    } else {
      [template_name, version] = opt.split('|||');
    }
    
    // Get repo_name from rows if needed
    if (!repo_name) {
      document.querySelectorAll('.tpl-row').forEach(row => {
        const selects = row.querySelectorAll('select');
        const repoSelect = selects[0]; // Repo is the first select
        const templateFiltered = row._templateFiltered;
        // Version is the last select (hidden template select is at index 1)
        const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
        const row_template = templateFiltered ? templateFiltered.getValue() : '';
        const row_version = versionSelect?.value || '';
        if (row_template === template_name && row_version === version) {
          repo_name = repoSelect?.value || '';
        }
      });
    }
    
    // Create separate template entry for each host for installation tracking
    const installTargets = [];
    // Filter out hosts that failed during creation
    const availableHosts = hosts.filter(({host}) => !failedHosts.has(host));
    
    if (availableHosts.length === 0) {
      showStatus(`Cannot install workspace: all hosts failed during template creation. Skipping installation.`);
      logMsg(`Skipping installation - all hosts failed during template creation`);
      updateRunProgress(100, 'Installation skipped - all hosts failed');
      renderTemplates();
      stopRunTimer();
      return;
    }
    
    if (failedHosts.size > 0) {
      const failedHostNames = Array.from(failedHosts).join(', ');
      showStatus(`Skipping installation on failed hosts: ${failedHostNames}. Installing on ${availableHosts.length} remaining host(s).`);
      logMsg(`Skipping installation on failed hosts: ${failedHostNames}. Installing on ${availableHosts.length} remaining host(s).`);
    }
    
    availableHosts.forEach(({host}) => {
      let target = templates.find(t => 
        t.template_name === template_name && 
        t.version === version && 
        t.host === host
      );
      if (!target) {
        // Create new entry with explicit host field
        target = { 
          template_name, 
          repo_name: repo_name || '', 
          version, 
          host: host, // Explicitly set host
          status: 'spin', 
          installProgress: 0, 
          hosts: [host] 
        };
        templates.push(target);
      } else {
        target.status = 'spin';
        target.installProgress = 0;
        target.hosts = [host];
        // Ensure host field is set correctly if it was missing or incorrect
        if (!target.host || target.host === 'host' || target.host === 'Host') {
          target.host = host;
        }
      }
      installTargets.push({ target, host });
    });
    renderTemplates();
    
    // STEP 2: Install Workspace (after SSH profiles execute)
    updateRunProgress(65, 'Installing workspace...');
    showStatus(`Installing workspace: ${template_name} v${version}...`);
    logMsg(`Starting workspace installation: ${template_name} v${version}`);
    
    // Check for running tasks before installing workspace
    await waitForNoRunningTasks(hosts, 'Install Workspace');
    
    if (!template_name || !version) {
      showStatus('Error: Template name and version are required');
      logMsg('Error: Missing template_name or version');
      hideRunProgress();
      stopRunTimer();
      return;
    }
    // User is already authenticated via login - proceed
    updateRunProgress(70, `Installing workspace: ${template_name} v${version}`);
    const totalHosts = hosts.length;
    const hostProgressMap = new Map(); // Track individual host progress
    logMsg(`Installing workspace ${template_name} v${version} on ${totalHosts} host(s)`);
    // Install on all hosts in parallel
    const installPromises = installTargets.map(async ({target, host}, hostIdx) => {
      try {
        const installStart = Date.now();
        logMsg(`Sending install request to ${host} for ${template_name} v${version}`);
        
        const res = await api('/runtime/fabric/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fabric_host: host,
            template_name,
            version,
          }),
          timeout: 15 * 60 * 1000, // 15 minutes timeout for installation
        });
        
        if (!res.ok) {
          const errorText = await res.text();
          logMsg(`Install workspace failed on ${host}: HTTP ${res.status} - ${errorText}`);
          hostProgressMap.set(host, 100); // Mark as done (failed)
          target.status = 'err';
          target.installProgress = 0;
          renderTemplates();
          return {host, success: false, error: `Install failed: HTTP ${res.status}`};
        }
        logMsg(`Workspace installation requested successfully on ${host}`);
        
        // Progress tracking with 15 minutes assumption
        const timeoutMs = 15 * 60 * 1000; // 15 minutes
        target.installProgress = 5; // Start with 5% to show immediate feedback
        renderTemplates();
        
        const progressInterval = setInterval(() => {
          const elapsed = Date.now() - installStart;
          const installPct = Math.min(95, Math.max(5, Math.floor((elapsed / timeoutMs) * 100)));
          if (target.installProgress !== installPct) {
            target.installProgress = installPct;
            renderTemplates();
          }
          // Track individual host progress
          hostProgressMap.set(host, installPct);
          // Calculate overall progress based on all hosts
          const totalProgress = Array.from(hostProgressMap.values()).reduce((sum, pct) => sum + pct, 0);
          const avgProgress = totalProgress / totalHosts;
          const overallProgress = 70 + (avgProgress / 100) * 25; // 70-95% range
          updateRunProgress(Math.min(95, overallProgress), `Installing on ${hosts.length} host(s)... (${Math.round(avgProgress)}%)`);
        }, 500); // Update every 500ms for smoother animation
        
        // poll until running tasks are zero
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          const sres = await api('/tasks/status', { params: { fabric_host: host } });
          if (!sres.ok) { clearInterval(progressInterval); break; }
          const sdata = await sres.json();
          const cnt = sdata.running_count ?? 0;
          if (cnt === 0) { clearInterval(progressInterval); break; }
          await new Promise(r => setTimeout(r, 2000));
        }
        clearInterval(progressInterval);
        
        const done = await api('/tasks/status', { params: { fabric_host: host } });
        hostProgressMap.set(host, 100); // Mark as completed
        if (done.ok) {
          const d = await done.json();
          if ((d.running_count ?? 0) === 0) {
            // Check for task errors after tasks complete
            try {
              // Capture timestamp and template name for filtering
              const installStartTime = new Date(installStart).toISOString();
              const errorsRes = await api('/tasks/errors', { 
                params: { 
                  fabric_host: host, 
                  limit: 20,
                  fabric_name: template_name,
                  since_timestamp: installStartTime
                } 
              });
              if (errorsRes.ok) {
                const errorsData = await errorsRes.json();
                if (errorsData.errors && errorsData.errors.length > 0) {
                  const errorMessages = errorsData.errors.map(err => `Task '${err.task_name}': ${err.error}`).join('; ');
                  const errorMsg = `Workspace '${template_name}' v${version} installation completed on ${host} but with errors: ${errorMessages}`;
                  showStatus(errorMsg);
                  target.status = 'err';
                  target.installProgress = 0;
                  renderTemplates();
                  const completedCount = Array.from(hostProgressMap.values()).filter(p => p === 100).length;
                  updateRunProgress(70 + (completedCount / totalHosts) * 25, `Completed on ${completedCount}/${totalHosts} host(s)`);
                  return {host, success: false, error: errorMessages};
                }
              }
            } catch (error) {
              // Continue anyway - this is not critical
            }
            
            logMsg(`Installed successfully on ${host}`);
            target.status = 'installed';
            target.installProgress = 100;
            renderTemplates();
            const completedCount = Array.from(hostProgressMap.values()).filter(p => p === 100).length;
            updateRunProgress(70 + (completedCount / totalHosts) * 25, `Completed on ${completedCount}/${totalHosts} host(s)`);
            return {host, success: true};
          } else {
            logMsg(`Still running or timeout on ${host}`);
            target.status = 'err';
            target.installProgress = 0;
            renderTemplates();
            return {host, success: false, error: 'Timeout'};
          }
        }
        target.status = 'err';
        target.installProgress = 0;
        renderTemplates();
        return {host, success: false, error: 'Status check failed'};
      } catch (error) {
        logMsg(`Error installing on ${host}: ${error.message || error}`);
        hostProgressMap.set(host, 100); // Mark as done (error)
        target.status = 'err';
        target.installProgress = 0;
        renderTemplates();
        return {host, success: false, error: error.message || error};
      }
    });
    const results = await Promise.allSettled(installPromises);
    const settledResults = results.map(r => r.status === 'fulfilled' ? r.value : {host: 'unknown', success: false, error: r.reason?.message || 'Promise rejected'});
    const successCount = settledResults.filter(r => r.success).length;
    // Status is already updated per host in the promise handlers above
    renderTemplates();
    
    if (successCount === hosts.length) {
      updateRunProgress(100, 'Workspace installation completed successfully!');
      showStatus(`Workspace installation completed successfully on all ${hosts.length} host(s)`);
      logMsg(`Workspace ${template_name} v${version} installed successfully on all ${hosts.length} host(s)`);
    } else {
      updateRunProgress(100, `Workspace installation completed on ${successCount}/${hosts.length} host(s)`);
      showStatus(`Workspace installation completed on ${successCount}/${hosts.length} host(s)`);
      logMsg(`Workspace ${template_name} v${version} installed on ${successCount}/${hosts.length} host(s)`);
    }
    renderTemplates(); // Update UI state
    stopRunTimer(); // Stop the timer but keep progress bar visible
  } catch (error) {
    logMsg(`Run operation error: ${error.message || error}`);
    showStatus(`Error: ${error.message || error}`);
    hideRunProgress();
    stopRunTimer();
  } finally {
    // Re-enable button - check if we have options in dropdown or filled rows
    updateInstallSelect(); // This will update button state
    if (runBtn && runBtn.disabled) {
      // Make sure button isn't stuck disabled
      const rows = Array.from(document.querySelectorAll('.tpl-row'));
      const allFilled = rows.length > 0 && rows.every(r => {
        const selects = r.querySelectorAll('select');
        const repoSelect = selects[0]; // Repo is the first select
        const templateFiltered = r._templateFiltered;
        // Version is the last select (hidden template select is at index 1)
        const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
        const repo_name = repoSelect?.value || '';
        const template_name = templateFiltered ? templateFiltered.getValue() : '';
        const version = versionSelect?.value || '';
        return repo_name && template_name && version;
      });
      if (allFilled) {
        runBtn.disabled = false;
      }
    }
  }
}

// Configuration save/retrieve functions
function collectConfiguration() {
  const fabricHostInput = el('fabricHost');
  const nhiSelect = el('nhiCredentialSelect');
  const expertModeInput = el('expertMode');
  const newHostnameInput = el('newHostname');
  const chgPassInput = el('chgPass');
  const installSelectInput = el('installSelect');
  const sshProfileSelectInput = el('sshProfileSelect');
  const sshWaitTimeInput = el('sshWaitTime');
  const runWorkspaceEnabledInput = el('runWorkspaceEnabled');
  
  // Ensure confirmedHosts is an array to avoid errors
  const hostsArray = Array.isArray(confirmedHosts) ? confirmedHosts : [];
  
  let config = {
    fabricHost: fabricHostInput ? fabricHostInput.value : '',
    nhiCredentialId: nhiSelect ? (nhiSelect.value || '') : '',
    // Note: We don't save decrypted credentials or encryption password for security reasons
    // NHI credentials are automatically loaded when configuration is restored (no password needed)
    expertMode: expertModeInput ? expertModeInput.checked : false,
    newHostname: newHostnameInput ? newHostnameInput.value : '',
    chgPass: chgPassInput ? chgPassInput.value : '',
    confirmedHosts: hostsArray.map(h => ({ host: h.host, port: h.port })),
    installSelect: installSelectInput ? installSelectInput.value : '',
    runWorkspaceEnabled: runWorkspaceEnabledInput ? runWorkspaceEnabledInput.checked : true,
    sshProfileId: sshProfileSelectInput ? (sshProfileSelectInput.value || '') : '',
    sshWaitTime: sshWaitTimeInput ? (parseInt(sshWaitTimeInput.value) || 60) : 60,
    templates: []
  };
  
  // Collect all template rows (only include rows with all values filled)
  document.querySelectorAll('.tpl-row').forEach(row => {
    const selects = row.querySelectorAll('select');
    const repoSelect = selects[0]; // Repo is the first select
    const templateFiltered = row._templateFiltered;
    // Version is the last select (hidden template select is at index 1)
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    if (repoSelect && templateFiltered && versionSelect) {
      const repo_name = repoSelect.value || '';
      const template_name = templateFiltered ? templateFiltered.getValue() : '';
      const version = versionSelect.value || '';
      // Only add template if all three values are filled
      if (repo_name && template_name && version) {
        config.templates.push({ repo_name, template_name, version });
      }
    }
  });
  
  return config;
}

async function restoreConfiguration(config) {
  // Set flag to prevent button from being enabled during restore
  isRestoringConfiguration = true;
  const runBtn = el('btnInstallSelected');
  
  // Clear actionStatus when restoring configuration
  const actionStatus = el('actionStatus');
  if (actionStatus) {
    actionStatus.style.display = 'none';
    const messageEl = el('actionStatusMessage');
    if (messageEl) messageEl.innerHTML = '';
    const progressSection = el('actionStatusProgress');
    if (progressSection) progressSection.style.display = 'none';
  }
  
  try {
    
    // Ensure preparation section is loaded - wait for elements to exist (reduced timeout)
    let attempts = 0;
    while (attempts < 15 && !el('fabricHost')) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    
    if (!el('fabricHost')) {
      showStatus('Error: Preparation section not loaded. Please try again.');
      return;
    }
    
    // IMPORTANT: Disable Run button immediately when loading configuration
    // It will be enabled when hosts are available and tokens are acquired
    if (runBtn) {
      runBtn.disabled = true;
    }
    
    // Reset state to ensure fresh start
    currentNhiId = null;
    confirmedHosts = []; // Clear confirmed hosts
    validatedHosts = [];
    // Clear templates array to ensure fresh state - templates will be re-added when run starts
    templates = [];
    
    // Restore basic fields - always safe, no API calls
    const fabricHostInput = el('fabricHost');
    if (fabricHostInput && config.fabricHost !== undefined) {
      fabricHostInput.value = config.fabricHost || '';
    }
    
    const expertModeInput = el('expertMode');
    if (expertModeInput && config.expertMode !== undefined) {
      expertModeInput.checked = config.expertMode || false;
    }
    
    // Restore NHI credential selection if available, and auto-load automatically (no password needed)
    if (config.nhiCredentialId) {
      const nhiSelect = el('nhiCredentialSelect');
      if (nhiSelect) {
        // Load credentials if not already loaded (may have been loaded by initializePreparationSection)
        if (!_nhiCredentialsCache) {
          await loadNhiCredentialsForAuth();
        } else {
          // Just populate dropdown with cached data
          populateNhiCredentialsDropdown(nhiSelect, _nhiCredentialsCache);
        }
        nhiSelect.value = String(config.nhiCredentialId);
        
        // Automatically load the credential (no password required)
        try {
          await loadSelectedNhiCredential();
          
          // Wait for credential to load and hosts to be populated (reduced from 300ms)
          await new Promise(resolve => setTimeout(resolve, 100));
          
          // Populate hosts from NHI credential (auto-confirmed)
          if (window.validatedNhiHosts && window.validatedNhiHosts.length > 0) {
            // Populate validated hosts from NHI credential (but don't set confirmedHosts yet)
            validatedHosts = [...window.validatedNhiHosts];
            
            // Update manual input to match
            const fabricHostInput = el('fabricHost');
            if (fabricHostInput) {
              const validatedHostsStr = validatedHosts.map(({host, port}) => 
                host + (port !== undefined ? ':' + port : '')
              ).join(' ');
              fabricHostInput.value = validatedHostsStr;
              renderHostChips();
              updateValidationStatus();
              fabricHostInput.readOnly = true;
              fabricHostInput.disabled = false;
              fabricHostInput.style.backgroundColor = '#f5f5f7';
              fabricHostInput.style.cursor = 'not-allowed';
            }
            
            // Make NHI credential input readonly
            const fabricHostFromNhiInput = el('fabricHostFromNhi');
            if (fabricHostFromNhiInput) {
              const nhiHostsStr = window.validatedNhiHosts.map(({host, port}) => 
                host + (port !== undefined ? ':' + port : '')
              ).join(' ');
              fabricHostFromNhiInput.value = nhiHostsStr;
              fabricHostFromNhiInput.readOnly = true;
              fabricHostFromNhiInput.disabled = false;
              fabricHostFromNhiInput.style.backgroundColor = '#f5f5f7';
              fabricHostFromNhiInput.style.cursor = 'not-allowed';
            }
            
            // Auto-confirm hosts and acquire tokens
            if (autoConfirmHosts()) {
              // Render host list (but don't show hostsListRow)
              await renderFabricHostList();
              
              // Automatically acquire tokens
              if (await acquireTokens()) {
                // Enable Add Row button
                const addRowBtn = el('btnAddRow');
                if (addRowBtn) addRowBtn.disabled = false;
                showStatus('Configuration loaded. Hosts confirmed and tokens acquired.', { hideAfterMs: 2000 });
                updateCreateEnabled();
              } else {
                showStatus('Configuration loaded but token acquisition failed. Please check credentials.');
              }
            } else {
              await renderFabricHostList();
            }
          } else if (config.confirmedHosts && config.confirmedHosts.length > 0) {
            // Fallback: Use confirmed hosts from configuration if NHI credential doesn't have hosts
            validatedHosts = config.confirmedHosts.map(h => ({ 
              host: h.host, 
              port: h.port, 
              isValid: true 
            }));
            await renderFabricHostList();
            renderHostChips();
            const fabricHostInput = el('fabricHost');
            if (fabricHostInput) {
              const hostString = validatedHosts.map(({host, port}) => 
                host + (port !== undefined ? ':' + port : '')
              ).join(' ');
              fabricHostInput.value = hostString;
            }
            
            // Auto-confirm hosts and acquire tokens
            if (autoConfirmHosts()) {
              if (await acquireTokens()) {
                const addRowBtn = el('btnAddRow');
                if (addRowBtn) addRowBtn.disabled = false;
                showStatus('Configuration loaded. Hosts confirmed and tokens acquired.', { hideAfterMs: 2000 });
                updateCreateEnabled();
              } else {
                showStatus('Configuration loaded but token acquisition failed. Please check credentials.');
              }
            } else {
            }
          } else {
            showStatus('NHI credential loaded. No hosts in credential.');
          }
        } catch (e) {
          showStatus('Error loading NHI credential for configuration');
          logMsg(`Error loading NHI credential: ${e.message || e}`);
          // Keep Run button disabled on error
          if (runBtn) runBtn.disabled = true;
        }
      }
    } else {
      // No NHI credential in config - keep Run button disabled
      if (runBtn) runBtn.disabled = true;
    }
    const newHostnameInput = el('newHostname');
    if (newHostnameInput && config.newHostname !== undefined) {
      newHostnameInput.value = config.newHostname || '';
    }
    
    const chgPassInput = el('chgPass');
    if (chgPassInput && config.chgPass !== undefined) {
      chgPassInput.value = config.chgPass || '';
    }
    
    // Restore SSH profile selection
    const sshProfileSelect = el('sshProfileSelect');
    if (sshProfileSelect && config.sshProfileId !== undefined) {
      // Load profiles if not already loaded (may have been loaded by initializePreparationSection)
      if (!_sshProfilesCache) {
        await loadSshProfilesForPreparation();
      } else {
        // Just populate dropdown with cached data
        populateSshProfilesDropdown(sshProfileSelect, _sshProfilesCache);
      }
      sshProfileSelect.value = config.sshProfileId || '';
    }
    
    // Restore SSH wait time
    const sshWaitTimeInput = el('sshWaitTime');
    if (sshWaitTimeInput && config.sshWaitTime !== undefined) {
      sshWaitTimeInput.value = config.sshWaitTime || 60;
    }
    
    // Update expert mode visibility
    const out = el('out');
    if (out) {
      out.style.display = el('expertMode').checked ? 'block' : 'none';
    }
    
    // Restore hosts to validatedHosts and auto-confirm if not already done during NHI credential loading
    // This handles cases where NHI credential wasn't loaded or doesn't have hosts
    try {
      if ((!currentNhiId || validatedHosts.length === 0) && config.confirmedHosts && config.confirmedHosts.length > 0) {
        // Restore hosts to validatedHosts
        validatedHosts = config.confirmedHosts.map(h => ({ 
          host: h.host, 
          port: h.port, 
          isValid: true 
        }));
        await renderFabricHostList();
        renderHostChips();
        const fabricHostInput = el('fabricHost');
        if (fabricHostInput) {
          const hostString = validatedHosts.map(({host, port}) => 
            host + (port !== undefined ? ':' + port : '')
          ).join(' ');
          fabricHostInput.value = hostString;
        }
        
        // Auto-confirm hosts and acquire tokens
        if (autoConfirmHosts()) {
          if (await acquireTokens()) {
            const addRowBtn = el('btnAddRow');
            if (addRowBtn) addRowBtn.disabled = false;
            updateCreateEnabled();
          }
        }
      } else if (config.fabricHost && fabricHostInput) {
        const hosts = parseFabricHosts();
        validatedHosts = hosts.map(h => ({ host: h.host, port: h.port, isValid: true }));
        await renderFabricHostList();
        renderHostChips();
        
        // Auto-confirm hosts and acquire tokens
        if (autoConfirmHosts()) {
          if (await acquireTokens()) {
            const addRowBtn = el('btnAddRow');
            if (addRowBtn) addRowBtn.disabled = false;
            updateCreateEnabled();
          }
        }
      }
    } catch (err) {
      logMsg(`Warning: Error restoring hosts: ${err.message || err}`);
    }
    
    // NHI credentials are automatically loaded when configuration is restored (no password needed)
    
    // Clear existing template rows
    const container = el('tplFormList');
    if (container) container.innerHTML = '';
    
    // Helper function to set dropdown values with proper waiting
    async function setDropdownValue(select, value, waitMs = 0) {
      if (!select || !value) return false;
      try {
        await new Promise(resolve => setTimeout(resolve, waitMs));
        
        // Wait for options to be available (but don't wait forever)
        let attempts = 0;
        while (select.options.length <= 1 && attempts < 20) {
          await new Promise(resolve => setTimeout(resolve, 100));
          attempts++;
        }
        
        const option = Array.from(select.options).find(opt => opt.value === value);
        if (option) {
          select.value = value;
          select.dispatchEvent(new Event('change'));
          return true;
        }
      } catch (err) {
        logMsg(`Warning: Error setting dropdown value: ${err.message || err}`);
      }
      return false;
    }
    
    // Load cached templates first to use for restoration if API is not available
    let cachedTemplates = [];
    try {
      const cacheData = await apiJson('/cache/templates');
      cachedTemplates = cacheData.templates || [];
      // Store globally so event handlers can use it to avoid API calls
      window.cachedTemplates = cachedTemplates;
    } catch (error) {
    }
    // Restore template rows sequentially - use cached templates if API not available
    if (config.templates && config.templates.length > 0) {
      
      // First, try to populate repositories from cache or API
      const host = getFabricHostPrimary();
      let availableRepos = [];
      
      if (cachedTemplates.length > 0) {
        // Get unique repos from cache
        availableRepos = Array.from(new Set(cachedTemplates.map(t => t.repo_name).filter(Boolean))).sort();
      } else if (host) {
        // Try to load from API - cookies sent automatically
        // No need to pre-check session; API will return 401 if no session, which we handle gracefully
        try {
          const reposRes = await api('/repo/remotes', { params: { fabric_host: host } });
          if (reposRes.ok) {
            const reposData = await reposRes.json();
            availableRepos = (reposData.repositories || []).map(r => r.name).filter(Boolean);
          }
          // If 401, we just continue without repos (silent failure is fine during config restore)
        } catch (err) {
          // Silent failure - we'll use cached templates or empty repos
        }
      }
      
      for (let i = 0; i < config.templates.length; i++) {
        try {
          const {repo_name, template_name, version} = config.templates[i];
          
          // Check if repo_name and template_name are valid (non-empty strings)
          // Version can be empty, but if it is, we'll try to restore anyway and let the user select a version
          if (!repo_name || !template_name || (typeof repo_name !== 'string') || (typeof template_name !== 'string')) {
            continue;
          }
          
          // Trim strings to handle whitespace-only values
          const trimmedRepo = repo_name.trim();
          const trimmedTemplate = template_name.trim();
          const trimmedVersion = (version && typeof version === 'string') ? version.trim() : '';
          
          if (!trimmedRepo || !trimmedTemplate) {
            continue;
          }
          
          // Use trimmed values
          const finalRepo = trimmedRepo;
          const finalTemplate = trimmedTemplate;
          const finalVersion = trimmedVersion;
          
            // Add the row first
          try {
            addTplRow({ repo_name: finalRepo, template_name: finalTemplate, version: finalVersion });
            
            // Get the row we just added (reduced from 200ms)
            await new Promise(resolve => setTimeout(resolve, 50));
            const rows = document.querySelectorAll('.tpl-row');
            if (rows.length === 0) {
              continue;
            }
            
            const currentRow = rows[rows.length - 1];
            const selects = currentRow.querySelectorAll('select');
            const r = selects[0]; // Repo is the first select
            const templateFiltered = currentRow._templateFiltered;
            const v = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
            
            if (!r || !templateFiltered || !v) {
              continue;
            }
            
            // If using cached templates, populate dropdowns from cache
            if (cachedTemplates.length > 0 && availableRepos.length > 0) {
              // Populate repo dropdown with cached repos immediately
              if (r.options.length <= 1) {
                availableRepos.forEach(repoName => {
                  const opt = document.createElement('option');
                  opt.value = repoName;
                  opt.textContent = repoName;
                  r.appendChild(opt);
                });
                r.disabled = false;
              }
              
              // Set repo value WITHOUT triggering change event to avoid API calls
              if (availableRepos.includes(finalRepo)) {
                // Temporarily remove event listeners to prevent API calls
                const originalValue = r.value;
                r.value = finalRepo;
                
                // Ensure repo value persists - add a flag to prevent clearing
                r._restoredFromCache = true;
                
                // Populate templates for this repo from cache directly (removed unnecessary wait)
                const templatesForRepo = cachedTemplates.filter(t => t.repo_name === finalRepo);
                const uniqueNames = Array.from(new Set(templatesForRepo.map(t => t.template_name).filter(Boolean))).sort();
                const templateOptions = uniqueNames.map(name => {
                  const o = document.createElement('option');
                  o.value = name;
                  o.textContent = name;
                  return o;
                });
                templateFiltered.populateOptions(templateOptions);
                templateFiltered.enable();
                
                // Verify repo value is still set after populateOptions
                if (r.value !== finalRepo) {
                  r.value = finalRepo;
                }
                
                // Set template value (removed unnecessary wait)
                if (uniqueNames.includes(finalTemplate)) {
                  
                  // Set template value WITHOUT triggering change events that would try to load from API
                  // We're using cache, so we'll populate versions directly from cache
                  templateFiltered.input.value = finalTemplate;
                  if (templateFiltered.select) {
                    templateFiltered.select.value = finalTemplate;
                  }
                  // Update datalist to show the value
                  if (templateFiltered.datalist) {
                    templateFiltered.updateDatalist();
                  }
                  
                  // Verify repo value is still set after setting template
                  if (r.value !== finalRepo) {
                    r.value = finalRepo;
                  }
                  
                  // Populate versions for this repo+template from cache
                  await new Promise(resolve => setTimeout(resolve, 100));
                  
                  // Get all matching templates from cache
                  const matchingTemplates = cachedTemplates.filter(t => 
                    t.repo_name === finalRepo && 
                    t.template_name === finalTemplate && 
                    t.version && 
                    t.version.trim() !== ''
                  );
                  
                  
                  const versions = Array.from(new Set(matchingTemplates.map(t => t.version.trim())))
                    .filter(Boolean)
                    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
                  
                  
                  // Clear and populate version dropdown
                  v.innerHTML = '';
                  const optVerPh = document.createElement('option');
                  optVerPh.value = '';
                  optVerPh.textContent = 'Select version';
                  v.appendChild(optVerPh);
                  
                  if (versions.length > 0) {
                    versions.forEach(ver => {
                      const o = document.createElement('option');
                      o.value = ver;
                      o.textContent = ver;
                      v.appendChild(o);
                    });
                    v.disabled = false;
                  } else {
                    v.disabled = true;
                  }
                  
                  // Set version value (don't dispatch change event to avoid triggering updateInstallSelect too early)
                  // Always select a version if available, even if not specified in config
                  if (versions.length > 0) {
                    if (finalVersion && versions.includes(finalVersion)) {
                      await new Promise(resolve => setTimeout(resolve, 100));
                      v.value = finalVersion;
                    } else if (finalVersion) {
                      // Select first version if available
                      if (v.options.length > 1) {
                        v.value = v.options[1].value;
                      }
                    } else {
                      // No version specified in config - select first available
                      if (v.options.length > 1) {
                        v.value = v.options[1].value;
                      }
                    }
                    
                    // Double-check version is set
                    if (!v.value && v.options.length > 1) {
                      v.value = v.options[1].value;
                    }
                    
                    // Store that we've set the version to prevent it from being cleared
                    v._versionSetFromCache = true;
                    
                  } else {
                  }
                  
                  // Final verification: ensure repo value is still set
                  await new Promise(resolve => setTimeout(resolve, 100));
                  if (r.value !== finalRepo) {
                    r.value = finalRepo;
                  }
                } else {
                }
              } else {
              }
              
            } else {
              // Fallback to API-based loading if no cache
              // Load repositories if needed
              if (r._loadRepositories) {
                try {
                  if (host) {
                    const loaded = await r._loadRepositories();
                    if (loaded) {
                      // Wait for repos to populate
                      let repoAttempts = 0;
                      while (r.options.length <= 1 && repoAttempts < 30) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                        repoAttempts++;
                      }
                    }
                  }
                } catch (err) {
                }
              }
              
              // Fallback: Set repo value and let event handlers populate templates/versions (may trigger API calls)
              // Only do this if we have tokens available
              if (finalRepo && host) {
                const repoOpt = Array.from(r.options).find(opt => opt.value === finalRepo);
                if (repoOpt) {
                  r.value = finalRepo;
                  r.dispatchEvent(new Event('change'));
                  await new Promise(resolve => setTimeout(resolve, 1000));
                }
              } else if (finalRepo) {
                // No token - skip API calls, just log warning
              }
              
              // Set template value if not already set from cache path above
              if (finalTemplate && templateFiltered) {
                const currentTemplate = templateFiltered.getValue();
                if (currentTemplate !== finalTemplate) {
                  await new Promise(resolve => setTimeout(resolve, 300));
                  templateFiltered.setValue(finalTemplate);
                  // Only dispatch change if we're using API path (have token)
                  if (host) {
                    templateFiltered.select.dispatchEvent(new Event('change'));
                    await new Promise(resolve => setTimeout(resolve, 1000));
                  }
                }
              }
              
              // Set version value if it exists
              if (finalVersion) {
                await new Promise(resolve => setTimeout(resolve, 300));
                const versionOpt = Array.from(v.options).find(opt => opt.value === finalVersion);
                if (versionOpt) {
                  v.value = finalVersion;
                  if (host) {
                    v.dispatchEvent(new Event('change'));
                  }
                } else {
                  // Select first version if available
                  if (v.options.length > 1) {
                    v.value = v.options[1].value;
                  }
                }
              } else if (v.options.length > 1) {
                // No version specified - select first available version
                v.value = v.options[1].value;
              }
            }
            
            // Verify final values and ensure version is set
            await new Promise(resolve => setTimeout(resolve, 300));
            
            // Double-check version is set - if not, try to set it again
            if (!v.value && v.options.length > 1) {
              v.value = v.options[1].value;
            }
            
            // Ensure repo value is still set before moving to next row
            if (r.value !== finalRepo && finalRepo) {
              r.value = finalRepo;
            }
            
            // Wait before adding next row
            await new Promise(resolve => setTimeout(resolve, 300));
          } catch (err) {
            logMsg(`Warning: Error adding template row ${i + 1}: ${err.message || err}`);
            continue;
          }
        } catch (err) {
          logMsg(`Warning: Error restoring template row ${i + 1}: ${err.message || err}`);
        }
      }
      
      
      // Shorter wait before updating install select - we've already set all values from cache
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Verify all rows were restored correctly and ensure versions are set
      const finalRows = document.querySelectorAll('.tpl-row');
      
      finalRows.forEach((row, idx) => {
        const selects = row.querySelectorAll('select');
        const repoSelect = selects[0];
        const templateFiltered = row._templateFiltered;
        const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
        if (repoSelect && templateFiltered && versionSelect) {
          const repo = repoSelect.value || '';
          const template = templateFiltered ? templateFiltered.getValue() : '';
          let version = versionSelect.value || '';
          
          // If version is empty but options exist, set it immediately
          if (!version && versionSelect.options.length > 1) {
            version = versionSelect.options[1].value;
            versionSelect.value = version;
          }
          
          // Try to populate versions from cache if still empty
          if (!version && repo && template && cachedTemplates.length > 0) {
            const versions = cachedTemplates
              .filter(t => t.repo_name === repo && t.template_name === template && t.version)
              .map(t => t.version)
              .filter(Boolean);
            
            if (versions.length > 0) {
              versionSelect.innerHTML = '';
              versions.forEach(ver => {
                const opt = document.createElement('option');
                opt.value = ver;
                opt.textContent = ver;
                versionSelect.appendChild(opt);
              });
              versionSelect.value = versions[0];
            }
          }
        }
      });
      
      // Minimal wait - values are already set from cache
      await new Promise(resolve => setTimeout(resolve, 100));
      
    } else {
    }
    
    // Update install select dropdown with restored templates
    try {
      
      // Call updateInstallSelect to populate dropdown immediately
      updateInstallSelect();
      
      // Wait briefly for dropdown to populate (values are already set from cache)
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Restore install select value immediately after dropdown is populated
      const select = el('installSelect');
      if (select && select.options.length > 0) {
        if (config.installSelect) {
          const option = Array.from(select.options).find(opt => opt.value === config.installSelect);
          if (option) {
            select.value = config.installSelect;
          } else {
            // Set to first option if available
            if (select.options.length > 0) {
              select.value = select.options[0].value;
            }
          }
        } else if (select.options.length > 0) {
          // No stored value - select first option
          select.value = select.options[0].value;
        }
      } else {
        // If dropdown not ready, wait briefly and try once more
        await new Promise(resolve => setTimeout(resolve, 100));
        updateInstallSelect();
        if (config.installSelect && select && select.options.length > 0) {
          const option = Array.from(select.options).find(opt => opt.value === config.installSelect);
          if (option) {
            select.value = config.installSelect;
          }
        }
      }
    } catch (err) {
      logMsg(`Warning: Error updating install select: ${err.message || err}`);
    }
    
    // Auto-confirm hosts when configuration is loaded
    // Keep bypassGatingConditions = false so run button requires both conditions
    
    // Enable Add Row button (allowed even before hosts are confirmed when loading config)
    const btnAddRow = el('btnAddRow');
    if (btnAddRow) {
      btnAddRow.disabled = false;
    }
    
    // Enable Install Select dropdown (normally disabled initially)
    const installSelect = el('installSelect');
    if (installSelect) {
      installSelect.disabled = false;
    }
    
    // Restore Run Workspace toggle - default to true if not specified
    const runWorkspaceEnabledInput = el('runWorkspaceEnabled');
    if (runWorkspaceEnabledInput) {
      runWorkspaceEnabledInput.checked = config.runWorkspaceEnabled !== false; // Default to true if not specified or false
    }
    // Clear the restoring flag - restore is complete
    isRestoringConfiguration = false;
    
    // Call updateCreateEnabled to ensure button state is correct
    // This will enable the run button if hosts are confirmed and tokens are acquired
    updateCreateEnabled();
  } catch (error) {
    // Clear the restoring flag even on error
    isRestoringConfiguration = false;
    
    // Catch any unexpected errors
    logMsg(`Error during restore: ${error.message || error}`);
    showStatus('Configuration partially restored - some errors occurred');
    
    // Enable Add Row button even if restore had errors
    const btnAddRow = el('btnAddRow');
    if (btnAddRow) btnAddRow.disabled = false;
    
    // Disable Run button on error
    const runBtnError = el('btnInstallSelected');
    if (runBtnError) {
      runBtnError.disabled = true;
    }
    
    // Call updateCreateEnabled to ensure button state is correct
    // This will keep the run button disabled until both NHI credentials are loaded and hosts are confirmed
    updateCreateEnabled();
  }
}


// Initialize run view handlers
function initializeRunView() {
  // Initialize preparation section logic for run view (uses same element IDs)
  if (typeof initializePreparationSection === 'function') {
    initializePreparationSection();
  }
  
  // Ensure the Run button handler is attached (initializePreparationSection should do this, but ensure it)
  if (typeof attachRunButtonHandler === 'function') {
    attachRunButtonHandler();
  }
  
  // The Run button is btnInstallSelected (same as preparation section)
  // It's already set up by initializePreparationSection and attachRunButtonHandler
  // We just need to ensure the configuration is restored
  
  // Set up Cancel button
  const cancelBtn = el('btnCancelConfig');
  if (cancelBtn) {
    cancelBtn.onclick = () => {
      showConfigsListView();
    };
  }
}

// Refresh configurations button - set up when section loads
function setupConfigButtons() {
  // New Configuration button
  const newConfigBtn = el('btnNewConfig');
  if (newConfigBtn) {
    newConfigBtn.onclick = () => {
      showNewConfigView();
    };
  }
  
  // Back to List buttons
  const backToListBtn = el('btnBackToList');
  if (backToListBtn) {
    backToListBtn.onclick = () => {
      showConfigsListView();
    };
  }
  
  const backFromRunBtn = el('btnBackFromRun');
  if (backFromRunBtn) {
    backFromRunBtn.onclick = () => {
      showConfigsListView();
    };
  }
  
  const refreshBtn = el('btnRefreshConfigs');
  if (refreshBtn) {
    refreshBtn.onclick = () => {
      loadConfigurations();
    };
  }
  
  // Edit form buttons
  const saveEditBtn = el('btnSaveEditConfig');
  if (saveEditBtn) {
    saveEditBtn.onclick = handleSaveEditConfig;
  }
  
  const cancelEditBtn = el('btnCancelEditConfig');
  if (cancelEditBtn) {
    cancelEditBtn.onclick = cancelEditConfig;
  }
  
  // Add Row button for edit form
  const addEditRowBtn = el('btnAddEditRow');
  if (addEditRowBtn) {
    addEditRowBtn.onclick = (e) => {
      e.preventDefault();
      addEditTplRow();
      updateEditInstallSelectFromRows();
    };
  }
  
  const deleteBtn = el('btnDeleteConfig');
  if (deleteBtn && !deleteBtn.onclick) {
    deleteBtn.onclick = async () => {
      const selected = document.querySelectorAll('.config-checkbox:checked');
      if (selected.length === 0) {
        showStatus('Please select at least one configuration to delete');
        return;
      }
      
      const configIds = Array.from(selected).map(cb => parseInt(cb.value));
      const count = configIds.length;
      const confirmMsg = `Are you sure you want to delete ${count} configuration(s)?`;
      
      if (confirm(confirmMsg)) {
        showStatus(`Deleting ${count} configuration(s)...`);
        let successCount = 0;
        let failCount = 0;
        
        for (const configId of configIds) {
          try {
            const res = await api(`/config/delete/${configId}`, { method: 'DELETE' });
            if (res.ok) {
              successCount++;
            } else if (res.status === 404) {
              // Configuration doesn't exist - treat as success (already deleted)
              successCount++;
            } else {
              failCount++;
            }
          } catch (error) {
            failCount++;
          }
        }
        
        if (successCount > 0) {
          showStatus(`Deleted ${successCount} configuration(s)${failCount > 0 ? `, ${failCount} failed` : ''}`);
          logMsg(`Deleted ${successCount} configuration(s)`);
          
          // Clear API cache for config list to ensure fresh data
          const cacheKey = '/config/list?';
          if (_requestCache.has(cacheKey)) {
            _requestCache.delete(cacheKey);
          }
          
          // Reload configurations list
          loadConfigurations();
        } else {
          showStatus(`Failed to delete ${failCount} configuration(s)`);
        }
      }
    };
  }
}

// Delete button is set up in setupConfigButtons() function above

async function editEvent(eventId) {
  try {
    showStatus(`Loading event for editing...`);
    const getRes = await api(`/event/get/${eventId}`);
    if (!getRes.ok) {
      showStatus('Failed to retrieve event');
      return;
    }
    
    const eventData = await getRes.json();
    if (!eventData) {
      showStatus('Invalid event data received');
      return;
    }
    
    // Set edit mode
    editingEventId = eventId;
    
    // Populate form with event data - convert UTC to local time for display/editing
    const localEvent = utcToLocal(eventData.event_date, eventData.event_time);
    el('eventName').value = eventData.name || '';
    el('eventDate').value = localEvent.date || '';
    el('eventTime').value = localEvent.time || '';
    el('eventAutoRun').checked = eventData.auto_run || false;
    
    // Load configurations and set selected one
    await loadEventConfigs();
    setTimeout(() => {
      el('eventConfigSelect').value = eventData.configuration_id || '';
      updateCreateEventButton();
    }, 100);
    
    // Switch buttons - show Update, hide Create
    el('btnCreateEvent').style.display = 'none';
    el('btnUpdateEvent').style.display = 'inline-block';
    el('btnCancelEvent').style.display = 'inline-block';
    el('btnUpdateEvent').disabled = false;
    
    // Scroll to form
    document.querySelector('#event-schedule-section h3').scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    showStatus(`Event '${eventData.name}' loaded for editing. Click Update to save changes.`);
    logMsg(`Event loaded for editing: ${eventData.name} (ID: ${eventId})`);
  } catch (error) {
    showStatus(`Error loading event for editing: ${error.message || error}`);
    logMsg(`Error loading event for editing: ${error.message || error}`);
  }
}

function cancelEventEdit() {
  editingEventId = null;
  el('eventName').value = '';
  el('eventDate').value = '';
  el('eventTime').value = '';
  el('eventConfigSelect').value = '';
  el('eventAutoRun').checked = false;
  
  el('btnCreateEvent').style.display = 'inline-block';
  el('btnUpdateEvent').style.display = 'none';
  el('btnCancelEvent').style.display = 'none';
  
  updateCreateEventButton();
}
// Set up event schedule button handlers
function setupEventButtons() {
  const createBtn = el('btnCreateEvent');
  if (createBtn && !createBtn.onclick) {
    createBtn.onclick = async () => {
      const name = el('eventName').value.trim();
  const date = el('eventDate').value;
  const time = el('eventTime').value;
  const configSelectValue = el('eventConfigSelect').value;
  const configId = configSelectValue ? parseInt(configSelectValue, 10) : 0;
  const autoRun = el('eventAutoRun').checked;
  
  if (!name) {
    showStatus('Event name is required');
    return;
  }
  
  if (!date) {
    showStatus('Event date is required');
    return;
  }
  
  if (!configId || isNaN(configId)) {
    showStatus('Please select a configuration');
    return;
  }
  
  // Validate that date/time is not in the past (using local time)
  const timePart = time ? time + ':00' : '00:00';
  let eventDateTime, now;
  if (typeof dayjs !== 'undefined') {
    eventDateTime = dayjs(`${date}T${timePart}`);
    now = dayjs();
  } else {
    eventDateTime = new Date(date + (time ? 'T' + time : 'T00:00:00'));
    now = new Date();
  }
  
  const isValid = typeof dayjs !== 'undefined' 
    ? eventDateTime.isValid() && !eventDateTime.isBefore(now)
    : !isNaN(eventDateTime.getTime()) && eventDateTime >= now;
  
  if (!isValid) {
    showStatus('Event date and time cannot be in the past', { error: true });
    updateCreateEventButton(); // Update to show error messages
    return;
  }
  
  // Convert local date/time to UTC before sending to backend
  const utcEvent = localToUTC(date, time);
  
  try {
    // No password needed - credentials are encrypted with FS_SERVER_SECRET
    const res = await api('/event/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        event_date: utcEvent.date,
        event_time: utcEvent.time || null,
        configuration_id: configId,
        auto_run: autoRun,
        nhi_password: null  // No longer needed - using FS_SERVER_SECRET
      })
    });
    
    if (!res.ok) {
      const errorText = await res.text();
      const errorMessage = errorText || `Failed to create event: ${res.status} ${res.statusText}`;
      showStatus(`Failed to create event: ${errorMessage}`);
      return;
    }
    
    const data = await res.json();
    showStatus(data.message || 'Event created successfully');
    logMsg(`Event created: ${name}${autoRun ? ' (Auto Run enabled)' : ''}`);
    
    // Clear form
    cancelEventEdit();
    
    // Reload events list
    loadEvents();
  } catch (error) {
    showStatus(`Error creating event: ${error.message || error}`);
    logMsg(`Error creating event: ${error.message || error}`);
  }
    };
  }
  
  const updateBtn = el('btnUpdateEvent');
  if (updateBtn && !updateBtn.onclick) {
    updateBtn.onclick = async () => {
      const name = el('eventName').value.trim();
      const date = el('eventDate').value;
      const time = el('eventTime').value;
      const configSelectValue = el('eventConfigSelect').value;
      const configId = configSelectValue ? parseInt(configSelectValue, 10) : 0;
      const autoRun = el('eventAutoRun').checked;
      
      if (!editingEventId) {
        showStatus('No event selected for editing');
        return;
      }
      
      if (!name) {
        showStatus('Event name is required');
        return;
      }
      
      if (!date) {
        showStatus('Event date is required');
        return;
      }
      
      if (!configId || isNaN(configId)) {
        showStatus('Please select a configuration');
        return;
      }
      
      // Validate that date/time is not in the past (using local time)
      const timePart = time ? time + ':00' : '00:00';
      let eventDateTime, now;
      if (typeof dayjs !== 'undefined') {
        eventDateTime = dayjs(`${date}T${timePart}`);
        now = dayjs();
      } else {
        eventDateTime = new Date(date + (time ? 'T' + time : 'T00:00:00'));
        now = new Date();
      }
      
      const isValid = typeof dayjs !== 'undefined' 
        ? eventDateTime.isValid() && !eventDateTime.isBefore(now)
        : !isNaN(eventDateTime.getTime()) && eventDateTime >= now;
      
      if (!isValid) {
        showStatus('Event date and time cannot be in the past', { error: true });
        updateCreateEventButton(); // Update to show error messages
        return;
      }
      
      // Convert local date/time to UTC before sending to backend
      const utcEvent = localToUTC(date, time);
      
      try {
        // No password needed - credentials are encrypted with FS_SERVER_SECRET
        const res = await api('/event/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: editingEventId,
            name: name,
            event_date: utcEvent.date,
            event_time: utcEvent.time || null,
            configuration_id: configId,
            auto_run: autoRun,
            nhi_password: null  // No longer needed - using FS_SERVER_SECRET
          })
        });
        
        if (!res.ok) {
          const errorText = await res.text();
          const errorMessage = errorText || `Failed to update event: ${res.status} ${res.statusText}`;
          showStatus(`Failed to update event: ${errorMessage}`);
          return;
        }
        
        const data = await res.json();
        showStatus(data.message || 'Event updated successfully');
        logMsg(`Event updated: ${name}${autoRun ? ' (Auto Run enabled)' : ''}`);
        
        // Clear form and exit edit mode
        cancelEventEdit();
        
        // Reload events list
        loadEvents();
      } catch (error) {
        showStatus(`Error updating event: ${error.message || error}`);
        logMsg(`Error updating event: ${error.message || error}`);
      }
    };
  }
  
  const cancelBtn = el('btnCancelEvent');
  if (cancelBtn && !cancelBtn.onclick) {
    cancelBtn.onclick = () => {
      cancelEventEdit();
      showStatus('Edit cancelled');
    };
  }
  
  const refreshBtn = el('btnRefreshEvents');
  if (refreshBtn && !refreshBtn.onclick) {
    refreshBtn.onclick = () => {
      loadEventConfigs();
      loadEvents();
    };
  }
  
  const deleteBtn = el('btnDeleteEvent');
  if (deleteBtn && !deleteBtn.onclick) {
    deleteBtn.onclick = async () => {
      const selected = document.querySelectorAll('.event-checkbox:checked');
      if (selected.length === 0) {
        showStatus('Please select at least one event to delete');
        return;
      }
      
      const eventIds = Array.from(selected).map(cb => parseInt(cb.value));
      const count = eventIds.length;
      const confirmMsg = `Are you sure you want to delete ${count} event(s)?`;
      
      if (confirm(confirmMsg)) {
        showStatus(`Deleting ${count} event(s)...`);
        let successCount = 0;
        let failCount = 0;
        
        for (const eventId of eventIds) {
          try {
            const res = await api(`/event/delete/${eventId}`, { method: 'DELETE' });
            if (res.ok) {
              successCount++;
            } else {
              failCount++;
            }
          } catch (error) {
            failCount++;
            logMsg(`Error deleting event ${eventId}: ${error.message || error}`);
          }
        }
        
        if (successCount > 0) {
          showStatus(`Successfully deleted ${successCount} event(s)${failCount > 0 ? `, ${failCount} failed` : ''}`);
          logMsg(`Deleted ${successCount} event(s)`);
          loadEvents();
        } else {
          showStatus(`Failed to delete ${failCount} event(s)`);
        }
      }
    };
  }
}

// Enable/disable Create/Update Event button based on form validation
function updateCreateEventButton() {
  const createBtn = el('btnCreateEvent');
  const updateBtn = el('btnUpdateEvent');
  const nameInput = el('eventName');
  const dateInput = el('eventDate');
  const timeInput = el('eventTime');
  const configSelect = el('eventConfigSelect');
  const dateError = el('eventDateError');
  const timeError = el('eventTimeError');
  
  // Only proceed if elements exist (section is loaded)
  if (!nameInput || !dateInput || !configSelect) {
    return;
  }
  
  const name = nameInput.value.trim();
  const date = dateInput.value;
  const time = timeInput ? timeInput.value : '';
  const configId = configSelect.value;
  
  // Validate date/time is not in the past
  let dateTimeValid = true;
  let dateErrorMessage = '';
  let timeErrorMessage = '';
  
  if (date) {
    const timePart = time ? time + ':00' : '00:00';
    let eventDateTime, now;
    if (typeof dayjs !== 'undefined') {
      eventDateTime = dayjs(`${date}T${timePart}`);
      now = dayjs();
    } else {
      eventDateTime = new Date(date + (time ? 'T' + time : 'T00:00:00'));
      now = new Date();
    }
    
    const isValid = typeof dayjs !== 'undefined' 
      ? eventDateTime.isValid() && !eventDateTime.isBefore(now)
      : !isNaN(eventDateTime.getTime()) && eventDateTime >= now;
    
    if (!isValid) {
      dateTimeValid = false;
      if (time) {
        timeErrorMessage = 'Event date and time cannot be in the past';
      } else {
        dateErrorMessage = 'Event date cannot be in the past';
      }
    }
  }
  
  // Show/hide error messages
  if (dateError) {
    if (dateErrorMessage) {
      dateError.textContent = dateErrorMessage;
      dateError.style.display = 'inline';
      if (dateInput) dateInput.style.borderColor = '#f87171';
    } else {
      dateError.style.display = 'none';
      if (dateInput) dateInput.style.borderColor = '';
    }
  }
  
  if (timeError) {
    if (timeErrorMessage) {
      timeError.textContent = timeErrorMessage;
      timeError.style.display = 'inline';
      if (timeInput) timeInput.style.borderColor = '#f87171';
    } else {
      timeError.style.display = 'none';
      if (timeInput) timeInput.style.borderColor = '';
    }
  }
  
  // Buttons are enabled only when all required fields are filled AND date/time is valid
  const isValid = !!(name && date && configId && dateTimeValid);
  
  if (createBtn) {
    createBtn.disabled = !isValid;
  }
  if (updateBtn) {
    updateBtn.disabled = !isValid;
  }
}

// Set up event listeners for Create Event form validation
function initEventFormValidation() {
  const nameInput = el('eventName');
  const dateInput = el('eventDate');
  const timeInput = el('eventTime');
  const configSelect = el('eventConfigSelect');
  
  // Set min date to today
  if (dateInput) {
    const today = typeof dayjs !== 'undefined' 
      ? dayjs().format('YYYY-MM-DD')
      : new Date().toISOString().split('T')[0];
    dateInput.setAttribute('min', today);
    
    // Update min date when date changes (to handle time validation)
    dateInput.addEventListener('change', function() {
      const selectedDate = dateInput.value;
      const today = typeof dayjs !== 'undefined' 
        ? dayjs().format('YYYY-MM-DD')
        : new Date().toISOString().split('T')[0];
      
      if (selectedDate === today && timeInput) {
        // If date is today, set min time to current time
        if (typeof dayjs !== 'undefined') {
          const currentTime = dayjs().format('HH:mm');
          timeInput.setAttribute('min', currentTime);
        } else {
          const now = new Date();
          const hours = String(now.getHours()).padStart(2, '0');
          const minutes = String(now.getMinutes()).padStart(2, '0');
          timeInput.setAttribute('min', `${hours}:${minutes}`);
        }
      } else if (timeInput) {
        // If date is in the future, remove min time restriction
        timeInput.removeAttribute('min');
      }
      
      updateCreateEventButton();
    });
    
    dateInput.addEventListener('input', updateCreateEventButton);
  }
  
  if (timeInput) {
    timeInput.addEventListener('change', function() {
      // Validate when time changes
      if (dateInput && dateInput.value) {
        const selectedDate = dateInput.value;
        const today = typeof dayjs !== 'undefined' 
          ? dayjs().format('YYYY-MM-DD')
          : new Date().toISOString().split('T')[0];
        const selectedTime = timeInput.value;
        
        if (selectedDate === today && selectedTime) {
          const eventDateTime = new Date(selectedDate + 'T' + selectedTime);
          const now = new Date();
          if (eventDateTime < now) {
            showStatus('Event time cannot be in the past', { error: true });
            timeInput.value = '';
          }
        }
      }
      updateCreateEventButton();
    });
    timeInput.addEventListener('input', updateCreateEventButton);
  }
  
  if (nameInput) {
    nameInput.addEventListener('input', updateCreateEventButton);
    nameInput.addEventListener('change', updateCreateEventButton);
  }
  
  if (configSelect) {
    configSelect.addEventListener('change', updateCreateEventButton);
  }
  
  // Initial check
  updateCreateEventButton();
}

// Delete button is set up in setupEventButtons() function above

// Attach run button handler
function attachRunButtonHandler() {
  const runBtn = el('btnInstallSelected');
  if (runBtn) {
    // Remove any existing handlers first
    runBtn.onclick = null;
    // Attach the handler
    runBtn.onclick = handleTrackedRunButton;
  }
}
// Tracked Run: execute step-by-step with detailed logging and track in Reports
async function handleTrackedRunButton() {
  
  let runId = null;
  const errors = [];
  const executionDetails = {
    fabric_creations: [],
    installations: [],
    ssh_executions: [],
    hostname_changes: [],
    password_changes: []
  };
  let hosts = []; // Declare hosts at function scope so it's accessible in catch block
  
  let runBtn = el('btnInstallSelected');

  // Helper function to clean up run state (but keep Run button disabled)
  const cleanupRunState = () => {
    hideRunInProgressWarning();
    hideRunProgress();
    stopRunTimer();
  };
  
  // Helper function to fully complete the run and re-enable Run button
  const completeRun = () => {
    isRunInProgress = false;
    cleanupRunState();
    if (runBtn) runBtn.disabled = false;
  };

  if (runBtn) runBtn.disabled = true;

  isRunInProgress = true;
  showRunInProgressWarning();
  showStatus('Installation started.');
  
  try {
    runBtn = runBtn || el('btnInstallSelected');
    if (runBtn) runBtn.disabled = true;
    
    // Show expert mode output during run
    const expertModeCheckbox = el('expertMode');
    const out = el('out');
    if (out && expertModeCheckbox) {
      out.style.display = '';
      if (!expertModeCheckbox.checked) {
        expertModeCheckbox.checked = true;
      }
    }
    
    // Create manual run record
    const configPayload = collectConfiguration();
    const configurationName = configPayload.configName || 'Manual Run';
    try {
      const createRes = await api('/run/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ configuration_name: configurationName })
      });
      if (createRes.ok) {
        const createData = await createRes.json();
        runId = createData.run_id;
      }
    } catch (err) {
      logMsg(`Warning: Could not create run record: ${err.message || err}`);
    }
    
    // Show progress bar and start timer
    updateRunProgress(0, 'Starting...');
    startRunTimer();
    
    hosts = getAllConfirmedHosts();
    if (hosts.length === 0) {
      // Auto-confirm hosts if available
    if (autoConfirmHosts()) {
      // Hosts are now confirmed, continue
    } else {
      showStatus('No hosts configured. Please add at least one valid host.');
      if (runId) {
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'error', message: 'No hosts configured', errors: ['No hosts configured'] })
        });
      }
      completeRun();
      return;
    }
      if (runId) {
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'error', message: 'No hosts configured', errors: ['No hosts configured'] })
        });
      }
      completeRun();
      return;
    }
    
    // Show Running Tasks section
    const runningTasksContainer = el('runningTasksContainer');
    if (runningTasksContainer) {
      runningTasksContainer.style.display = '';
    }
    
    // User is already authenticated via login - proceed
    // Build templates list from ALL rows (with deduplication)
    updateRunProgress(5, 'Collecting templates...');
    const allRowTemplates = [];
    const seenTemplates = new Set(); // Track seen templates to avoid duplicates
    document.querySelectorAll('.tpl-row').forEach(row => {
      const selects = row.querySelectorAll('select');
      const repoSelect = selects[0];
      const templateFiltered = row._templateFiltered;
      const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
      const repo_name = repoSelect?.value || '';
      const template_name = templateFiltered ? templateFiltered.getValue() : '';
      const version = versionSelect?.value || '';
      if (template_name && repo_name && version) {
        // Create a unique key for this template
        const templateKey = `${repo_name}|||${template_name}|||${version}`;
        // Only add if we haven't seen this exact template before
        if (!seenTemplates.has(templateKey)) {
          seenTemplates.add(templateKey);
          allRowTemplates.push({ template_name, repo_name, version });
        }
      }
    });
    
    if (allRowTemplates.length === 0) {
      showStatus('No workspace templates found in rows. Please add and fill template rows.');
      if (runId) {
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'error', message: 'No templates found', errors: ['No workspace templates found in rows'] })
        });
      }
      completeRun();
      return;
    }
    
    // Sort templates alphabetically
    allRowTemplates.sort((a, b) => {
      const nameCompare = a.template_name.localeCompare(b.template_name);
      if (nameCompare !== 0) return nameCompare;
      return a.version.localeCompare(b.version);
    });
    
    // Ensure ALL templates from rows are in the templates array for tracking
    allRowTemplates.forEach(({template_name, repo_name, version}) => {
      const exists = templates.find(t => t.template_name === template_name && t.version === version);
      if (!exists) {
        templates.push({ template_name, repo_name, version, status: '', createProgress: 0, hosts: [] });
      } else {
        // Reset status for existing templates since we're starting a new run
        // The preparation steps will delete all fabrics, so we need to recreate them
        exists.status = '';
        exists.createProgress = 0;
        exists.hosts = [];
      }
    });
    
    // Since preparation steps delete all fabrics, we need to create all templates
    // Don't check existing status - always create templates that are in the rows
    const templatesToCreate = allRowTemplates;
    
    // Track failed hosts across all operations
    const failedHosts = new Set();
    
    // Track start time for duration calculation
    const runStartTime = Date.now();
    
    // If we need to create templates, run preparation steps first
    if (templatesToCreate.length > 0) {
      // Execute preparation steps (5-20%)
      updateRunProgress(7, 'Executing preparation steps...');
      
      // Refresh repositories
      updateRunProgress(9, 'Refreshing repositories...');
      logMsg('Refreshing repositories...');
      await executeOnAllHosts('Refresh Repositories', async (fabric_host) => {
        const res = await api('/repo/refresh', { method: 'POST', params: { fabric_host } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Uninstall workspaces (reset)
      updateRunProgress(11, 'Uninstalling workspaces...');
      logMsg('Uninstalling workspaces...');
      await executeOnAllHosts('Uninstall Workspaces', async (fabric_host) => {
        const res = await api('/runtime/reset', { method: 'POST', params: { fabric_host } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Remove workspaces (batch delete)
      updateRunProgress(13, 'Removing workspaces...');
      logMsg('Removing workspaces...');
      await executeOnAllHosts('Remove Workspaces', async (fabric_host) => {
        const res = await api('/model/fabric/batch', { method: 'DELETE', params: { fabric_host } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Change hostname (if provided)
      const hostnameBase = el('newHostname').value.trim();
      if (hostnameBase) {
        updateRunProgress(15, 'Changing hostnames...');
        await waitForNoRunningTasks(hosts, 'Change Hostname');
        const hostnamePromises = hosts.map(async ({host}, index) => {
          try {
            const hostname = hostnameBase + (index + 1);
            const res = await api('/system/hostname', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ fabric_host: host, hostname })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            logMsg(`Hostname changed to ${hostname} for ${host}`);
            executionDetails.hostname_changes.push({
              host: host,
              new_hostname: hostname,
              success: true
            });
          } catch (error) {
            logMsg(`Change hostname failed on ${host}: ${error.message || error}`);
            executionDetails.hostname_changes.push({
              host: host,
              new_hostname: hostnameBase + (index + 1),
              success: false,
              error: error.message || String(error)
            });
          }
        });
        await Promise.all(hostnamePromises);
      }
      
      // Change password (if provided)
      const new_password = el('chgPass').value.trim();
      if (new_password) {
        updateRunProgress(17, 'Changing guest user password...');
        logMsg('Changing guest user password...');
        const passwordChangeResults = await executeOnAllHosts('Change password', async (fabric_host) => {
          const res = await api('/user/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fabric_host, username: 'guest', new_password })
          });
          if (!res.ok) {
            let errorMessage = `HTTP ${res.status}`;
            try {
              const errorData = await res.json();
              errorMessage = errorData.detail || errorData.message || errorMessage;
            } catch (e) {
              // If JSON parsing fails, try to get text
              try {
                const errorText = await res.text();
                if (errorText) {
                  errorMessage = errorText;
                }
              } catch (e2) {
                // Use default error message
              }
            }
            logMsg(`Password change error on ${fabric_host}: ${errorMessage}`);
            throw new Error(errorMessage);
          }
        });
        // Track password change results
        if (passwordChangeResults) {
          passwordChangeResults.forEach(result => {
            executionDetails.password_changes.push({
              host: result.host,
              username: 'guest',
              success: result.success || false,
              error: result.error || null
            });
          });
        }
      }
      
      // Add templates to create to the templates array
      updateRunProgress(20, 'Preparing templates...');
      logMsg('Preparing templates...');
      templatesToCreate.forEach(({template_name, repo_name, version}) => {
        const exists = templates.find(t => t.template_name === template_name && t.version === version);
        if (!exists) {
          templates.push({ template_name, repo_name, version, status: 'spin', createProgress: 0, hosts: [] });
        }
      });
      renderTemplates();
      
      updateRunProgress(22, `Creating ${templatesToCreate.length} workspace template(s)...`);
      showStatus(`Creating ${templatesToCreate.length} workspace template(s)...`);
      logMsg(`Creating ${templatesToCreate.length} workspace template(s): ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      
      // Check for running tasks before creating templates
      await waitForNoRunningTasks(hosts, 'Create Templates');
      
      // Process templates sequentially (one at a time)
      const totalTemplates = templatesToCreate.length;
      logMsg(`Starting sequential creation of ${totalTemplates} templates: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      
      let createdCount = 0;
      
      // Process each template one at a time
      for (let i = 0; i < templatesToCreate.length; i++) {
        const rowTemplate = templatesToCreate[i];
        logMsg(`[${i + 1}/${totalTemplates}] Starting creation process for ${rowTemplate.template_name} v${rowTemplate.version}`);
        
        // Check if all hosts have failed before processing this template
        const availableHostsBeforeTemplate = hosts.filter(({host}) => !failedHosts.has(host));
        if (availableHostsBeforeTemplate.length === 0) {
          const errorMsg = `All hosts have failed. Stopping execution before processing template '${rowTemplate.template_name}'.`;
          showStatus(errorMsg);
          logMsg(errorMsg);
          updateRunProgress(100, `Execution stopped - all hosts failed`);
          renderTemplates();
          stopRunTimer();
          if (runId) {
            await api(`/run/update/${runId}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                status: 'error', 
                message: 'Execution stopped - all hosts failed',
                errors: errors,
                execution_details: executionDetails
              })
            });
          }
          completeRun();
          return;
        }
        
        // Check for running tasks before creating this template
        await waitForNoRunningTasks(hosts, `Create Template ${rowTemplate.template_name}`);
        
        // Create separate template entry for each host
        hosts.forEach(({host}) => {
          let t = templates.find(t => 
            t.template_name === rowTemplate.template_name && 
            t.version === rowTemplate.version && 
            t.host === host
          );
          if (!t) {
            t = { 
              template_name: rowTemplate.template_name,
              repo_name: rowTemplate.repo_name,
              version: rowTemplate.version,
              host: host,
              status: 'spin', 
              createProgress: 0, 
              hosts: [host] 
            };
            templates.push(t);
          } else {
            t.status = 'spin';
            t.createProgress = 0;
            t.hosts = [host];
            if (!t.host || t.host === 'host' || t.host === 'Host') {
              t.host = host;
            }
          }
        });
        renderTemplates();
        
        // Update progress for starting this template
        const templateProgress = 20 + (i / totalTemplates) * 40;
        updateRunProgress(templateProgress, `Creating template ${i + 1}/${totalTemplates}: ${rowTemplate.template_name}`);
        
        // Process all hosts for this template in parallel
        const hostPromises = hosts.map(async ({host}) => {
          if (failedHosts.has(host)) {
            return {host, success: false, error: 'Host failed during previous template creation', skipped: true};
          }
          
          let t = templates.find(t => 
            t.template_name === rowTemplate.template_name && 
            t.version === rowTemplate.version && 
            t.host === host
          );
          if (!t) {
            t = { 
              template_name: rowTemplate.template_name,
              repo_name: rowTemplate.repo_name,
              version: rowTemplate.version,
              host: host,
              status: 'spin', 
              createProgress: 0, 
              hosts: [host] 
            };
            templates.push(t);
          } else {
            if (!t.host || t.host === 'host' || t.host === 'Host') {
              t.host = host;
            }
          }
          
          const creationStart = Date.now();
          try {
            // Get template id
            const { template_id } = await apiJson('/repo/template', {
              params: {
                fabric_host: host,
                template_name: t.template_name,
                repo_name: t.repo_name,
                version: t.version,
              }
            });
            logMsg(`Template located on ${host}`);

            // Create fabric
            logMsg(`Creating fabric ${t.template_name} v${t.version} on ${host} (template_id: ${template_id})`);
            
            let res = await api('/model/fabric', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                fabric_host: host,
                template_id,
                template_name: t.template_name,
                version: t.version,
              }),
            });
            
            if (!res.ok) {
              const errorText = await res.text().catch(() => `HTTP ${res.status}`);
              let errorDetail = errorText;
              try {
                const errorJson = JSON.parse(errorText);
                if (errorJson.detail) {
                  errorDetail = errorJson.detail;
                }
              } catch (e) {}
              const errorMsg = `Failed to create fabric '${t.template_name}' v${t.version} on ${host}: ${errorDetail}`;
              showStatus(errorMsg);
              logMsg(errorMsg);
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
              const creationDuration = (Date.now() - creationStart) / 1000;
              executionDetails.fabric_creations.push({
                host: host,
                template_name: t.template_name,
                version: t.version,
                success: false,
                duration_seconds: creationDuration,
                errors: [errorDetail]
              });
              return {host, success: false, error: errorDetail || 'Create failed'};
            }
            
            const responseData = await res.json().catch(() => ({}));
            logMsg(`Fabric creation request submitted on ${host} for ${t.template_name} v${t.version} (template_id: ${template_id})`);

            // Poll running task count until zero or timeout
            const timeoutMs = 15 * 60 * 1000;
            t.createProgress = 5;
            renderTemplates();
            
            const progressInterval = setInterval(() => {
              const elapsed = Date.now() - creationStart;
              const pct = Math.min(95, Math.max(5, Math.floor((elapsed / timeoutMs) * 100)));
              if (t.createProgress !== pct) {
                t.createProgress = pct;
                renderTemplates();
              }
            }, 500);

            while (Date.now() - creationStart < timeoutMs) {
              const sres = await api('/tasks/status', { params: { fabric_host: host } });
              if (!sres.ok) { clearInterval(progressInterval); break; }
              const sdata = await sres.json();
              const cnt = sdata.running_count ?? 0;
              if (cnt === 0) { clearInterval(progressInterval); break; }
              await new Promise(r => setTimeout(r, 2000));
            }
            clearInterval(progressInterval);

            // Check status
            const done = await api('/tasks/status', { params: { fabric_host: host } });
            if (done.ok) {
              const d = await done.json();
              if ((d.running_count ?? 0) === 0) {
                // Check for task errors
                try {
                  const createStartTime = new Date(creationStart).toISOString();
                  const errorsRes = await api('/tasks/errors', { 
                    params: { 
                      fabric_host: host, 
                      limit: 20,
                      fabric_name: t.template_name,
                      since_timestamp: createStartTime
                    } 
                  });
                  if (errorsRes.ok) {
                    const errorsData = await errorsRes.json();
                    if (errorsData.errors && errorsData.errors.length > 0) {
                      const errorMessages = errorsData.errors.map(err => `Task '${err.task_name}': ${err.error}`).join('; ');
                      const errorMsg = `Template '${t.template_name}' v${t.version} creation completed on ${host} but with errors: ${errorMessages}`;
                      // showStatus already calls logMsg internally, so don't duplicate
                      showStatus(errorMsg);
                      t.status = 'err';
                      t.createProgress = 0;
                      renderTemplates();
                      const creationDuration = (Date.now() - creationStart) / 1000;
                      executionDetails.fabric_creations.push({
                        host: host,
                        template_name: t.template_name,
                        version: t.version,
                        success: false,
                        duration_seconds: creationDuration,
                        errors: [errorMessages]
                      });
                      return {host, success: false, error: errorMessages};
                    }
                  }
                } catch (error) {}
                
                // showStatus already calls logMsg internally, so don't duplicate
                showStatus(`Template '${t.template_name}' v${t.version} created successfully on ${host}`);
                t.status = 'created';
                t.createProgress = 100;
                renderTemplates();
                const creationDuration = (Date.now() - creationStart) / 1000;
                executionDetails.fabric_creations.push({
                  host: host,
                  template_name: t.template_name,
                  version: t.version,
                  success: true,
                  duration_seconds: creationDuration
                });
                return {host, success: true};
              } else {
                const errorMsg = `Template '${t.template_name}' v${t.version} creation timeout on ${host} - tasks still running`;
                showStatus(errorMsg);
                logMsg(errorMsg);
                t.status = 'err';
                t.createProgress = 0;
                renderTemplates();
                const creationDuration = (Date.now() - creationStart) / 1000;
                executionDetails.fabric_creations.push({
                  host: host,
                  template_name: t.template_name,
                  version: t.version,
                  success: false,
                  duration_seconds: creationDuration,
                  errors: ['Timeout - tasks still running']
                });
                return {host, success: false, error: 'Timeout - tasks still running'};
              }
            } else {
              const errorText = await done.text().catch(() => 'Unknown error');
              const errorMsg = `Failed to check task status on ${host} for '${t.template_name}' v${t.version}: ${errorText}`;
              showStatus(errorMsg);
              logMsg(errorMsg);
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
              const creationDuration = (Date.now() - creationStart) / 1000;
              executionDetails.fabric_creations.push({
                host: host,
                template_name: t.template_name,
                version: t.version,
                success: false,
                duration_seconds: creationDuration,
                errors: ['Status check failed']
              });
              return {host, success: false, error: 'Status check failed'};
            }
          } catch (error) {
            const errorMsg = `Error processing template '${rowTemplate.template_name}' v${rowTemplate.version} on ${host}: ${error.message || error}`;
            showStatus(errorMsg);
            logMsg(errorMsg);
            if (t) {
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
            }
            const creationDuration = (Date.now() - creationStart) / 1000;
            executionDetails.fabric_creations.push({
              host: host,
              template_name: rowTemplate.template_name,
              version: rowTemplate.version,
              success: false,
              duration_seconds: creationDuration,
              errors: [error.message || String(error)]
            });
            return {host, success: false, error: error.message || error};
          }
        });

        const results = await Promise.allSettled(hostPromises);
        const settledResults = results.map(r => r.status === 'fulfilled' ? r.value : {host: 'unknown', success: false, error: r.reason?.message || 'Promise rejected'});
        const successCount = settledResults.filter(r => r.success).length;
        const failedHostsForTemplate = settledResults.filter(r => !r.success && !r.skipped);
        failedHostsForTemplate.forEach(f => failedHosts.add(f.host));
        
        const availableHostsForTemplate = hosts.filter(({host}) => !failedHosts.has(host));
        
        if (successCount === 0 && failedHostsForTemplate.length > 0) {
          const errorDetails = failedHostsForTemplate.map(f => `${f.host}: ${f.error || 'Unknown error'}`).join('; ');
          const errorMsg = `Template '${rowTemplate.template_name}' v${rowTemplate.version} creation failed on all hosts: ${errorDetails}`;
          showStatus(errorMsg);
          logMsg(errorMsg);
          logMsg(`Stopping execution - template creation failed on all hosts`);
          updateRunProgress(100, `Execution stopped - template creation failed`);
          renderTemplates();
          stopRunTimer();
          errors.push(errorMsg);
          if (runId) {
            await api(`/run/update/${runId}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                status: 'error', 
                message: 'Execution stopped - template creation failed',
                errors: errors,
                execution_details: executionDetails
              })
            });
          }
          if (runBtn) runBtn.disabled = false;
          return;
        }
        
        if (availableHostsForTemplate.length === 0) {
          const errorMsg = `All hosts have failed. Stopping execution.`;
          showStatus(errorMsg);
          logMsg(errorMsg);
          logMsg(`Stopping execution - all hosts failed`);
          updateRunProgress(100, `Execution stopped - all hosts failed`);
          renderTemplates();
          stopRunTimer();
          errors.push(errorMsg);
          if (runId) {
            await api(`/run/update/${runId}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                status: 'error', 
                message: 'Execution stopped - all hosts failed',
                errors: errors,
                execution_details: executionDetails
              })
            });
          }
          completeRun();
          return;
        }
        
        if (successCount > 0) {
          createdCount++;
          if (successCount < hosts.length) {
            const failedHostNames = failedHostsForTemplate.map(f => f.host).join(', ');
            showStatus(`Template '${rowTemplate.template_name}' created on ${successCount}/${hosts.length} host(s). Failed on: ${failedHostNames}`);
            logMsg(`Template '${rowTemplate.template_name}' created on ${successCount}/${hosts.length} host(s). Failed on: ${failedHostNames}`);
          }
        }
        renderTemplates();
        
        if (successCount > 0) {
          logMsg(`Template '${rowTemplate.template_name}' v${rowTemplate.version} creation completed on ${successCount}/${hosts.length} host(s)`);
        }
        
        await waitForNoRunningTasks(hosts, `After creating ${rowTemplate.template_name}`);
        
        const completedProgress = 20 + ((i + 1) / totalTemplates) * 40;
        updateRunProgress(completedProgress, `Template ${i + 1}/${totalTemplates} created: ${rowTemplate.template_name}`);
      }
      
      updateRunProgress(60, `All workspace templates processed: ${createdCount}/${totalTemplates} created successfully`);
      renderTemplates();
      
      if (createdCount === totalTemplates) {
        showStatus(`Created all ${templatesToCreate.length} workspace template(s) successfully: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      } else {
        showStatus(`Created ${createdCount}/${templatesToCreate.length} workspace template(s) successfully: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      }
    } else {
      updateRunProgress(60, 'All workspace templates already exist');
      logMsg('All workspace templates already created, skipping creation phase');
      showStatus('All workspace templates already exist');
    }
    
    // Execute SSH Profiles (if selected) BEFORE Install Workspace
    const sshProfileSelect = el('sshProfileSelect');
    const sshProfileId = sshProfileSelect ? sshProfileSelect.value : '';
    const sshWaitTimeInput = el('sshWaitTime');
    const sshWaitTime = sshWaitTimeInput ? (parseInt(sshWaitTimeInput.value) || 60) : 60;
    
    if (sshProfileId) {
      updateRunProgress(61, 'Executing SSH profiles...');
      showStatus('Executing SSH profiles on all hosts...');
      
      // No encryption password required - uses FS_SERVER_SECRET
      try {
        const availableHostsForSsh = hosts.filter(({host}) => !failedHosts.has(host));
        
        if (availableHostsForSsh.length === 0) {
          showStatus('Skipping SSH profile execution - all hosts failed during template creation.');
          logMsg('Skipping SSH profile execution - all hosts failed during template creation');
        } else {
          if (failedHosts.size > 0) {
            const failedHostNames = Array.from(failedHosts).join(', ');
            logMsg(`Skipping SSH execution on failed hosts: ${failedHostNames}. Executing on ${availableHostsForSsh.length} remaining host(s).`);
          }
          
          // Capture SSH profile metadata for reporting
          const sshProfileOption = sshProfileSelect?.options[sshProfileSelect.selectedIndex];
          let sshProfileNameForRun = sshProfileOption ? sshProfileOption.text : 'N/A';
          let sshCommandsList = [];
          try {
            const sshProfileDetails = await getSshProfileDetailsById(sshProfileId);
            if (sshProfileDetails) {
              if (sshProfileDetails.name) {
                sshProfileNameForRun = sshProfileDetails.name;
              }
              if (typeof sshProfileDetails.commands === 'string') {
                sshCommandsList = sshProfileDetails.commands
                  .split('\n')
                  .map(cmd => cmd.trim())
                  .filter(Boolean);
              }
            }
          } catch (metaError) {
            logMsg(`Warning: Unable to fetch SSH profile details: ${metaError.message || metaError}`);
          }

          executionDetails.ssh_profile_info = {
            profile_id: parseInt(sshProfileId, 10) || null,
            profile_name: sshProfileNameForRun,
            wait_time_seconds: sshWaitTime,
            commands: sshCommandsList
          };

          const sshResults = await executeSshProfiles(availableHostsForSsh, sshProfileId, sshWaitTime);
          const sshSuccessCount = sshResults.filter(r => r.success).length;
          
          // Track SSH execution results
          sshResults.forEach(result => {
            executionDetails.ssh_executions.push({
              host: result.host,
              success: result.success,
              error: result.error || null,
              output: result.output || null
            });
          });
          
          if (sshSuccessCount === availableHostsForSsh.length) {
            updateRunProgress(63, 'SSH profiles executed successfully!');
            showStatus(`SSH profiles executed successfully on all ${availableHostsForSsh.length} host(s)`);
          } else {
            updateRunProgress(63, `SSH profiles executed on ${sshSuccessCount}/${availableHostsForSsh.length} host(s)`);
            showStatus(`SSH profiles executed on ${sshSuccessCount}/${availableHostsForSsh.length} host(s)`);
            const sshErrors = sshResults.filter(r => !r.success).map(r => `${r.host}: ${r.error || 'Unknown error'}`);
            if (sshErrors.length > 0) {
              showStatus(`SSH profile errors (continuing with installation):\n${sshErrors.join('\n')}`, { error: true });
              logMsg(`SSH profile errors: ${sshErrors.join('; ')}`);
              errors.push(...sshErrors);
            }
          }
        }
      } catch (error) {
        logMsg(`SSH profile execution error: ${error.message || error}`);
        showStatus(`Error executing SSH profiles: ${error.message || error}`, { error: true });
        errors.push(`SSH execution error: ${error.message || error}`);
      }
    }
    // Install the selected workspace (after SSH profiles execute)
    // Check if Run Workspace is enabled
    const runWorkspaceEnabledInput = el('runWorkspaceEnabled');
    const runWorkspaceEnabled = runWorkspaceEnabledInput ? runWorkspaceEnabledInput.checked : true;
    
    if (!runWorkspaceEnabled) {
      logMsg('Run Workspace is disabled - skipping workspace installation');
      updateRunProgress(100, 'Run completed - workspace installation skipped');
      showStatus('Run completed - workspace installation was disabled');
      renderTemplates();
      stopRunTimer();
      
      // Update run record with final status
      const finalStatus = errors.length === 0 ? 'success' : 'error';
      const finalMessage = errors.length === 0 
        ? 'Run completed successfully (workspace installation skipped)' 
        : `Run completed with ${errors.length} error(s) (workspace installation skipped)`;
      
      const runDuration = (Date.now() - runStartTime) / 1000;
      const finalExecutionDetails = {
        ...executionDetails,
        hosts: hosts.map(({host}) => host),
        duration_seconds: runDuration,
        // Explicitly include hostname and password changes
        hostname_changes: executionDetails.hostname_changes || [],
        hostname_changes_count: executionDetails.hostname_changes ? executionDetails.hostname_changes.length : 0,
        password_changes: executionDetails.password_changes || [],
        password_changes_count: executionDetails.password_changes ? executionDetails.password_changes.length : 0
      };
      
      const sshProfileInfo = executionDetails.ssh_profile_info;
      const sshExecutions = executionDetails.ssh_executions || [];

      if ((sshProfileInfo && (sshProfileInfo.profile_id || sshProfileInfo.profile_name || (sshProfileInfo.commands && sshProfileInfo.commands.length > 0))) || sshExecutions.length > 0) {
        const commandsList = Array.isArray(sshProfileInfo?.commands) ? sshProfileInfo.commands : [];
        const hostResults = sshExecutions.map(exec => ({
          host: exec.host,
          success: exec.success,
          commands_executed: exec.success ? commandsList.length : 0,
          commands_failed: exec.success ? 0 : commandsList.length,
          error: exec.error || null,
          output: exec.output || null
        }));

        finalExecutionDetails.ssh_profile = {
          profile_id: sshProfileInfo?.profile_id ?? null,
          profile_name: sshProfileInfo?.profile_name || 'N/A',
          wait_time_seconds: sshProfileInfo?.wait_time_seconds ?? null,
          commands: commandsList,
          hosts: hostResults
        };
      }

      delete finalExecutionDetails.ssh_executions;
      delete finalExecutionDetails.ssh_profile_info;
      
      if (runId) {
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            status: finalStatus, 
            message: finalMessage,
            errors: errors,
            execution_details: finalExecutionDetails
          })
        });
      }
      
      completeRun();
      return;
    }
    updateRunProgress(64, 'Preparing to install selected workspace...');
    logMsg('Preparing to install selected workspace...');
    const opt = el('installSelect').value;
    
    let template_name, version, repo_name;
    if (!opt) {
      const select = el('installSelect');
      if (select && select.options.length > 0 && select.options[0].value) {
        [template_name, version] = select.options[0].value.split('|||');
      } else {
        const created = templates.filter(t => t.status === 'created' || t.status === 'installed');
        if (created.length === 0) {
          showStatus('No templates available to install. Please create templates first.');
          logMsg('No templates available to install. Skipping installation phase.');
          updateRunProgress(100, 'No templates available to install');
          renderTemplates();
          stopRunTimer();
          if (runId) {
            await api(`/run/update/${runId}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                status: 'success', 
                message: 'No templates available to install',
                errors: errors,
                execution_details: executionDetails
              })
            });
          }
          completeRun();
          return;
        }
        const first = created[0];
        template_name = first.template_name;
        version = first.version;
      }
    } else {
      [template_name, version] = opt.split('|||');
    }
    // Get repo_name from rows if needed
    if (!repo_name) {
      document.querySelectorAll('.tpl-row').forEach(row => {
        const selects = row.querySelectorAll('select');
        const repoSelect = selects[0];
        const templateFiltered = row._templateFiltered;
        const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
        const row_template = templateFiltered ? templateFiltered.getValue() : '';
        const row_version = versionSelect?.value || '';
        if (row_template === template_name && row_version === version) {
          repo_name = repoSelect?.value || '';
        }
      });
    }
    
    const installTargets = [];
    const availableHosts = hosts.filter(({host}) => !failedHosts.has(host));
    
    if (availableHosts.length === 0) {
      showStatus(`Cannot install workspace: all hosts failed during template creation. Skipping installation.`);
      logMsg(`Skipping installation - all hosts failed during template creation`);
      updateRunProgress(100, 'Installation skipped - all hosts failed');
      renderTemplates();
      stopRunTimer();
      if (runId) {
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            status: 'error', 
            message: 'Installation skipped - all hosts failed',
            errors: errors,
            execution_details: executionDetails
          })
        });
      }
      completeRun();
      return;
    }
    
    if (failedHosts.size > 0) {
      const failedHostNames = Array.from(failedHosts).join(', ');
      showStatus(`Skipping installation on failed hosts: ${failedHostNames}. Installing on ${availableHosts.length} remaining host(s).`);
      logMsg(`Skipping installation on failed hosts: ${failedHostNames}. Installing on ${availableHosts.length} remaining host(s).`);
    }
    
    availableHosts.forEach(({host}) => {
      let target = templates.find(t => 
        t.template_name === template_name && 
        t.version === version && 
        t.host === host
      );
      if (!target) {
        target = { 
          template_name, 
          repo_name: repo_name || '', 
          version, 
          host: host,
          status: 'spin', 
          installProgress: 0, 
          hosts: [host] 
        };
        templates.push(target);
      } else {
        target.status = 'spin';
        target.installProgress = 0;
        target.hosts = [host];
        if (!target.host || target.host === 'host' || target.host === 'Host') {
          target.host = host;
        }
      }
      installTargets.push({ target, host });
    });
    renderTemplates();
    
    // Install Workspace
    updateRunProgress(65, 'Installing workspace...');
    showStatus(`Installing workspace: ${template_name} v${version}...`);
    logMsg(`Starting workspace installation: ${template_name} v${version}`);
    
    await waitForNoRunningTasks(hosts, 'Install Workspace');
    
    if (!template_name || !version) {
      showStatus('Error: Template name and version are required');
      logMsg('Error: Missing template_name or version');
      hideRunProgress();
      stopRunTimer();
      if (runId) {
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            status: 'error', 
            message: 'Missing template name or version',
            errors: errors,
            execution_details: executionDetails
          })
        });
      }
      completeRun();
      return;
    }
    
    // User is already authenticated via login - proceed
    
    updateRunProgress(70, `Installing workspace: ${template_name} v${version}`);
    const totalHosts = hosts.length;
    const hostProgressMap = new Map();
    
    logMsg(`Installing workspace ${template_name} v${version} on ${totalHosts} host(s)`);
    
    // Install on all hosts in parallel
    const installPromises = installTargets.map(async ({target, host}, hostIdx) => {
      const installStart = Date.now();
      try {
        logMsg(`Sending install request to ${host} for ${template_name} v${version}`);
        
        const res = await api('/runtime/fabric/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fabric_host: host,
            template_name,
            version,
          }),
          timeout: 15 * 60 * 1000, // 15 minutes timeout for installation
        });
        
        if (!res.ok) {
          const errorText = await res.text();
          logMsg(`Install workspace failed on ${host}: HTTP ${res.status} - ${errorText}`);
          hostProgressMap.set(host, 100);
          target.status = 'err';
          target.installProgress = 0;
          renderTemplates();
          const installDuration = (Date.now() - installStart) / 1000;
          executionDetails.installations.push({
            host: host,
            template_name: template_name,
            version: version,
            success: false,
            duration_seconds: installDuration,
            errors: [`HTTP ${res.status}: ${errorText}`]
          });
          return {host, success: false, error: `Install failed: HTTP ${res.status}`};
        }
        logMsg(`Workspace installation requested successfully on ${host}`);
        
        const timeoutMs = 15 * 60 * 1000;
        target.installProgress = 5;
        renderTemplates();
        
        const progressInterval = setInterval(() => {
          const elapsed = Date.now() - installStart;
          const installPct = Math.min(95, Math.max(5, Math.floor((elapsed / timeoutMs) * 100)));
          if (target.installProgress !== installPct) {
            target.installProgress = installPct;
            renderTemplates();
          }
          hostProgressMap.set(host, installPct);
          const totalProgress = Array.from(hostProgressMap.values()).reduce((sum, pct) => sum + pct, 0);
          const avgProgress = totalProgress / totalHosts;
          const overallProgress = 70 + (avgProgress / 100) * 25;
          updateRunProgress(Math.min(95, overallProgress), `Installing on ${hosts.length} host(s)... (${Math.round(avgProgress)}%)`);
        }, 500);
        
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          const sres = await api('/tasks/status', { params: { fabric_host: host } });
          if (!sres.ok) { clearInterval(progressInterval); break; }
          const sdata = await sres.json();
          const cnt = sdata.running_count ?? 0;
          if (cnt === 0) { clearInterval(progressInterval); break; }
          await new Promise(r => setTimeout(r, 2000));
        }
        clearInterval(progressInterval);
        
        const done = await api('/tasks/status', { params: { fabric_host: host } });
        hostProgressMap.set(host, 100);
        if (done.ok) {
          const d = await done.json();
          if ((d.running_count ?? 0) === 0) {
            try {
              const installStartTime = new Date(installStart).toISOString();
              const errorsRes = await api('/tasks/errors', { 
                params: { 
                  fabric_host: host, 
                  limit: 20,
                  fabric_name: template_name,
                  since_timestamp: installStartTime
                } 
              });
              if (errorsRes.ok) {
                const errorsData = await errorsRes.json();
                if (errorsData.errors && errorsData.errors.length > 0) {
                  const errorMessages = errorsData.errors.map(err => `Task '${err.task_name}': ${err.error}`).join('; ');
                  const errorMsg = `Workspace '${template_name}' v${version} installation completed on ${host} but with errors: ${errorMessages}`;
                  showStatus(errorMsg);
                  logMsg(errorMsg);
                  target.status = 'err';
                  target.installProgress = 0;
                  renderTemplates();
                  const completedCount = Array.from(hostProgressMap.values()).filter(p => p === 100).length;
                  updateRunProgress(70 + (completedCount / totalHosts) * 25, `Completed on ${completedCount}/${totalHosts} host(s)`);
                  const installDuration = (Date.now() - installStart) / 1000;
                  executionDetails.installations.push({
                    host: host,
                    template_name: template_name,
                    version: version,
                    success: false,
                    duration_seconds: installDuration,
                    errors: [errorMessages]
                  });
                  return {host, success: false, error: errorMessages};
                }
              }
            } catch (error) {}
            
            logMsg(`Installed successfully on ${host}`);
            target.status = 'installed';
            target.installProgress = 100;
            renderTemplates();
            const completedCount = Array.from(hostProgressMap.values()).filter(p => p === 100).length;
            updateRunProgress(70 + (completedCount / totalHosts) * 25, `Completed on ${completedCount}/${totalHosts} host(s)`);
            const installDuration = (Date.now() - installStart) / 1000;
            executionDetails.installations.push({
              host: host,
              template_name: template_name,
              version: version,
              success: true,
              duration_seconds: installDuration
            });
            return {host, success: true};
          } else {
            logMsg(`Still running or timeout on ${host}`);
            target.status = 'err';
            target.installProgress = 0;
            renderTemplates();
            const installDuration = (Date.now() - installStart) / 1000;
            executionDetails.installations.push({
              host: host,
              template_name: template_name,
              version: version,
              success: false,
              duration_seconds: installDuration,
              errors: ['Timeout']
            });
            return {host, success: false, error: 'Timeout'};
          }
        }
        target.status = 'err';
        target.installProgress = 0;
        renderTemplates();
        const installDuration = (Date.now() - installStart) / 1000;
        executionDetails.installations.push({
          host: host,
          template_name: template_name,
          version: version,
          success: false,
          duration_seconds: installDuration,
          errors: ['Status check failed']
        });
        return {host, success: false, error: 'Status check failed'};
      } catch (error) {
        logMsg(`Error installing on ${host}: ${error.message || error}`);
        hostProgressMap.set(host, 100);
        target.status = 'err';
        target.installProgress = 0;
        renderTemplates();
        const installDuration = (Date.now() - installStart) / 1000;
        executionDetails.installations.push({
          host: host,
          template_name: template_name,
          version: version,
          success: false,
          duration_seconds: installDuration,
          errors: [error.message || String(error)]
        });
        return {host, success: false, error: error.message || error};
      }
    });

    const results = await Promise.allSettled(installPromises);
    const settledResults = results.map(r => r.status === 'fulfilled' ? r.value : {host: 'unknown', success: false, error: r.reason?.message || 'Promise rejected'});
    const successCount = settledResults.filter(r => r.success).length;
    
    renderTemplates();
    
    if (successCount === hosts.length) {
      updateRunProgress(100, 'Workspace installation completed successfully!');
      showStatus(`Workspace installation completed successfully on all ${hosts.length} host(s)`);
      logMsg(`Workspace ${template_name} v${version} installed successfully on all ${hosts.length} host(s)`);
    } else {
      updateRunProgress(100, `Workspace installation completed on ${successCount}/${hosts.length} host(s)`);
      showStatus(`Workspace installation completed on ${successCount}/${hosts.length} host(s)`);
      logMsg(`Workspace ${template_name} v${version} installed on ${successCount}/${hosts.length} host(s)`);
      const installErrors = results.filter(r => !r.success).map(r => `${r.host}: ${r.error || 'Unknown error'}`);
      errors.push(...installErrors);
    }
    
    // Update run record with final status
    const finalStatus = errors.length === 0 ? 'success' : 'error';
    const finalMessage = errors.length === 0 
      ? 'Run completed successfully' 
      : `Run completed with ${errors.length} error(s)`;
    
    // Prepare final execution details with all required fields
    const runDuration = (Date.now() - runStartTime) / 1000;
    const finalExecutionDetails = {
      ...executionDetails,
      hosts: hosts.map(({host}) => host),
      duration_seconds: runDuration,
      // Explicitly include hostname and password changes
      hostname_changes: executionDetails.hostname_changes || [],
      hostname_changes_count: executionDetails.hostname_changes ? executionDetails.hostname_changes.length : 0,
      password_changes: executionDetails.password_changes || [],
      password_changes_count: executionDetails.password_changes ? executionDetails.password_changes.length : 0
    };
    
    // Transform ssh_executions to ssh_profile format if SSH profile was used
    const sshProfileSelectForReport = el('sshProfileSelect');
    const sshProfileIdForReport = sshProfileSelectForReport?.value;
    if (sshProfileIdForReport) {
      const sshProfileName = sshProfileSelectForReport?.options[sshProfileSelectForReport.selectedIndex]?.text || 'N/A';
      const sshWaitTimeInput = el('sshWaitTime');
      const sshWaitTime = sshWaitTimeInput ? (parseInt(sshWaitTimeInput.value) || 60) : 60;
      
      // Get SSH profile commands if available
      let sshCommands = [];
      try {
        const sshRes = await api('/ssh-command-profiles/list');
        if (sshRes.ok) {
          const sshData = await sshRes.json();
          const sshProfile = sshData.profiles?.find(p => p.id === parseInt(sshProfileIdForReport));
          if (sshProfile && sshProfile.commands) {
            sshCommands = sshProfile.commands.split('\n').filter(c => c.trim());
          }
        }
      } catch (err) {
        // Ignore errors
      }
      
      // Build hosts array from ssh_executions if available, otherwise create empty array
      const sshHosts = executionDetails.ssh_executions && executionDetails.ssh_executions.length > 0
        ? executionDetails.ssh_executions.map(exec => ({
            host: exec.host,
            success: exec.success,
            commands_executed: exec.success ? sshCommands.length : 0,
            commands_failed: exec.success ? 0 : sshCommands.length,
            error: exec.error || null,
            output: exec.output || null
          }))
        : [];
      
      finalExecutionDetails.ssh_profile = {
        profile_id: parseInt(sshProfileIdForReport),
        profile_name: sshProfileName,
        wait_time_seconds: sshWaitTime,
        commands: sshCommands,
        hosts: sshHosts
      };
      // Remove ssh_executions as we're using ssh_profile now
      delete finalExecutionDetails.ssh_executions;
      
      // Debug: Log what we're saving
      console.log('Saving SSH profile to report:', JSON.stringify(finalExecutionDetails.ssh_profile, null, 2));
    }
    
    if (runId) {
      try {
        // Debug: Log full execution details being saved
        console.log('Saving execution_details to report:', JSON.stringify(finalExecutionDetails, null, 2));
        
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            status: finalStatus, 
            message: finalMessage,
            errors: errors,
            execution_details: finalExecutionDetails
          })
        });
        logMsg(`Run tracking updated (ID: ${runId}, Status: ${finalStatus})`);
      } catch (err) {
        logMsg(`Warning: Could not update run record: ${err.message || err}`);
      }
    }
    
    renderTemplates();
    stopRunTimer();
    
    completeRun();
  } catch (error) {
    const errorMsg = `Run error: ${error.message || error}`;
    showStatus(errorMsg, { error: true, showProgress: false });
    logMsg(errorMsg);
    
    // Update run record with error
    if (runId) {
      try {
        const runDuration = (Date.now() - runStartTime) / 1000;
        const finalExecutionDetails = {
          ...executionDetails,
          hosts: (hosts || []).map(({host}) => host),
          duration_seconds: runDuration,
          // Explicitly include hostname and password changes
          hostname_changes: executionDetails.hostname_changes || [],
          hostname_changes_count: executionDetails.hostname_changes ? executionDetails.hostname_changes.length : 0,
          password_changes: executionDetails.password_changes || [],
          password_changes_count: executionDetails.password_changes ? executionDetails.password_changes.length : 0
        };
        
        await api(`/run/update/${runId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            status: 'error', 
            message: errorMsg,
            errors: [errorMsg],
            execution_details: finalExecutionDetails
          })
        });
      } catch (err) {
        logMsg(`Warning: Could not update run record: ${err.message || err}`);
      }
    }
    
    completeRun();
  } finally {
    updateInstallSelect();
  }
}

// Handler function for save config button
async function handleSaveConfigButton() {
  clearConfigName();
  
  // Validate guest password if provided
  const chgPassInput = el('chgPass');
  if (chgPassInput && chgPassInput.value.trim()) {
    const passwordValidation = validateGuestPassword(chgPassInput.value.trim());
    if (!passwordValidation.valid) {
      showStatus(`Password policy violation: Missing ${passwordValidation.errors.join(', ')}`);
      validateGuestPasswordField('chgPass', 'chgPassError');
      return;
    }
  }
  
  // Get name - if editing, use existing name, otherwise prompt
  let name;
  if (editingConfigId) {
    // Get existing name
    try {
      const getRes = await api(`/config/get/${editingConfigId}`);
      if (getRes.ok) {
        const existingConfig = await getRes.json();
        const newName = prompt('Enter a name for this configuration:', existingConfig.name || '');
        if (!newName || !newName.trim()) {
          showStatus('Save cancelled - name is required');
          return;
        }
        name = newName.trim();
      } else {
        showStatus('Error: Could not retrieve existing configuration details');
        return;
      }
    } catch (error) {
      showStatus(`Error: ${error.message || error}`);
      return;
    }
  } else {
    name = prompt('Enter a name for this configuration:');
    if (!name || !name.trim()) {
      showStatus('Save cancelled - name is required');
      return;
    }
    name = name.trim();
  }
  
  let config;
  try {
    config = collectConfiguration();
  } catch (error) {
    showStatus(`Error collecting configuration: ${error.message || error}`);
    return;
  }
  
  try {
    const payload = {
      name: name,
      config_data: config
    };
    // Only include id if editing an existing configuration
    if (editingConfigId) {
      payload.id = editingConfigId;
    }
    
    const res = await api('/config/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  
    if (!res.ok) {
      const errorText = await res.text();
      showStatus(`Failed to save configuration: ${errorText}`);
      return;
    }
    
    const data = await res.json();
    const action = editingConfigId ? 'updated' : 'saved';
    showStatus(data.message || `Configuration ${action} successfully`);
    logMsg(`Configuration ${action}: ${name}${editingConfigId ? ` (ID: ${editingConfigId})` : ''}`);
    
    // Clear edit mode and config name display
    const savedConfigId = editingConfigId;
    editingConfigId = null;
    clearConfigName();
    
    // Clear API cache and pending requests for configurations list
    const cacheKey = '/config/list?';
    if (_requestCache.has(cacheKey)) {
      _requestCache.delete(cacheKey);
    }
    if (_pendingRequests.has(cacheKey)) {
      _pendingRequests.delete(cacheKey);
    }
    
    // Clear cache for the saved configuration to ensure fresh data on next load
    if (savedConfigId) {
      const configCacheKey = `/config/get/${savedConfigId}?`;
      if (_requestCache.has(configCacheKey)) {
        _requestCache.delete(configCacheKey);
      }
      if (_pendingRequests.has(configCacheKey)) {
        _pendingRequests.delete(configCacheKey);
      }
    }
    
    // Reset all inputs in FabricStudio Runs section
    resetPreparationSection();
    
    // Navigate to configurations section (this will trigger loadConfigurations via initializeSection)
    const configMenuItem = document.querySelector('.menu-item[data-section="configurations"]');
    if (configMenuItem) {
      configMenuItem.click(); // This will trigger the menu click handler
    } else {
      // If menu item not found, just refresh the list
      loadConfigurations();
    }
  } catch (error) {
    showStatus(`Error saving configuration: ${error.message || error}`);
    logMsg(`Error saving configuration: ${error.message || error}`);
  }
}

// Attach save button handler
function attachSaveButtonHandler() {
  const saveBtn = el('btnSaveConfig');
  if (saveBtn) {
    saveBtn.onclick = handleSaveConfigButton;
  }
}
// NHI Management functions
let editingNhiId = null; // Track if we're editing an existing NHI credential

async function loadNhiCredentials() {
  const nhiList = el('nhiList');
  if (!nhiList) return;
  
  try {
    nhiList.innerHTML = '<p>Loading...</p>';
    
    const res = await api('/nhi/list');
    if (!res.ok) {
      nhiList.innerHTML = `<p style="color: #f87171;">Error loading NHI credentials: ${res.statusText}</p>`;
      return;
    }
    
    const data = await res.json();
    const credentials = data.credentials || [];
    
    if (credentials.length === 0) {
      nhiList.innerHTML = '<p>No NHI credentials found. Use the form above to create one.</p>';
      return;
    }
    
    // Add "Select All" / "Deselect All" functionality
    let html = `
      <div style="margin-bottom: 12px; padding: 8px; border: 1px solid #d2d2d7; background: #fafafa; border-radius: 4px;">
        <button id="btnSelectAllNhi" style="padding: 4px 12px; font-size: 12px; margin-right: 8px;">Select All</button>
        <button id="btnDeselectAllNhi" style="padding: 4px 12px; font-size: 12px;">Deselect All</button>
      </div>
    `;
    html += '<div style="display: flex; flex-direction: column; gap: 12px;">';
    
    credentials.forEach(cred => {
      const createdDate = formatDateTime(cred.created_at);
      const updatedDate = formatDateTime(cred.updated_at);
      
      html += `
        <div class="config-item" data-nhi-id="${cred.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <input type="checkbox" class="nhi-checkbox" value="${cred.id}" id="nhi-${cred.id}" style="margin: 0;">
            <label for="nhi-${cred.id}" style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">
              <span style="font-size: 16px;">${cred.name}</span>
            </label>
            <button class="btn-config-edit nhi-edit-btn" data-nhi-id="${cred.id}" style="padding: 4px 12px; font-size: 12px;">Edit</button>
            <button class="btn-config-delete nhi-delete-btn" data-nhi-id="${cred.id}" style="padding: 4px 12px; font-size: 12px;">Delete</button>
          </div>
          <div style="font-size: 12px; color: #86868b; margin-left: 24px; line-height: 1.6;">
            <div style="margin-bottom: 4px;"><strong>Client ID:</strong> ${cred.client_id}</div>
            ${cred.hosts_with_tokens && cred.hosts_with_tokens.length > 0 ? `
              <div style="margin-bottom: 4px;"><strong>FabricStudio Hosts with Tokens:</strong></div>
              <div style="margin-left: 12px; margin-bottom: 4px;">
                ${cred.hosts_with_tokens.map(h => {
                  const isExpired = h.token_lifetime === 'Expired';
                  const isValid = h.token_lifetime && h.token_lifetime !== 'N/A' && !isExpired;
                  return `<div style="margin-bottom: 2px;">
                    <span style="font-family: monospace; font-size: 11px;">${h.host}</span>: 
                    <span style="color: ${isValid ? '#10b981' : (isExpired ? '#f87171' : '#86868b')}; font-weight: ${isValid ? '600' : 'normal'}; margin-left: 4px;">${h.token_lifetime || 'N/A'}</span>
                  </div>`;
                }).join('')}
              </div>
            ` : '<div style="margin-bottom: 4px;"><strong>FabricStudio Hosts with Tokens:</strong> None</div>'}
            <div style="margin-bottom: 4px;"><strong>Created:</strong> ${createdDate}</div>
            <div><strong>Updated:</strong> ${updatedDate}</div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    nhiList.innerHTML = html;
    
    // Add event listeners for edit buttons
    document.querySelectorAll('.nhi-edit-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const nhiId = parseInt(btn.getAttribute('data-nhi-id'));
        await editNhi(nhiId);
      });
    });
    
    // Add event listeners for delete buttons
    document.querySelectorAll('.nhi-delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const nhiId = parseInt(btn.getAttribute('data-nhi-id'));
        if (confirm('Are you sure you want to delete this NHI credential?')) {
          await deleteNhi(nhiId);
        }
      });
    });
    
    // Checkbox selection for multiple delete
    document.querySelectorAll('.nhi-checkbox').forEach(checkbox => {
      checkbox.addEventListener('change', () => {
        updateNhiDeleteButtonVisibility();
      });
    });
    
    // Set up Select All / Deselect All buttons
    const selectAllBtn = el('btnSelectAllNhi');
    const deselectAllBtn = el('btnDeselectAllNhi');
    
    if (selectAllBtn) {
      selectAllBtn.onclick = () => {
        document.querySelectorAll('.nhi-checkbox').forEach(cb => cb.checked = true);
        updateNhiDeleteButtonVisibility();
      };
    }
    
    if (deselectAllBtn) {
      deselectAllBtn.onclick = () => {
        document.querySelectorAll('.nhi-checkbox').forEach(cb => cb.checked = false);
        updateNhiDeleteButtonVisibility();
      };
    }
    
    function updateNhiDeleteButtonVisibility() {
      const deleteBtn = el('btnDeleteNhi');
      if (deleteBtn) {
        const checked = document.querySelectorAll('.nhi-checkbox:checked');
        deleteBtn.style.display = checked.length > 0 ? 'inline-block' : 'none';
        if (checked.length > 0) {
          deleteBtn.textContent = `Delete Selected (${checked.length})`;
        } else {
          deleteBtn.textContent = 'Delete Selected';
        }
      }
    }
    
  } catch (error) {
    nhiList.innerHTML = `<p style="color: #f87171;">Error loading NHI credentials: ${error.message || error}</p>`;
  }
}
async function editNhi(nhiId) {
  try {
    // No password required - uses FS_SERVER_SECRET
    const getRes = await api(`/nhi/get/${nhiId}`);
    if (!getRes.ok) {
      const errorText = await getRes.text().catch(() => 'Unknown error');
      showStatus(`Failed to retrieve NHI credential: ${errorText}`);
      return;
    }
    
    const nhiData = await getRes.json();
    if (!nhiData) {
      showStatus('Invalid NHI credential data received');
      return;
    }
    
    // Set edit mode
    editingNhiId = nhiId;
    
    // Populate form with NHI data
    el('nhiName').value = nhiData.name || '';
    el('nhiClientId').value = nhiData.client_id || '';
    // Client secret is not displayed when editing - user can optionally update it
    const clientSecretInput = el('nhiClientSecret');
    if (clientSecretInput) {
      clientSecretInput.value = '';
      clientSecretInput.disabled = false;
      clientSecretInput.placeholder = 'Leave empty to keep existing, or enter new secret';
    }
    
    // Populate fabric hosts field with hosts that have tokens
    const fabricHostsInput = el('nhiFabricHosts');
    if (fabricHostsInput && nhiData.hosts_with_tokens && Array.isArray(nhiData.hosts_with_tokens)) {
      const hosts = nhiData.hosts_with_tokens.sort();
      fabricHostsInput.value = hosts.join(' ');
    } else if (fabricHostsInput) {
      fabricHostsInput.value = '';
    }
    
    // Switch buttons - show Update, hide Create
    el('btnSaveNhi').style.display = 'none';
    el('btnUpdateNhi').style.display = 'inline-block';
    el('btnCancelNhi').style.display = 'inline-block';
    el('btnUpdateNhi').disabled = false;
    
    // Scroll to form
    document.querySelector('#nhi-management-section h3').scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    showStatus(`NHI credential '${nhiData.name}' loaded for editing. Click Update to save changes.`);
    
    // Update button state
    updateNhiButtons();
  } catch (error) {
    showStatus(`Error loading NHI credential for editing: ${error.message || error}`);
    logMsg(`Error loading NHI credential for editing: ${error.message || error}`);
  }
}

function cancelNhiEdit() {
  editingNhiId = null;
  el('nhiName').value = '';
  el('nhiClientId').value = '';
  const clientSecretInput = el('nhiClientSecret');
  if (clientSecretInput) {
    clientSecretInput.disabled = false;
    clientSecretInput.placeholder = 'Enter client secret (required for new credentials, optional for updates)';
    clientSecretInput.value = '';
  }
  const fabricHostsInput = el('nhiFabricHosts');
  if (fabricHostsInput) fabricHostsInput.value = '';
  
  el('btnSaveNhi').style.display = 'inline-block';
  el('btnUpdateNhi').style.display = 'none';
  el('btnCancelNhi').style.display = 'none';
  
  updateNhiButtons();
}
async function deleteNhi(nhiId) {
  try {
    const res = await api(`/nhi/delete/${nhiId}`, { method: 'DELETE' });
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to delete NHI credential: ${errorText}`);
      return;
    }
    
    showStatus('NHI credential deleted successfully');
    logMsg(`NHI credential ${nhiId} deleted`);
    
    // Clear cache and reload NHI credentials list
    clearNhiCredentialsCache();
    loadNhiCredentials();
    
    // Refresh dropdown in authentication section if it exists
    loadNhiCredentialsForAuth();
  } catch (error) {
    showStatus(`Error deleting NHI credential: ${error.message || error}`);
    logMsg(`Error deleting NHI credential: ${error.message || error}`);
  }
}

// Validate NHI name: alphanumeric, dash, underscore only
function isValidNhiName(name) {
  if (!name) return false;
  // Allow alphanumeric, dash, and underscore only
  const nameRegex = /^[a-zA-Z0-9_-]+$/;
  return nameRegex.test(name);
}

function updateNhiButtons() {
  const saveBtn = el('btnSaveNhi');
  const updateBtn = el('btnUpdateNhi');
  const name = el('nhiName').value.trim();
  const clientId = el('nhiClientId').value.trim();
  const clientSecret = el('nhiClientSecret').value.trim();
  
  // Validate name format
  const nameValid = isValidNhiName(name);
  const nameErrorSpan = el('nhiNameError');
  if (nameErrorSpan) {
    if (name && !nameValid) {
      nameErrorSpan.textContent = 'Name must contain only alphanumeric characters, dashes, and underscores';
      nameErrorSpan.style.display = 'inline';
    } else {
      nameErrorSpan.style.display = 'none';
    }
  }
  
  // For create we require clientSecret; for update we do not (clientSecret is optional)
  const creating = !editingNhiId;
  const requiredFieldsOk = creating
    ? !!(name && clientId && clientSecret)
    : !!(name && clientId);
  const isValid = nameValid && requiredFieldsOk;
  
  if (saveBtn && saveBtn.style.display !== 'none') {
    saveBtn.disabled = !isValid;
  }
  if (updateBtn && updateBtn.style.display !== 'none') {
    updateBtn.disabled = !isValid;
  }
}

// Set up event listeners for NHI form validation
function initNhiFormValidation() {
  const nameInput = el('nhiName');
  const clientIdInput = el('nhiClientId');
  const clientSecretInput = el('nhiClientSecret');
  const encryptionPasswordInput = el('nhiEncryptionPassword');
  const confirmPasswordInput = el('nhiConfirmPassword');
  
  if (nameInput) {
    // Filter input to only allow alphanumeric, dash, underscore
    nameInput.addEventListener('input', (e) => {
      const value = e.target.value;
      const filtered = value.replace(/[^a-zA-Z0-9_-]/g, '');
      if (value !== filtered) {
        e.target.value = filtered;
      }
      updateNhiButtons();
    });
    nameInput.addEventListener('change', updateNhiButtons);
    nameInput.addEventListener('blur', updateNhiButtons);
  }
  
  if (clientIdInput) {
    clientIdInput.addEventListener('input', updateNhiButtons);
    clientIdInput.addEventListener('change', updateNhiButtons);
  }
  
  if (clientSecretInput) {
    clientSecretInput.addEventListener('input', updateNhiButtons);
    clientSecretInput.addEventListener('change', updateNhiButtons);
  }
  
  // Password fields removed - no longer needed
  
  // Initial check
  updateNhiButtons();
}

// Set up NHI Management button handlers
function setupNhiButtons() {
  const saveBtn = el('btnSaveNhi');
  if (saveBtn && !saveBtn.onclick) {
    saveBtn.onclick = async () => {
      const name = el('nhiName').value.trim();
      const clientId = el('nhiClientId').value.trim();
      const clientSecret = el('nhiClientSecret').value.trim();
      
      if (!name || !clientId || !clientSecret) {
        showStatus('Please fill in name, client ID, and client secret');
        return;
      }
      
      // Validate name format
      if (!isValidNhiName(name)) {
        showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
        return;
      }
      
      try {
        // Get FabricStudio hosts from input field
        const fabricHostsInput = el('nhiFabricHosts');
        const fabricHosts = fabricHostsInput ? fabricHostsInput.value.trim() : '';
        
        const payload = {
          name: name,
          client_id: clientId,
          client_secret: clientSecret
        };
        // Only include fabric_hosts if provided
        if (fabricHosts) {
          payload.fabric_hosts = fabricHosts;
        }
        
        const res = await api('/nhi/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
    
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to save NHI credential: ${errorText}`);
      return;
    }
    
    const data = await res.json();
    
    // Check for token retrieval errors
    if (data.token_errors && Array.isArray(data.token_errors) && data.token_errors.length > 0) {
      // Display error messages for failed token retrievals
      const errorMsg = data.token_errors.filter(e => e && e.trim()).join('\n');
      if (errorMsg) {
        const fullMessage = `NHI credential saved, but token retrieval failed:\n${errorMsg}`;
        // Use NHI-specific status element
        showNhiStatus(fullMessage, { error: true });
        showStatus(fullMessage, { error: true });
        logMsg(`NHI credential saved: ${name}, but token errors: ${errorMsg}`);
      } else {
        showNhiStatus(data.message || 'NHI credential saved successfully');
    showStatus(data.message || 'NHI credential saved successfully');
    logMsg(`NHI credential saved: ${name}`);
      }
    } else {
      showNhiStatus(data.message || 'NHI credential saved successfully');
      showStatus(data.message || 'NHI credential saved successfully');
      logMsg(`NHI credential saved: ${name}`);
    }
    
    // Clear form
    cancelNhiEdit();
    
    // Clear cache and reload NHI credentials list
    clearNhiCredentialsCache();
    loadNhiCredentials();
    
    // Refresh dropdown in authentication section if it exists
    loadNhiCredentialsForAuth();
  } catch (error) {
    showStatus(`Error saving NHI credential: ${error.message || error}`);
    logMsg(`Error saving NHI credential: ${error.message || error}`);
  }
    };
  }
  
  const updateBtn = el('btnUpdateNhi');
  if (updateBtn && !updateBtn.onclick) {
    updateBtn.onclick = async () => {
      const name = el('nhiName').value.trim();
      const clientId = el('nhiClientId').value.trim();
      const clientSecret = el('nhiClientSecret').value.trim();
      
      if (!editingNhiId) {
        showStatus('No NHI credential selected for editing');
        return;
      }
      
      // For update, only name and clientId are required; clientSecret is optional
      if (!name || !clientId) {
        showStatus('Please fill in name and client ID');
        return;
      }
      
      // Validate name format
      if (!isValidNhiName(name)) {
        showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
        return;
      }
      
      try {
        // Get FabricStudio hosts from input field
        const fabricHostsInput = el('nhiFabricHosts');
        const fabricHosts = fabricHostsInput ? fabricHostsInput.value.trim() : '';
        
        const payload = {
          id: editingNhiId,
          name: name,
          client_id: clientId
        };
        // Only include client_secret if provided (for updates)
        if (clientSecret) {
          payload.client_secret = clientSecret;
        }
        // Only include fabric_hosts if provided
        if (fabricHosts) {
          payload.fabric_hosts = fabricHosts;
        }
        
        const res = await api('/nhi/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
    
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to update NHI credential: ${errorText}`);
      return;
    }
    
    const data = await res.json();
    
    // Check for token retrieval errors
    if (data.token_errors && Array.isArray(data.token_errors) && data.token_errors.length > 0) {
      // Display error messages for failed token retrievals
      const errorMsg = data.token_errors.filter(e => e && e.trim()).join('\n');
      if (errorMsg) {
        const fullMessage = `NHI credential updated, but token retrieval failed:\n${errorMsg}`;
        // Use NHI-specific status element
        showNhiStatus(fullMessage, { error: true });
        showStatus(fullMessage, { error: true });
        logMsg(`NHI credential updated: ${name} (ID: ${editingNhiId}), but token errors: ${errorMsg}`);
      } else {
        showNhiStatus(data.message || 'NHI credential updated successfully');
    showStatus(data.message || 'NHI credential updated successfully');
    logMsg(`NHI credential updated: ${name} (ID: ${editingNhiId})`);
      }
    } else {
      showNhiStatus(data.message || 'NHI credential updated successfully');
      showStatus(data.message || 'NHI credential updated successfully');
      logMsg(`NHI credential updated: ${name} (ID: ${editingNhiId})`);
    }
    
    // Clear form and exit edit mode
    cancelNhiEdit();
    
    // Clear cache and reload NHI credentials list
    clearNhiCredentialsCache();
    loadNhiCredentials();
    
    // Refresh dropdown in authentication section if it exists
    loadNhiCredentialsForAuth();
  } catch (error) {
    showStatus(`Error updating NHI credential: ${error.message || error}`);
    logMsg(`Error updating NHI credential: ${error.message || error}`);
  }
    };
  }
  
  const cancelBtn = el('btnCancelNhi');
  if (cancelBtn && !cancelBtn.onclick) {
    cancelBtn.onclick = () => {
      cancelNhiEdit();
      showStatus('Edit cancelled');
    };
  }
  
  const refreshBtn = el('btnRefreshNhi');
  if (refreshBtn && !refreshBtn.onclick) {
    refreshBtn.onclick = () => {
      loadNhiCredentials();
    };
  }
  
  const deleteBtn = el('btnDeleteNhi');
  if (deleteBtn && !deleteBtn.onclick) {
    deleteBtn.onclick = async () => {
      const selected = document.querySelectorAll('.nhi-checkbox:checked');
      if (selected.length === 0) {
        showStatus('Please select at least one NHI credential to delete');
        return;
      }
      
      if (!confirm(`Are you sure you want to delete ${selected.length} NHI credential(s)?`)) {
        return;
      }
      
      let successCount = 0;
      let failCount = 0;
      
      for (const checkbox of selected) {
        const nhiId = parseInt(checkbox.value);
        try {
          const res = await api(`/nhi/delete/${nhiId}`, { method: 'DELETE' });
          if (res.ok) {
            successCount++;
          } else {
            failCount++;
          }
        } catch (error) {
          failCount++;
        }
      }
      
      if (successCount > 0) {
        showStatus(`Deleted ${successCount} NHI credential(s)${failCount > 0 ? `, ${failCount} failed` : ''}`);
        logMsg(`Deleted ${successCount} NHI credential(s)`);
        loadNhiCredentials();
        
        // Refresh dropdown in authentication section if it exists
        loadNhiCredentialsForAuth();
      } else {
        showStatus(`Failed to delete NHI credentials`);
      }
    };
  }
}

// SSH Keys Management functions
let editingSshKeyId = null;

function isValidSshKeyName(name) {
  return /^[a-zA-Z0-9_-]+$/.test(name);
}

async function loadSshKeys() {
  const sshKeysList = el('sshKeysList');
  if (!sshKeysList) return;
  
  try {
    sshKeysList.innerHTML = '<p>Loading SSH keys...</p>';
    
    const res = await api('/ssh-keys/list');
    if (!res.ok) {
      sshKeysList.innerHTML = `<p style="color: #f87171;">Error loading SSH keys: ${res.statusText}</p>`;
      return;
    }
    
    const data = await res.json();
    const keys = data.keys || [];
    
    if (keys.length === 0) {
      sshKeysList.innerHTML = '<p>No SSH keys found. Use the form above to create one.</p>';
      return;
    }
    
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';
    
    keys.forEach(key => {
      const createdDate = formatDateTime(key.created_at);
      const updatedDate = formatDateTime(key.updated_at);
      // Truncate public key for display (first 50 chars)
      const publicKeyPreview = key.public_key.length > 50 ? key.public_key.substring(0, 50) + '...' : key.public_key;
      
      html += `
        <div class="config-item" data-ssh-key-id="${key.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <label style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">
              <span style="font-size: 16px;">${key.name}</span>
            </label>
            <button class="btn-config-edit ssh-key-edit-btn" data-ssh-key-id="${key.id}" style="padding: 4px 12px; font-size: 12px;">Edit</button>
            <button class="btn-config-delete ssh-key-delete-btn" data-ssh-key-id="${key.id}" style="padding: 4px 12px; font-size: 12px;">Delete</button>
          </div>
          <div style="font-size: 12px; color: #86868b; margin-left: 0; line-height: 1.6;">
            <div style="margin-bottom: 4px;"><strong>Public Key:</strong></div>
            <div style="margin-left: 12px; margin-bottom: 4px; font-family: monospace; font-size: 11px; word-break: break-all;">${publicKeyPreview}</div>
            <div style="margin-bottom: 4px;"><strong>Created:</strong> ${createdDate}</div>
            <div><strong>Updated:</strong> ${updatedDate}</div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    sshKeysList.innerHTML = html;
    
    // Add event listeners for edit buttons
    document.querySelectorAll('.ssh-key-edit-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const sshKeyId = parseInt(btn.getAttribute('data-ssh-key-id'));
        await editSshKey(sshKeyId);
      });
    });
    
    // Add event listeners for delete buttons
    document.querySelectorAll('.ssh-key-delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const sshKeyId = parseInt(btn.getAttribute('data-ssh-key-id'));
        if (confirm('Are you sure you want to delete this SSH key?')) {
          await deleteSshKey(sshKeyId);
        }
      });
    });
    
  } catch (error) {
    sshKeysList.innerHTML = `<p style="color: #f87171;">Error loading SSH keys: ${error.message || error}</p>`;
  }
}

async function editSshKey(sshKeyId) {
  try {
    showStatus(`Loading SSH key for editing...`);
    
    // No password required - uses FS_SERVER_SECRET
    const res = await api(`/ssh-keys/get/${sshKeyId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to load SSH key: ${errorText}`);
      return;
    }
    
    const sshKeyData = await res.json();
    
    // Populate form fields
    el('sshKeyName').value = sshKeyData.name || '';
    el('sshKeyPublic').value = sshKeyData.public_key || '';
    el('sshKeyPrivate').value = ''; // Clear private key field - user can optionally update it
    el('sshKeyPrivate').placeholder = 'Leave empty to keep existing, or enter new private key';
    el('sshKeyPrivate').disabled = false;
    
    editingSshKeyId = sshKeyId;
    
    // Switch buttons - show Update, hide Create
    el('btnSaveSshKey').style.display = 'none';
    el('btnUpdateSshKey').style.display = 'inline-block';
    el('btnCancelSshKey').style.display = 'inline-block';
    el('btnUpdateSshKey').disabled = false;
    
    // Scroll to form
    document.querySelector('#ssh-keys-section h3').scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    showStatus(`SSH key '${sshKeyData.name}' loaded for editing. Click Update to save changes.`);
  } catch (error) {
    showStatus(`Error loading SSH key for editing: ${error.message || error}`);
  }
}

function cancelSshKeyEdit() {
  editingSshKeyId = null;
  
  // Clear form fields
  el('sshKeyName').value = '';
  el('sshKeyPublic').value = '';
  el('sshKeyPrivate').value = '';
  el('sshKeyPrivate').placeholder = 'Enter private key (-----BEGIN OPENSSH PRIVATE KEY-----...)';
  el('sshKeyPrivate').disabled = false;
  // Password field removed - no longer needed
  
  // Hide error messages
  const nameError = el('sshKeyNameError');
  if (nameError) nameError.style.display = 'none';
  
  // Switch buttons - show Create, hide Update
  el('btnSaveSshKey').style.display = 'inline-block';
  el('btnUpdateSshKey').style.display = 'none';
  el('btnCancelSshKey').style.display = 'none';
  
  // Update button states
  updateSshKeyButtons();
}

function updateSshKeyButtons() {
  const saveBtn = el('btnSaveSshKey');
  const updateBtn = el('btnUpdateSshKey');
  const nameInput = el('sshKeyName');
  const publicKeyInput = el('sshKeyPublic');
  const privateKeyInput = el('sshKeyPrivate');
  
  if (!nameInput || !publicKeyInput || !privateKeyInput) return;
  
  const name = nameInput.value.trim();
  const publicKey = publicKeyInput.value.trim();
  const privateKey = privateKeyInput.value.trim();
  
  // Validate name format
  const nameValid = isValidSshKeyName(name);
  const nameError = el('sshKeyNameError');
  if (nameError) {
    if (name && !nameValid) {
      nameError.textContent = 'Name must contain only alphanumeric characters, dashes, and underscores';
      nameError.style.display = 'inline';
    } else {
      nameError.style.display = 'none';
    }
  }
  
  // For create: name, public key, and private key required
  // For update: name and public key required (private key optional)
  const isCreate = !editingSshKeyId;
  const requiredFieldsOk = name && publicKey && (isCreate ? privateKey : true);
  
  const isValid = nameValid && requiredFieldsOk;
  
  if (saveBtn && saveBtn.style.display !== 'none') {
    saveBtn.disabled = !isValid;
  }
  if (updateBtn && updateBtn.style.display !== 'none') {
    updateBtn.disabled = !isValid;
  }
}

function initSshKeyFormValidation() {
  const nameInput = el('sshKeyName');
  const publicKeyInput = el('sshKeyPublic');
  const privateKeyInput = el('sshKeyPrivate');
  const encryptionPasswordInput = el('sshKeyEncryptionPassword');
  
  if (nameInput) {
    nameInput.addEventListener('input', (e) => {
      const value = e.target.value;
      const filtered = value.replace(/[^a-zA-Z0-9_-]/g, '');
      if (value !== filtered) {
        e.target.value = filtered;
      }
      updateSshKeyButtons();
    });
    nameInput.addEventListener('change', updateSshKeyButtons);
    nameInput.addEventListener('blur', updateSshKeyButtons);
  }
  
  if (publicKeyInput) {
    publicKeyInput.addEventListener('input', updateSshKeyButtons);
    publicKeyInput.addEventListener('change', updateSshKeyButtons);
  }
  
  if (privateKeyInput) {
    privateKeyInput.addEventListener('input', updateSshKeyButtons);
    privateKeyInput.addEventListener('change', updateSshKeyButtons);
  }
  
  // Password field removed - no longer needed
  
  // Initial check
  updateSshKeyButtons();
}
function setupSshKeyButtons() {
  const saveBtn = el('btnSaveSshKey');
  if (saveBtn && !saveBtn.onclick) {
    saveBtn.onclick = async () => {
      const name = el('sshKeyName').value.trim();
      const publicKey = el('sshKeyPublic').value.trim();
      const privateKey = el('sshKeyPrivate').value.trim();
      
      if (!name || !publicKey || !privateKey) {
        showStatus('Please fill in name, public key, and private key');
        return;
      }
      
      // Validate name format
      if (!isValidSshKeyName(name)) {
        showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
        return;
      }
      
      try {
        const res = await api('/ssh-keys/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name,
            public_key: publicKey,
            private_key: privateKey
          })
        });
        
        if (!res.ok) {
          const errorText = await res.text().catch(() => 'Unknown error');
          showStatus(`Failed to save SSH key: ${errorText}`);
          return;
        }
        
        const data = await res.json();
        showStatus(data.message || 'SSH key saved successfully');
        
        // Clear form
        cancelSshKeyEdit();
        
        // Reload SSH keys list
        loadSshKeys();
      } catch (error) {
        showStatus(`Error saving SSH key: ${error.message || error}`);
      }
    };
  }
  
  const updateBtn = el('btnUpdateSshKey');
  if (updateBtn && !updateBtn.onclick) {
    updateBtn.onclick = async () => {
      const name = el('sshKeyName').value.trim();
      const publicKey = el('sshKeyPublic').value.trim();
      const privateKey = el('sshKeyPrivate').value.trim();
      if (!editingSshKeyId) {
        showStatus('No SSH key selected for editing');
        return;
      }
      
      if (!name || !publicKey) {
        showStatus('Please fill in name and public key');
        return;
      }
      
      // Validate name format
      if (!isValidSshKeyName(name)) {
        showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
        return;
      }
      
      try {
        const payload = {
          id: editingSshKeyId,
          name: name,
          public_key: publicKey
        };
        
        // Only include private_key if provided (not empty)
        const privateKey = el('sshKeyPrivate').value.trim();
        if (privateKey) {
          payload.private_key = privateKey;
        }
        
        const res = await api('/ssh-keys/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        
        if (!res.ok) {
          const errorText = await res.text().catch(() => 'Unknown error');
          showStatus(`Failed to update SSH key: ${errorText}`);
          return;
        }
        
        const data = await res.json();
        showStatus(data.message || 'SSH key updated successfully');
        
        // Clear form
        cancelSshKeyEdit();
        
        // Reload SSH keys list
        loadSshKeys();
      } catch (error) {
        showStatus(`Error updating SSH key: ${error.message || error}`);
      }
    };
  }
  
  const cancelBtn = el('btnCancelSshKey');
  if (cancelBtn && !cancelBtn.onclick) {
    cancelBtn.onclick = () => {
      cancelSshKeyEdit();
    };
  }
}

async function deleteSshKey(sshKeyId) {
  try {
    const res = await api(`/ssh-keys/delete/${sshKeyId}`, {
      method: 'DELETE'
    });
    
    if (res.ok) {
      const data = await res.json();
      showStatus(data.message || 'SSH key deleted successfully');
      loadSshKeys();
    } else {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to delete SSH key: ${errorText}`);
    }
  } catch (error) {
    showStatus(`Error deleting SSH key: ${error.message || error}`);
  }
}


// SSH Command Profiles Management functions
let editingSshProfileId = null;

function isValidSshProfileName(name) {
  return /^[a-zA-Z0-9_-]+$/.test(name);
}
async function loadSshCommandProfiles() {
  const profilesList = el('sshProfilesList');
  if (!profilesList) return;
  
  try {
    profilesList.innerHTML = '<p>Loading SSH command profiles...</p>';
    
    const res = await api('/ssh-command-profiles/list');
    if (!res.ok) {
      profilesList.innerHTML = `<p style="color: #f87171;">Error loading SSH command profiles: ${res.statusText}</p>`;
      return;
    }
    
    const data = await res.json();
    const profiles = data.profiles || [];
    
    if (profiles.length === 0) {
      profilesList.innerHTML = '<p>No SSH command profiles found. Use the form above to create one.</p>';
      return;
    }
    
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';
    
    profiles.forEach(profile => {
      const createdDate = formatDateTime(profile.created_at);
      const updatedDate = formatDateTime(profile.updated_at);
      // Count number of commands (lines)
      const commandCount = profile.commands.split('\n').filter(c => c.trim()).length;
      // Preview first few commands
      const commandsPreview = profile.commands.split('\n').slice(0, 3).join('\n');
      const hasMore = profile.commands.split('\n').length > 3;
      
      html += `
        <div class="config-item" data-ssh-profile-id="${profile.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <label style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">
              <span style="font-size: 16px;">${profile.name}</span>
            </label>
            <button class="btn-config-run ssh-profile-run-btn" data-ssh-profile-id="${profile.id}" style="padding: 4px 12px; font-size: 12px;">Run</button>
            <button class="btn-config-edit ssh-profile-edit-btn" data-ssh-profile-id="${profile.id}" style="padding: 4px 12px; font-size: 12px;">Edit</button>
            <button class="btn-config-delete ssh-profile-delete-btn" data-ssh-profile-id="${profile.id}" style="padding: 4px 12px; font-size: 12px;">Delete</button>
          </div>
          <div style="font-size: 12px; color: #86868b; margin-left: 0; line-height: 1.6;">
            ${profile.description ? `<div style="margin-bottom: 4px;"><strong>Description:</strong> ${profile.description}</div>` : ''}
            ${profile.ssh_key_name ? `<div style="margin-bottom: 4px;"><strong>SSH Key Pair:</strong> ${profile.ssh_key_name}</div>` : ''}
            <div style="margin-bottom: 4px;"><strong>Commands:</strong> ${commandCount} command(s)</div>
            <div style="margin-left: 12px; margin-bottom: 4px; font-family: monospace; font-size: 11px; white-space: pre-wrap; background: #1d1d1f; color: #ffffff; padding: 8px; border-radius: 4px; max-height: 100px; overflow-y: auto;">${commandsPreview}${hasMore ? '\n...' : ''}</div>
            <div style="margin-bottom: 4px;"><strong>Created:</strong> ${createdDate}</div>
            <div><strong>Updated:</strong> ${updatedDate}</div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    profilesList.innerHTML = html;
    
    // Add event listeners for edit buttons
    document.querySelectorAll('.ssh-profile-edit-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const profileId = parseInt(btn.getAttribute('data-ssh-profile-id'));
        await editSshCommandProfile(profileId);
      });
    });
    
    // Add event listeners for delete buttons
    document.querySelectorAll('.ssh-profile-delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const profileId = parseInt(btn.getAttribute('data-ssh-profile-id'));
        if (confirm('Are you sure you want to delete this SSH command profile?')) {
          await deleteSshCommandProfile(profileId);
        }
      });
    });
    
    // Add event listeners for run buttons
    document.querySelectorAll('.ssh-profile-run-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const profileId = parseInt(btn.getAttribute('data-ssh-profile-id'));
        await runSshCommandProfile(profileId);
      });
    });
    
  } catch (error) {
    profilesList.innerHTML = `<p style="color: #f87171;">Error loading SSH command profiles: ${error.message || error}</p>`;
  }
}
async function editSshCommandProfile(profileId) {
  try {
    showStatus(`Loading SSH command profile for editing...`);
    
    const res = await api(`/ssh-command-profiles/get/${profileId}`);
    
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to load SSH command profile: ${errorText}`);
      return;
    }
    
    const profileData = await res.json();
    
    // Populate form fields
    el('sshProfileName').value = profileData.name || '';
    el('sshProfileDescription').value = profileData.description || '';
    el('sshProfileCommands').value = profileData.commands || '';
    
    // Set SSH key selection
    const sshKeySelect = el('sshProfileSshKeyId');
    if (sshKeySelect) {
      sshKeySelect.value = profileData.ssh_key_id || '';
    }
    
    editingSshProfileId = profileId;
    
    // Switch buttons - show Update, hide Create
    el('btnSaveSshProfile').style.display = 'none';
    el('btnUpdateSshProfile').style.display = 'inline-block';
    el('btnCancelSshProfile').style.display = 'inline-block';
    el('btnUpdateSshProfile').disabled = false;
    
    // Scroll to form
    document.querySelector('#ssh-command-profiles-section h3').scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    showStatus(`SSH command profile '${profileData.name}' loaded for editing. Click Update to save changes.`);
  } catch (error) {
    showStatus(`Error loading SSH command profile for editing: ${error.message || error}`);
  }
}

function cancelSshCommandProfileEdit() {
  editingSshProfileId = null;
  
  // Clear form fields
  el('sshProfileName').value = '';
  el('sshProfileDescription').value = '';
  el('sshProfileCommands').value = '';
  
  // Clear SSH key selection
  const sshKeySelect = el('sshProfileSshKeyId');
  if (sshKeySelect) {
    sshKeySelect.value = '';
  }
  
  // Hide error messages
  const nameError = el('sshProfileNameError');
  if (nameError) nameError.style.display = 'none';
  
  // Switch buttons - show Create, hide Update
  el('btnSaveSshProfile').style.display = 'inline-block';
  el('btnUpdateSshProfile').style.display = 'none';
  el('btnCancelSshProfile').style.display = 'none';
  
  // Update button states
  updateSshCommandProfileButtons();
}

function updateSshCommandProfileButtons() {
  const saveBtn = el('btnSaveSshProfile');
  const updateBtn = el('btnUpdateSshProfile');
  const nameInput = el('sshProfileName');
  const commandsInput = el('sshProfileCommands');
  
  if (!nameInput || !commandsInput) return;
  
  const name = nameInput.value.trim();
  const commands = commandsInput.value.trim();
  
  // Validate name format
  const nameValid = isValidSshProfileName(name);
  const nameError = el('sshProfileNameError');
  if (nameError) {
    if (name && !nameValid) {
      nameError.textContent = 'Name must contain only alphanumeric characters, dashes, and underscores';
      nameError.style.display = 'inline';
    } else {
      nameError.style.display = 'none';
    }
  }
  
  // Both name and commands are required
  const isValid = nameValid && name && commands;
  
  if (saveBtn && saveBtn.style.display !== 'none') {
    saveBtn.disabled = !isValid;
  }
  if (updateBtn && updateBtn.style.display !== 'none') {
    updateBtn.disabled = !isValid;
  }
}

function initSshCommandProfileFormValidation() {
  const nameInput = el('sshProfileName');
  const commandsInput = el('sshProfileCommands');
  
  if (nameInput) {
    nameInput.addEventListener('input', (e) => {
      const value = e.target.value;
      const filtered = value.replace(/[^a-zA-Z0-9_-]/g, '');
      if (value !== filtered) {
        e.target.value = filtered;
      }
      updateSshCommandProfileButtons();
    });
    nameInput.addEventListener('change', updateSshCommandProfileButtons);
    nameInput.addEventListener('blur', updateSshCommandProfileButtons);
  }
  
  if (commandsInput) {
    commandsInput.addEventListener('input', updateSshCommandProfileButtons);
    commandsInput.addEventListener('change', updateSshCommandProfileButtons);
  }
  
  // Load SSH keys for the dropdown
  loadSshKeysForProfile();
  
  // Initial check
  updateSshCommandProfileButtons();
}

async function loadSshKeysForProfile() {
  const sshKeySelect = el('sshProfileSshKeyId');
  if (!sshKeySelect) return;
  
  try {
    const res = await api('/ssh-keys/list');
    if (!res.ok) {
      return;
    }
    
    const data = await res.json();
    const keys = data.keys || [];
    
    // Clear existing options except the first one
    sshKeySelect.innerHTML = '<option value="">None (select SSH key pair)</option>';
    
    // Add SSH keys to dropdown
    keys.forEach(key => {
      const option = document.createElement('option');
      option.value = key.id;
      option.textContent = key.name;
      sshKeySelect.appendChild(option);
    });
  } catch (error) {
  }
}

function setupSshCommandProfileButtons() {
  const saveBtn = el('btnSaveSshProfile');
  if (saveBtn && !saveBtn.onclick) {
    saveBtn.onclick = async () => {
      const name = el('sshProfileName').value.trim();
      const description = el('sshProfileDescription').value.trim();
      const commands = el('sshProfileCommands').value.trim();
      const sshKeyId = el('sshProfileSshKeyId').value ? parseInt(el('sshProfileSshKeyId').value) : null;
      
      if (!name || !commands) {
        showStatus('Please fill in name and commands');
        return;
      }
      
      // Validate name format
      if (!isValidSshProfileName(name)) {
        showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
        return;
      }
      
      try {
        const res = await api('/ssh-command-profiles/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name,
            description: description || null,
            commands: commands,
            ssh_key_id: sshKeyId
          })
        });
        
        if (!res.ok) {
          const errorText = await res.text().catch(() => 'Unknown error');
          showStatus(`Failed to save SSH command profile: ${errorText}`);
          return;
        }
        
        const data = await res.json();
        showStatus(data.message || 'SSH command profile saved successfully');
        
        // Clear form
        cancelSshCommandProfileEdit();
        
        // Reload profiles list
        clearSshProfilesCache();
      loadSshCommandProfiles();
      } catch (error) {
        showStatus(`Error saving SSH command profile: ${error.message || error}`);
      }
    };
  }
  
  const updateBtn = el('btnUpdateSshProfile');
  if (updateBtn && !updateBtn.onclick) {
    updateBtn.onclick = async () => {
      const name = el('sshProfileName').value.trim();
      const description = el('sshProfileDescription').value.trim();
      const commands = el('sshProfileCommands').value.trim();
      const sshKeyId = el('sshProfileSshKeyId').value ? parseInt(el('sshProfileSshKeyId').value) : null;
      
      if (!editingSshProfileId) {
        showStatus('No SSH command profile selected for editing');
        return;
      }
      
      if (!name || !commands) {
        showStatus('Please fill in name and commands');
        return;
      }
      
      // Validate name format
      if (!isValidSshProfileName(name)) {
        showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
        return;
      }
      
      try {
        const res = await api('/ssh-command-profiles/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: editingSshProfileId,
            name: name,
            description: description || null,
            commands: commands,
            ssh_key_id: sshKeyId
          })
        });
        
        if (!res.ok) {
          const errorText = await res.text().catch(() => 'Unknown error');
          showStatus(`Failed to update SSH command profile: ${errorText}`);
          return;
        }
        
        const data = await res.json();
        showStatus(data.message || 'SSH command profile updated successfully');
        
        // Clear form
        cancelSshCommandProfileEdit();
        
        // Reload profiles list
        clearSshProfilesCache();
      loadSshCommandProfiles();
      } catch (error) {
        showStatus(`Error updating SSH command profile: ${error.message || error}`);
      }
    };
  }
  
  const cancelBtn = el('btnCancelSshProfile');
  if (cancelBtn && !cancelBtn.onclick) {
    cancelBtn.onclick = () => {
      cancelSshCommandProfileEdit();
    };
  }
}

async function deleteSshCommandProfile(profileId) {
  try {
    const res = await api(`/ssh-command-profiles/delete/${profileId}`, {
      method: 'DELETE'
    });
    
    if (res.ok) {
      const data = await res.json();
      showStatus(data.message || 'SSH command profile deleted successfully');
      clearSshProfilesCache();
      loadSshCommandProfiles();
    } else {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to delete SSH command profile: ${errorText}`);
    }
  } catch (error) {
    showStatus(`Error deleting SSH command profile: ${error.message || error}`);
  }
}
// Custom dialog for SSH profile execution
async function promptSshProfileExecution(profileId, profileName, commandCount) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(0,0,0,0.4)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '9999';

    const dialog = document.createElement('div');
    dialog.style.background = 'white';
    dialog.style.border = '1px solid #d2d2d7';
    dialog.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)';
    dialog.style.width = '500px';
    dialog.style.maxWidth = '90%';
    dialog.style.padding = '20px';
    dialog.style.borderRadius = '0';

    const title = document.createElement('div');
    title.textContent = `Execute SSH Profile: ${profileName}`;
    title.style.fontWeight = '600';
    title.style.marginBottom = '16px';
    title.style.color = '#1d1d1f';
    title.style.fontSize = '16px';
    dialog.appendChild(title);

    const info = document.createElement('div');
    info.textContent = `Commands: ${commandCount} command(s)`;
    info.style.marginBottom = '16px';
    info.style.color = '#86868b';
    info.style.fontSize = '13px';
    dialog.appendChild(info);

    // NHI Credential selection
    const nhiLabel = document.createElement('label');
    nhiLabel.textContent = 'NHI Credential (optional):';
    nhiLabel.style.display = 'block';
    nhiLabel.style.marginBottom = '6px';
    nhiLabel.style.color = '#424245';
    nhiLabel.style.fontSize = '13px';
    nhiLabel.style.fontWeight = '500';
    dialog.appendChild(nhiLabel);

    const nhiSelect = document.createElement('select');
    nhiSelect.id = 'sshExecNhiSelect';
    nhiSelect.style.width = '100%';
    nhiSelect.style.boxSizing = 'border-box';
    nhiSelect.style.margin = '0 0 16px 0';
    nhiSelect.style.padding = '6px 10px';
    nhiSelect.style.border = '1px solid #d2d2d7';
    nhiSelect.style.minHeight = '32px';
    nhiSelect.style.fontSize = '13px';
    nhiSelect.style.color = '#1d1d1f';
    nhiSelect.innerHTML = '<option value="">None (enter host manually)</option>';
    dialog.appendChild(nhiSelect);

    // Load NHI credentials
    (async () => {
      try {
        const res = await api('/nhi/list');
        if (res.ok) {
          const data = await res.json();
          const credentials = data.credentials || [];
          credentials.forEach(cred => {
            const option = document.createElement('option');
            option.value = cred.id;
            option.textContent = `${cred.name} (${cred.hosts_with_tokens?.length || 0} host(s))`;
            nhiSelect.appendChild(option);
          });
        }
      } catch (error) {
        // Ignore errors
      }
    })();

    // Host input (shown when NHI not selected)
    const hostLabel = document.createElement('label');
    hostLabel.textContent = 'Hostname or IP:';
    hostLabel.style.display = 'block';
    hostLabel.style.marginBottom = '6px';
    hostLabel.style.color = '#424245';
    hostLabel.style.fontSize = '13px';
    hostLabel.style.fontWeight = '500';
    dialog.appendChild(hostLabel);

    const hostInput = document.createElement('input');
    hostInput.id = 'sshExecHostInput';
    hostInput.type = 'text';
    hostInput.placeholder = 'Enter hostname or IP address';
    hostInput.style.width = '100%';
    hostInput.style.boxSizing = 'border-box';
    hostInput.style.margin = '0 0 16px 0';
    hostInput.style.padding = '6px 10px';
    hostInput.style.border = '1px solid #d2d2d7';
    hostInput.style.minHeight = '32px';
    hostInput.style.fontSize = '13px';
    hostInput.style.color = '#1d1d1f';
    dialog.appendChild(hostInput);

    // Hosts display (shown when NHI selected)
    const hostsDisplay = document.createElement('div');
    hostsDisplay.id = 'sshExecHostsDisplay';
    hostsDisplay.style.display = 'none';
    hostsDisplay.style.marginBottom = '16px';
    dialog.appendChild(hostsDisplay);

    // Hosts chips container
    const hostsChipsContainer = document.createElement('div');
    hostsChipsContainer.id = 'sshExecHostsChips';
    hostsChipsContainer.style.display = 'none';
    hostsChipsContainer.style.flexWrap = 'wrap';
    hostsChipsContainer.style.gap = '6px';
    hostsChipsContainer.style.marginTop = '8px';
    hostsChipsContainer.style.minHeight = '32px';
    hostsDisplay.appendChild(hostsChipsContainer);

    // Selected hosts array
    let selectedHosts = [];

    // Function to render host chips
    const renderHostChips = () => {
      hostsChipsContainer.innerHTML = '';
      if (selectedHosts.length === 0) {
        hostsChipsContainer.style.display = 'none';
        return;
      }
      hostsChipsContainer.style.display = 'flex';
      
      selectedHosts.forEach((hostInfo, index) => {
        const host = typeof hostInfo === 'string' ? hostInfo : hostInfo.host;
        const port = typeof hostInfo === 'object' ? (hostInfo.port || 22) : 22;
        const entry = host + (port !== 22 ? ':' + port : '');
        
        const chip = document.createElement('div');
        chip.className = 'host-chip valid';
        
        const chipText = document.createElement('span');
        chipText.className = 'chip-text';
        chipText.textContent = entry;
        chip.appendChild(chipText);
        
        const chipDelete = document.createElement('button');
        chipDelete.className = 'chip-delete';
        chipDelete.textContent = '×';
        chipDelete.type = 'button';
        chipDelete.title = 'Remove host';
        chipDelete.addEventListener('click', () => {
          selectedHosts.splice(index, 1);
          renderHostChips();
          updateConfirmButton();
        });
        chip.appendChild(chipDelete);
        
        hostsChipsContainer.appendChild(chip);
      });
    };

    // Update hosts display when NHI credential changes - automatically load hosts
    nhiSelect.addEventListener('change', async () => {
      const nhiId = nhiSelect.value;
      hostsConfirmed = false; // Reset confirmation when credential changes
      if (nhiId) {
        hostInput.style.display = 'none';
        hostLabel.style.display = 'none';
        hostsDisplay.style.display = 'block';
        hostsDisplay.innerHTML = '<div style="font-size: 12px; color: #86868b; margin-bottom: 8px;">Loading hosts from NHI credential...</div>';
        hostsDisplay.appendChild(hostsChipsContainer);
        hostsDisplay.setAttribute('data-nhi-id', nhiId);
        selectedHosts = [];
        renderHostChips();
        
        // Automatically load hosts without password
        executeBtn.disabled = true;
        executeBtn.textContent = 'Loading hosts...';
        executeBtn.style.opacity = '0.5';
        executeBtn.style.cursor = 'not-allowed';
        
        try {
          const nhiRes = await api(`/nhi/get/${nhiId}`);
          
          if (!nhiRes.ok) {
            const errorText = await nhiRes.text().catch(() => 'Unknown error');
            hostsDisplay.innerHTML = `<div style="font-size: 12px; color: #dc2626; margin-bottom: 8px;">Failed to load hosts: ${errorText}</div>`;
            hostsDisplay.appendChild(hostsChipsContainer);
            executeBtn.disabled = false;
            executeBtn.textContent = 'Execute';
            executeBtn.style.opacity = '1';
            executeBtn.style.cursor = 'pointer';
            return;
          }
          
          const nhiData = await nhiRes.json();
          const hostsList = nhiData.hosts_with_tokens || [];
          
          if (hostsList.length === 0) {
            hostsDisplay.innerHTML = '<div style="font-size: 12px; color: #dc2626; margin-bottom: 8px;">No hosts found in this NHI credential</div>';
            hostsDisplay.appendChild(hostsChipsContainer);
            executeBtn.disabled = false;
            executeBtn.textContent = 'Execute';
            executeBtn.style.opacity = '1';
            executeBtn.style.cursor = 'pointer';
            return;
          }
          
          // Populate selected hosts and render chips
          selectedHosts = hostsList.map(h => ({ host: h, port: 22 }));
          renderHostChips();
          updateConfirmButton();
          
          hostsDisplay.innerHTML = `<div style="font-size: 12px; color: #10b981; margin-bottom: 8px;">Loaded ${hostsList.length} host(s). Review and confirm:</div>`;
          hostsDisplay.appendChild(hostsChipsContainer);
          
          executeBtn.disabled = true;
          executeBtn.textContent = 'Execute';
          executeBtn.style.opacity = '0.5';
          executeBtn.style.cursor = 'not-allowed';
        } catch (error) {
          hostsDisplay.innerHTML = `<div style="font-size: 12px; color: #dc2626; margin-bottom: 8px;">Error loading hosts: ${error.message || error}</div>`;
          hostsDisplay.appendChild(hostsChipsContainer);
          executeBtn.disabled = false;
          executeBtn.textContent = 'Execute';
          executeBtn.style.opacity = '1';
          executeBtn.style.cursor = 'pointer';
        }
      } else {
        hostInput.style.display = 'block';
        hostLabel.style.display = 'block';
        hostsDisplay.style.display = 'none';
        hostsDisplay.removeAttribute('data-nhi-id');
        selectedHosts = [];
        renderHostChips();
        executeBtn.disabled = false; // Enable execute for manual host entry
        executeBtn.textContent = 'Execute';
        executeBtn.style.opacity = '1';
        executeBtn.style.cursor = 'pointer';
      }
      updateConfirmButton();
    });

    // Password input
    // Password field removed - no longer needed (uses FS_SERVER_SECRET)

    const errorDiv = document.createElement('div');
    errorDiv.id = 'sshExecError';
    errorDiv.style.display = 'none';
    errorDiv.style.marginBottom = '12px';
    errorDiv.style.padding = '8px';
    errorDiv.style.background = '#fee';
    errorDiv.style.border = '1px solid #f87171';
    errorDiv.style.borderRadius = '4px';
    errorDiv.style.fontSize = '12px';
    errorDiv.style.color = '#dc2626';
    dialog.appendChild(errorDiv);

    // Confirm button (shown after hosts are loaded)
    const confirmBtn = document.createElement('button');
    confirmBtn.id = 'sshExecConfirmBtn';
    confirmBtn.textContent = 'Confirm Hosts';
    confirmBtn.style.padding = '6px 16px';
    confirmBtn.style.border = 'none';
    confirmBtn.style.background = '#10b981';
    confirmBtn.style.color = 'white';
    confirmBtn.style.cursor = 'pointer';
    confirmBtn.style.fontSize = '13px';
    confirmBtn.style.display = 'none';
    confirmBtn.style.marginBottom = '12px';
    confirmBtn.style.width = '100%';
    
    let hostsConfirmed = false;
    
    const updateConfirmButton = () => {
      if (nhiSelect.value && selectedHosts.length > 0 && !hostsConfirmed) {
        confirmBtn.style.display = 'block';
      } else {
        confirmBtn.style.display = 'none';
      }
    };
    
    confirmBtn.onclick = () => {
      if (selectedHosts.length === 0) {
        errorDiv.textContent = 'Please select at least one host';
        errorDiv.style.display = 'block';
        return;
      }
      hostsConfirmed = true;
      confirmBtn.style.display = 'none';
      errorDiv.style.display = 'none';
      executeBtn.disabled = false;
      executeBtn.style.opacity = '1';
      executeBtn.style.cursor = 'pointer';
    };
    
    dialog.appendChild(confirmBtn);

    // Buttons
    const buttonContainer = document.createElement('div');
    buttonContainer.style.display = 'flex';
    buttonContainer.style.gap = '8px';
    buttonContainer.style.justifyContent = 'flex-end';

    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.style.padding = '6px 16px';
    cancelBtn.style.border = '1px solid #d2d2d7';
    cancelBtn.style.background = 'white';
    cancelBtn.style.color = '#1d1d1f';
    cancelBtn.style.cursor = 'pointer';
    cancelBtn.style.fontSize = '13px';
    cancelBtn.onclick = () => {
      document.body.removeChild(overlay);
      resolve(null);
    };
    buttonContainer.appendChild(cancelBtn);

    const executeBtn = document.createElement('button');
    executeBtn.textContent = 'Execute';
    executeBtn.style.padding = '6px 16px';
    executeBtn.style.border = 'none';
    executeBtn.style.background = '#0071e3';
    executeBtn.style.color = 'white';
    executeBtn.style.cursor = 'pointer';
    executeBtn.style.fontSize = '13px';
    executeBtn.disabled = false; // Will be disabled if NHI credential is selected
    executeBtn.style.opacity = executeBtn.disabled ? '0.5' : '1';
    executeBtn.style.cursor = executeBtn.disabled ? 'not-allowed' : 'pointer';
    executeBtn.onclick = async () => {
      const nhiId = nhiSelect.value;
      const host = hostInput.value.trim();
      
      let hosts = [];
      
      // If NHI credential is selected, check if hosts are already loaded and confirmed
      if (nhiId) {
        if (!hostsConfirmed || selectedHosts.length === 0) {
          errorDiv.textContent = 'Please confirm the loaded hosts before executing';
          errorDiv.style.display = 'block';
          return;
        } else {
          // Hosts already confirmed, use selected hosts
          hosts = selectedHosts.map(h => ({ host: typeof h === 'string' ? h : h.host, port: typeof h === 'object' ? (h.port || 22) : 22 }));
        }
      } else {
        if (!host) {
          errorDiv.textContent = 'Please enter a hostname or select an NHI credential';
          errorDiv.style.display = 'block';
          return;
        }
        hosts = [{ host, port: 22 }];
      }
      
      // No password needed - uses FS_SERVER_SECRET
      document.body.removeChild(overlay);
      resolve({
        nhi_credential_id: nhiId ? parseInt(nhiId) : null,
        hosts: hosts
      });
    };
    buttonContainer.appendChild(executeBtn);

    dialog.appendChild(buttonContainer);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Focus on first input
    setTimeout(() => {
      hostInput.focus();
    }, 100);
  });
}
// Run SSH command profile manually
async function runSshCommandProfile(profileId) {
  try {
    // Get profile details first
    const profile = await getSshProfileDetailsById(profileId);
    if (!profile) {
      showStatus('SSH command profile not found', { error: true });
      return;
    }
    
    if (!profile.ssh_key_id) {
      showStatus('This SSH command profile does not have an SSH key pair assigned', { error: true });
      return;
    }
    
    const commandCount = profile.commands.split('\n').filter(c => c.trim()).length;
    
    // Show custom dialog
    const execData = await promptSshProfileExecution(profileId, profile.name, commandCount);
    if (!execData) {
      return; // User cancelled
    }
    
    const { nhi_credential_id, hosts } = execData;
    
    // Execute SSH profile on all hosts
    showStatus(`Executing SSH profile '${profile.name}' on ${hosts.length} host(s)...`);
    
    const results = [];
    for (const hostInfo of hosts) {
      const host = typeof hostInfo === 'string' ? hostInfo : hostInfo.host;
      const port = typeof hostInfo === 'object' ? (hostInfo.port || 22) : 22;
      
      try {
        showStatus(`Executing SSH profile '${profile.name}' on ${host}...`);
        
        const executeRes = await api('/ssh-profiles/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fabric_host: host,
            ssh_profile_id: profileId,
            ssh_port: port,
            nhi_credential_id: nhi_credential_id,
            wait_time_seconds: 0  // No wait time for manual execution
          }),
          timeout: 600000 // 10 minutes timeout for manual SSH execution (no wait time, but commands can take time)
        });
        
        if (!executeRes.ok) {
          const errorText = await executeRes.text().catch(() => 'Unknown error');
          results.push({ host, success: false, error: errorText });
          continue;
        }
        
        const executeData = await executeRes.json();
        results.push({
          host,
          success: executeData.success,
          output: executeData.output,
          error: executeData.error
        });
      } catch (error) {
        results.push({ host, success: false, error: error.message || error });
      }
    }
    
    // Display results
    const successCount = results.filter(r => r.success).length;
    const failCount = results.length - successCount;
    
    let message = `SSH profile '${profile.name}' execution completed:\n`;
    message += `✓ Success: ${successCount} host(s)\n`;
    if (failCount > 0) {
      message += `✗ Failed: ${failCount} host(s)\n`;
    }
    message += '\n';
    
    results.forEach(result => {
      if (result.success) {
        message += `✓ ${result.host}: Success\n`;
        if (result.output) {
          message += `  Output: ${result.output.substring(0, 200)}${result.output.length > 200 ? '...' : ''}\n`;
        }
      } else {
        message += `✗ ${result.host}: ${result.error || 'Unknown error'}\n`;
        if (result.output) {
          message += `  Output: ${result.output.substring(0, 200)}${result.output.length > 200 ? '...' : ''}\n`;
        }
      }
    });
    
    if (successCount === results.length) {
      await alertStyled('SSH Execution Success', message, false);
      showStatus(`SSH profile '${profile.name}' executed successfully on all ${results.length} host(s)`);
    } else {
      await alertStyled('SSH Execution Completed', message, failCount > 0);
      showStatus(`SSH profile '${profile.name}' executed on ${successCount}/${results.length} host(s)`, failCount > 0 ? { error: true } : {});
    }
  } catch (error) {
    showStatus(`Error running SSH command profile: ${error.message || error}`, { error: true });
  }
}
// Load SSH profiles for preparation section dropdown
// Cache for SSH profiles to avoid duplicate calls
let _sshProfilesCache = null;
let _sshProfilesLoading = null;

async function getSshProfileDetailsById(profileId) {
  const parsedId = parseInt(profileId, 10);
  if (!parsedId) {
    return null;
  }

  if (_sshProfilesCache) {
    const cachedProfile = _sshProfilesCache.find(p => parseInt(p.id, 10) === parsedId);
    if (cachedProfile && typeof cachedProfile.commands === 'string') {
      return cachedProfile;
    }
  }

  try {
    const res = await api(`/ssh-command-profiles/get/${parsedId}`);
    if (!res.ok) {
      return null;
    }
    return await res.json();
  } catch (error) {
    return null;
  }
}

async function loadSshProfilesForPreparation() {
  const sshProfileSelect = el('sshProfileSelect');
  if (!sshProfileSelect) return;
  
  // If already loading, wait for that request
  if (_sshProfilesLoading) {
    await _sshProfilesLoading;
    if (_sshProfilesCache) {
      populateSshProfilesDropdown(sshProfileSelect, _sshProfilesCache);
      return;
    }
  }
  
  // If we have cached data, use it
  if (_sshProfilesCache) {
    populateSshProfilesDropdown(sshProfileSelect, _sshProfilesCache);
    return;
  }
  
  // Load profiles
  _sshProfilesLoading = (async () => {
    try {
      const res = await api('/ssh-command-profiles/list');
      if (!res.ok) {
        return;
      }
      
      const data = await res.json();
      const profiles = data.profiles || [];
      _sshProfilesCache = profiles;
      populateSshProfilesDropdown(sshProfileSelect, profiles);
    } catch (error) {
      // Silent failure
    } finally {
      _sshProfilesLoading = null;
    }
  })();
  
  await _sshProfilesLoading;
}

function populateSshProfilesDropdown(select, profiles) {
  // Clear existing options except the first one
  select.innerHTML = '<option value="">None (select SSH profile)</option>';
  
  // Add SSH profiles to dropdown
  profiles.forEach(profile => {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = profile.name;
    select.appendChild(option);
  });
}

// Clear SSH profiles cache (call after save/delete/update)
function clearSshProfilesCache() {
  _sshProfilesCache = null;
  _requestCache.clear(); // Clear API cache for /ssh-command-profiles/list
}

// Execute SSH profiles on all hosts
async function executeSshProfiles(hosts, sshProfileId, waitTimeSeconds = 60) {
  const results = [];
  
  // Calculate timeout based on SSH operation requirements:
  // - Connection timeout: 30 seconds
  // - Command execution: up to 5 minutes (300 seconds) per command
  // - Wait time between commands: waitTimeSeconds
  // - Add buffer: 30 seconds
  // We need to fetch the profile first to know the number of commands
  let numCommands = 1; // Default to 1 command if we can't determine
  try {
    const profileRes = await api(`/ssh-command-profiles/get/${sshProfileId}`);
    if (profileRes.ok) {
      const profileData = await profileRes.json();
      if (profileData.commands) {
        const commandList = profileData.commands.split('\n').filter(cmd => cmd.trim());
        numCommands = Math.max(1, commandList.length);
      }
    }
  } catch (error) {
    // If we can't fetch the profile, use default
    console.warn('Could not fetch SSH profile to calculate timeout, using default:', error);
  }
  
  // Calculate timeout: connection (30s) + (commands * 300s) + (wait * commands) + buffer (30s)
  // Note: Wait time is applied after each command, including the last one
  const connectionTimeout = 30000; // 30 seconds
  const commandTimeout = 300000; // 5 minutes per command
  const waitTimeout = (waitTimeSeconds || 0) * 1000 * numCommands; // Wait after each command
  const buffer = 30000; // 30 seconds buffer
  const calculatedTimeout = connectionTimeout + (numCommands * commandTimeout) + waitTimeout + buffer;
  
  // Cap at 30 minutes maximum
  const timeout = Math.min(calculatedTimeout, 1800000);
  
  for (const {host, port} of hosts) {
    try {
      const res = await api('/ssh-profiles/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fabric_host: host,
            ssh_profile_id: parseInt(sshProfileId),
            ssh_port: port || 22,
            wait_time_seconds: waitTimeSeconds || 0
          }),
        timeout: timeout // Use calculated timeout
      });
      
      if (!res.ok) {
        const errorText = await res.text().catch(() => 'Unknown error');
        logMsg(`SSH profile execution failed on ${host}: ${errorText}`);
        results.push({ host, success: false, error: errorText });
        continue;
      }
      
      const data = await res.json();
      if (data.success) {
        results.push({ host, success: true, output: data.output });
      } else {
        results.push({ host, success: false, error: data.error || 'Unknown error', output: data.output });
      }
    } catch (error) {
      logMsg(`Error executing SSH profile on ${host}: ${error.message || error}`);
      results.push({ host, success: false, error: error.message || error });
    }
  }
  
  return results;
}

// Audit Logs Management functions
let currentFilters = { action: '', user: '', date_from: '', date_to: '' };

function setupAuditLogsButtons() {
  const refreshBtn = el('btnRefreshAuditLogs');
  const exportBtn = el('btnExportLogs');
  const applyFilterBtn = el('btnApplyFilter');
  const clearFilterBtn = el('btnClearFilter');
  
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      loadAuditLogs();
    });
  }
  
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      exportAuditLogs();
    });
  }
  
  if (applyFilterBtn) {
    applyFilterBtn.addEventListener('click', () => {
      applyFilters();
    });
  }
  
  if (clearFilterBtn) {
    clearFilterBtn.addEventListener('click', () => {
      clearFilters();
    });
  }
}

// Server Logs functions
let currentServerLogFilters = { level: '', logger_name: '', message: '', date_from: '', date_to: '' };

function setupServerLogsButtons() {
  const refreshBtn = el('btnServerLogsRefresh');
  const exportBtn = el('btnServerLogsExport');
  const applyBtn = el('btnServerLogsApply');
  const clearBtn = el('btnServerLogsClear');
  if (refreshBtn) refreshBtn.addEventListener('click', () => loadServerLogs());
  if (exportBtn) exportBtn.addEventListener('click', () => exportServerLogs());
  if (applyBtn) applyBtn.addEventListener('click', () => applyServerLogFilters());
  if (clearBtn) clearBtn.addEventListener('click', () => clearServerLogFilters());
}

function applyServerLogFilters() {
  currentServerLogFilters.level = (el('serverLogLevel')?.value || '');
  currentServerLogFilters.logger_name = (el('serverLogLogger')?.value || '').trim();
  currentServerLogFilters.message = (el('serverLogMessage')?.value || '').trim();
  // Convert datetime-local to UTC ISO format (full ISO string with Z)
  const dateFromValue = el('serverLogDateFrom')?.value || '';
  const dateToValue = el('serverLogDateTo')?.value || '';
  currentServerLogFilters.date_from = dateFromValue ? new Date(dateFromValue).toISOString() : '';
  currentServerLogFilters.date_to = dateToValue ? new Date(dateToValue).toISOString() : '';
  loadServerLogs();
}

function clearServerLogFilters() {
  if (el('serverLogLevel')) el('serverLogLevel').value = '';
  if (el('serverLogLogger')) el('serverLogLogger').value = '';
  if (el('serverLogMessage')) el('serverLogMessage').value = '';
  if (el('serverLogDateFrom')) el('serverLogDateFrom').value = '';
  if (el('serverLogDateTo')) el('serverLogDateTo').value = '';
  currentServerLogFilters = { level: '', logger_name: '', message: '', date_from: '', date_to: '' };
  loadServerLogs();
}

async function loadServerLogs() {
  const listEl = el('serverLogsList');
  if (!listEl) return;
  try {
    listEl.innerHTML = '<p>Loading server logs...</p>';
    let url = '/server-logs/list?limit=1000';
    const { level, logger_name, message, date_from, date_to } = currentServerLogFilters;
    if (level) url += `&level=${encodeURIComponent(level)}`;
    if (logger_name) url += `&logger_name=${encodeURIComponent(logger_name)}`;
    if (message) url += `&message=${encodeURIComponent(message)}`;
    if (date_from) url += `&date_from=${encodeURIComponent(date_from)}`;
    if (date_to) url += `&date_to=${encodeURIComponent(date_to)}`;
    const res = await api(url);
    if (!res.ok) {
      listEl.innerHTML = `<p style="color: #f87171;">Error loading server logs: ${res.statusText}</p>`;
      return;
    }
    const data = await res.json();
    const logs = data.logs || [];
    if (logs.length === 0) {
      listEl.innerHTML = '<p>No server logs found.</p>';
      return;
    }
    let html = '<table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #d2d2d7;">';
    html += '<thead><tr style="background: #f5f5f7; border-bottom: 2px solid #d2d2d7;">';
    html += '<th style="padding: 10px; text-align: left;">Time</th>';
    html += '<th style="padding: 10px; text-align: left;">Level</th>';
    html += '<th style="padding: 10px; text-align: left;">Logger</th>';
    html += '<th style="padding: 10px; text-align: left;">Message</th>';
    html += '</tr></thead><tbody>';
    logs.forEach(l => {
      const ts = formatDateTime(l.created_at);
      html += '<tr style="border-bottom: 1px solid #eee;">';
      html += `<td style="padding: 8px; font-size: 12px;">${ts}</td>`;
      html += `<td style="padding: 8px; font-size: 12px;">${l.level || '-'}</td>`;
      html += `<td style="padding: 8px; font-size: 12px;">${l.logger_name || '-'}</td>`;
      html += `<td style="padding: 8px; font-size: 12px; word-break: break-word;">${l.message || '-'}</td>`;
      html += '</tr>';
    });
    html += '</tbody></table>';
    listEl.innerHTML = html;
  } catch (e) {
    listEl.innerHTML = `<p style="color: #f87171;">Error loading server logs: ${e.message || e}</p>`;
  }
}

async function exportServerLogs() {
  let url = '/server-logs/export';
  const { level, logger_name, message, date_from, date_to } = currentServerLogFilters;
  const params = [];
  if (level) params.push(`level=${encodeURIComponent(level)}`);
  if (logger_name) params.push(`logger_name=${encodeURIComponent(logger_name)}`);
  if (message) params.push(`message=${encodeURIComponent(message)}`);
  if (date_from) params.push(`date_from=${encodeURIComponent(date_from)}`);
  if (date_to) params.push(`date_to=${encodeURIComponent(date_to)}`);
  if (params.length) url += '?' + params.join('&');
  const res = await fetch(url);
  if (!res.ok) {
    showStatus(`Failed to export server logs: ${res.statusText}`);
    return;
  }
  const blob = await res.blob();
  const dl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = dl;
  a.download = 'server_logs.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(dl);
}
function applyFilters() {
  const actionFilter = el('filterAction');
  const userFilter = el('filterUser');
  const dateFromFilter = el('filterDateFrom');
  const dateToFilter = el('filterDateTo');
  
  currentFilters.action = actionFilter ? actionFilter.value : '';
  currentFilters.user = userFilter ? userFilter.value.trim() : '';
  // Convert datetime-local to UTC ISO format (full ISO string with Z)
  const dateFromValue = dateFromFilter ? dateFromFilter.value : '';
  const dateToValue = dateToFilter ? dateToFilter.value : '';
  currentFilters.date_from = dateFromValue ? new Date(dateFromValue).toISOString() : '';
  currentFilters.date_to = dateToValue ? new Date(dateToValue).toISOString() : '';
  
  loadAuditLogs();
}

function clearFilters() {
  const actionFilter = el('filterAction');
  const userFilter = el('filterUser');
  const dateFromFilter = el('filterDateFrom');
  const dateToFilter = el('filterDateTo');
  
  if (actionFilter) actionFilter.value = '';
  if (userFilter) userFilter.value = '';
  if (dateFromFilter) dateFromFilter.value = '';
  if (dateToFilter) dateToFilter.value = '';
  
  currentFilters = { action: '', user: '', date_from: '', date_to: '' };
  loadAuditLogs();
}

async function loadAuditLogs() {
  const logsList = el('auditLogsList');
  if (!logsList) return;
  
  try {
    logsList.innerHTML = '<p>Loading audit logs...</p>';
    
    let url = '/audit-logs/list?limit=1000';
    if (currentFilters.action) {
      url += `&action=${encodeURIComponent(currentFilters.action)}`;
    }
    if (currentFilters.user) {
      url += `&user=${encodeURIComponent(currentFilters.user)}`;
    }
    if (currentFilters.date_from) {
      url += `&date_from=${encodeURIComponent(currentFilters.date_from)}`;
    }
    if (currentFilters.date_to) {
      url += `&date_from=${encodeURIComponent(currentFilters.date_to)}`;
    }
    
    const res = await api(url);
    if (!res.ok) {
      logsList.innerHTML = `<p style="color: #f87171;">Error loading audit logs: ${res.statusText}</p>`;
      return;
    }
    
    const data = await res.json();
    const logs = data.logs || [];
    
    if (logs.length === 0) {
      logsList.innerHTML = '<p>No audit logs found.</p>';
      return;
    }
    
    // Create table for logs
    let html = '<table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #d2d2d7;">';
    html += '<thead><tr style="background: #f5f5f7; border-bottom: 2px solid #d2d2d7;">';
    html += '<th style="padding: 12px; text-align: left; font-weight: 600; border-right: 1px solid #d2d2d7;">Timestamp</th>';
    html += '<th style="padding: 12px; text-align: left; font-weight: 600; border-right: 1px solid #d2d2d7;">Action</th>';
    html += '<th style="padding: 12px; text-align: left; font-weight: 600; border-right: 1px solid #d2d2d7;">User</th>';
    html += '<th style="padding: 12px; text-align: left; font-weight: 600; border-right: 1px solid #d2d2d7;">IP Address</th>';
    html += '<th style="padding: 12px; text-align: left; font-weight: 600;">Details</th>';
    html += '</tr></thead><tbody>';
    
    logs.forEach(log => {
      const timestamp = formatDateTime(log.created_at);
      const actionDisplay = log.action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      
      html += '<tr style="border-bottom: 1px solid #e5e5e7;">';
      html += `<td style="padding: 10px; border-right: 1px solid #e5e5e7; font-size: 13px;">${timestamp}</td>`;
      html += `<td style="padding: 10px; border-right: 1px solid #e5e5e7; font-size: 13px; font-weight: 500;">${actionDisplay}</td>`;
      html += `<td style="padding: 10px; border-right: 1px solid #e5e5e7; font-size: 13px;">${log.user || '-'}</td>`;
      html += `<td style="padding: 10px; border-right: 1px solid #e5e5e7; font-size: 13px; font-family: monospace;">${log.ip_address || '-'}</td>`;
      html += `<td style="padding: 10px; font-size: 13px; max-width: 400px; overflow-wrap: break-word;">${log.details || '-'}</td>`;
      html += '</tr>';
    });
    
    html += '</tbody></table>';
    logsList.innerHTML = html;
  } catch (error) {
    logsList.innerHTML = `<p style="color: #f87171;">Error loading audit logs: ${error.message || error}</p>`;
  }
}

async function exportAuditLogs() {
  try {
    let url = '/audit-logs/export';
    const params = [];
    if (currentFilters.action) {
      params.push(`action=${encodeURIComponent(currentFilters.action)}`);
    }
    if (currentFilters.user) {
      params.push(`user=${encodeURIComponent(currentFilters.user)}`);
    }
    if (currentFilters.date_from) {
      params.push(`date_from=${encodeURIComponent(currentFilters.date_from)}`);
    }
    if (currentFilters.date_to) {
      params.push(`date_to=${encodeURIComponent(currentFilters.date_to)}`);
    }
    if (params.length > 0) {
      url += '?' + params.join('&');
    }
    
    const res = await fetch(url);
    if (!res.ok) {
      showStatus(`Failed to export audit logs: ${res.statusText}`);
      return;
    }
    
    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = 'audit_logs.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(downloadUrl);
    
    showStatus('Audit logs exported successfully');
  } catch (error) {
    showStatus(`Error exporting audit logs: ${error.message || error}`);
  }
}

// Reports section functions
function setupReportsButtons() {
  const refreshBtn = el('btnRefreshReports');
  const backBtn = el('btnBackToReports');
  
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => loadReports());
  }
  
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      el('reportsList').style.display = 'block';
      el('reportDetailView').style.display = 'none';
      loadReports();
    });
  }
}

async function loadReports() {
  const listEl = el('reportsList');
  if (!listEl) return;
  
  try {
    listEl.innerHTML = '<p>Loading reports...</p>';
    const res = await api('/run/reports');
    
    if (!res.ok) {
      listEl.innerHTML = `<p style="color: #f87171;">Error loading reports: ${res.statusText}</p>`;
      return;
    }
    
    const data = await res.json();
    const runs = data.runs || [];
    
    if (runs.length === 0) {
      listEl.innerHTML = '<p>No run reports found.</p>';
      return;
    }
    
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';
    for (const run of runs) {
      const statusColor = run.status === 'success' ? '#34d399' : run.status === 'error' ? '#f87171' : '#fbbf24';
      const statusText = run.status === 'success' ? 'Success' : run.status === 'error' ? 'Error' : 'Running';
      const startDate = run.started_at ? formatDateTime(run.started_at) : 'N/A';
      const duration = run.duration_seconds ? `${Math.round(run.duration_seconds)}s` : 'N/A';
      
      html += `
        <div class="config-item" data-run-id="${run.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7; cursor: pointer;">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
            <span style="padding: 4px 8px; background: ${statusColor}; color: white; border-radius: 4px; font-size: 12px; font-weight: 600;">${statusText}</span>
            <span style="font-weight: 600; flex: 1;">${run.configuration_name || 'Manual Run'}</span>
            <span style="font-size: 12px; color: #86868b; font-family: monospace;">ID: ${run.id}</span>
            <span style="font-size: 12px; color: #86868b;">${startDate}</span>
          </div>
          <div style="font-size: 12px; color: #86868b;">
            Duration: ${duration} | ${run.message || ''}
          </div>
        </div>
      `;
    }
    html += '</div>';
    
    listEl.innerHTML = html;
    
    // Add click handlers
    document.querySelectorAll('[data-run-id]').forEach(item => {
      item.addEventListener('click', () => {
        const runId = parseInt(item.getAttribute('data-run-id'));
        showRunReport(runId);
      });
    });
  } catch (error) {
    listEl.innerHTML = `<p style="color: #f87171;">Error loading reports: ${error.message || error}</p>`;
  }
}
async function showRunReport(runId) {
  const detailView = el('reportDetailView');
  const detailContent = el('reportDetailContent');
  const detailTitle = el('reportDetailTitle');
  const listEl = el('reportsList');
  
  if (!detailView || !detailContent || !detailTitle) return;
  
  try {
    detailContent.innerHTML = '<p>Loading report details...</p>';
    detailView.style.display = 'block';
    listEl.style.display = 'none';
    
    const res = await api(`/run/reports/${runId}`);
    if (!res.ok) {
      detailContent.innerHTML = `<p style="color: #f87171;">Error loading report: ${res.statusText}</p>`;
      return;
    }
    
    const report = await res.json();
    detailTitle.textContent = `Run Report: ${report.configuration_name || 'Manual Run'}`;
    
    const statusColor = report.status === 'success' ? '#34d399' : report.status === 'error' ? '#f87171' : '#fbbf24';
    const statusText = report.status === 'success' ? 'Success' : report.status === 'error' ? 'Error' : 'Running';
    const startDate = report.started_at ? formatDateTime(report.started_at) : 'N/A';
    const endDate = report.completed_at ? formatDateTime(report.completed_at) : 'N/A';
    const duration = report.execution_details?.duration_seconds ? `${Math.round(report.execution_details.duration_seconds)}s` : 'N/A';
    
    let html = `
      <div style="margin-bottom: 24px;">
        <div style="display: flex; gap: 12px; align-items: center; margin-bottom: 12px;">
          <span style="padding: 6px 12px; background: ${statusColor}; color: white; border-radius: 4px; font-weight: 600;">${statusText}</span>
          <span style="font-size: 14px; color: #86868b; font-family: monospace; font-weight: 600;">Run ID: ${report.id}</span>
          <span style="font-size: 14px; color: #86868b;">Started: ${startDate}</span>
          <span style="font-size: 14px; color: #86868b;">Completed: ${endDate}</span>
          <span style="font-size: 14px; color: #86868b;">Duration: ${duration}</span>
        </div>
        ${report.message ? `<p style="margin-bottom: 12px;"><strong>Message:</strong> ${report.message}</p>` : ''}
      </div>
    `;
    
    const details = report.execution_details || {};
    
    // Get sshProfile for display
    let sshProfile = details.ssh_profile;

    // Legacy support: convert ssh_executions if ssh_profile is missing
    if (!sshProfile && Array.isArray(details.ssh_executions) && details.ssh_executions.length > 0) {
      const legacyExecutions = details.ssh_executions;
      sshProfile = {
        profile_id: details.ssh_profile_id || null,
        profile_name: details.ssh_profile_name || 'SSH Profile',
        wait_time_seconds: details.ssh_wait_time_seconds || null,
        commands: details.ssh_commands || [],
        hosts: legacyExecutions.map(exec => ({
          host: exec.host,
          success: exec.success,
          commands_executed: exec.success ? (details.ssh_commands ? details.ssh_commands.length : 0) : 0,
          commands_failed: exec.success ? 0 : (details.ssh_commands ? details.ssh_commands.length : 0),
          error: exec.error || null,
          output: exec.output || null
        }))
      };
    }

    // Debug: Log SSH profile data
    console.log('Report execution_details:', JSON.stringify(details, null, 2));
    console.log('SSH Profile data (normalized):', JSON.stringify(sshProfile, null, 2));

    const hosts = details.hosts || [];

    if (hosts.length > 0) {
      html += '<h4 style="margin-top: 24px; margin-bottom: 12px;">Host Summary</h4>';
      html += '<div style="display: flex; flex-direction: column; gap: 16px;">';
      
      for (const host of hosts) {
        html += `<div style="border: 1px solid #d2d2d7; border-radius: 6px; padding: 16px; background: #fafafa;">`;
        html += `<h5 style="margin: 0 0 12px 0; font-size: 14px; font-weight: 600;">Host: ${host}</h5>`;
        
        // Hostname Changes (1st)
        const hostnameChanges = (details.hostname_changes || []).filter(h => h.host === host);
        if (hostnameChanges.length > 0) {
          html += '<div style="margin-top: 8px; padding: 8px; background: #fef3c7; border-left: 3px solid #f59e0b; border-radius: 4px;">';
          html += '<div style="font-weight: 600; color: #92400e; margin-bottom: 4px; font-size: 13px;">Hostname Changes:</div>';
          html += '<ul style="margin: 4px 0 0 16px; font-size: 11px; color: #92400e;">';
          for (const hc of hostnameChanges) {
            const statusIcon = hc.success ? '✓' : '✗';
            const statusColor = hc.success ? '#047857' : '#dc2626';
            html += `<li style="color: ${statusColor}; margin-bottom: 2px;">
              <span style="font-weight: bold;">${statusIcon}</span>
              <code>${hc.host}</code>: Changed to <strong>${hc.new_hostname || 'N/A'}</strong>${hc.error ? ` - ${hc.error}` : ''}
            </li>`;
          }
          html += '</ul></div>';
        }
        
        // Password Changes (2nd)
        const passwordChanges = (details.password_changes || []).filter(p => p.host === host);
        if (passwordChanges.length > 0) {
          html += '<div style="margin-top: 8px; padding: 8px; background: #fef3c7; border-left: 3px solid #f59e0b; border-radius: 4px;">';
          html += '<div style="font-weight: 600; color: #92400e; margin-bottom: 4px; font-size: 13px;">Password Changes:</div>';
          html += '<ul style="margin: 4px 0 0 16px; font-size: 11px; color: #92400e;">';
          for (const pc of passwordChanges) {
            const statusIcon = pc.success ? '✓' : '✗';
            const statusColor = pc.success ? '#047857' : '#dc2626';
            html += `<li style="color: ${statusColor}; margin-bottom: 2px;">
              <span style="font-weight: bold;">${statusIcon}</span>
              <code>${pc.host}</code>: Changed password for user <strong>${pc.username || 'guest'}</strong>${pc.error ? ` - ${pc.error}` : ''}
            </li>`;
          }
          html += '</ul></div>';
        }
        
        // Fabric Creations (3rd)
        const creations = (details.fabric_creations || []).filter(c => c.host === host);
        if (creations.length > 0) {
          html += '<div style="margin-top: 8px; padding: 8px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px;">';
          html += '<div style="font-weight: 600; color: #047857; margin-bottom: 4px; font-size: 13px;">Fabric Creations:</div>';
          html += '<ul style="margin: 4px 0 0 16px; font-size: 11px; color: #047857;">';
          for (const creation of creations) {
            const statusIcon = creation.success ? '✓' : '✗';
            const statusColor = creation.success ? '#047857' : '#dc2626';
            const duration = creation.duration_seconds ? ` (${Math.round(creation.duration_seconds)}s)` : '';
            const errors = creation.errors && creation.errors.length > 0 ? ` - ${creation.errors.join('; ')}` : '';
            html += `<li style="color: ${statusColor}; margin-bottom: 2px;">
              <span style="font-weight: bold;">${statusIcon}</span>
              <strong>${creation.template_name || ''}</strong> v${creation.version || ''}${duration}${errors}
            </li>`;
          }
          html += '</ul></div>';
        }
        
        // SSH Commands (4th)
        if (sshProfile && sshProfile.hosts) {
          const hostSshResult = sshProfile.hosts.find(h => h.host === host);
          if (hostSshResult) {
            html += '<div style="margin-top: 8px; padding: 8px; background: #f0f9ff; border-left: 3px solid #3b82f6; border-radius: 4px;">';
            html += '<div style="font-weight: 600; color: #1e40af; margin-bottom: 4px; font-size: 13px;">SSH Commands:</div>';
            html += '<div style="font-size: 11px; color: #1e40af; margin-left: 8px;">';
            const statusIcon = hostSshResult.success ? '✓' : '✗';
            const statusColor = hostSshResult.success ? '#10b981' : '#ef4444';
            html += `<div style="margin-bottom: 2px;">
              <span style="color: ${statusColor}; font-weight: bold;">${statusIcon}</span>
              <code>${host}</code>: ${hostSshResult.commands_executed || 0} executed, ${hostSshResult.commands_failed || 0} failed${hostSshResult.error ? ` - ${hostSshResult.error}` : ''}
            </div>`;
            html += '</div></div>';
          }
        }
        
        // Installations (5th)
        const installations = (details.installations || []).filter(i => i.host === host);
        if (installations.length > 0) {
          html += '<div style="margin-top: 8px; padding: 8px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px;">';
          html += '<div style="font-weight: 600; color: #047857; margin-bottom: 4px; font-size: 13px;">Installations:</div>';
          html += '<ul style="margin: 4px 0 0 16px; font-size: 11px; color: #047857;">';
          for (const install of installations) {
            const statusIcon = install.success ? '✓' : '✗';
            const statusColor = install.success ? '#047857' : '#dc2626';
            const duration = install.duration_seconds ? ` (${Math.round(install.duration_seconds)}s)` : '';
            const errors = install.errors && install.errors.length > 0 ? ` - ${install.errors.join('; ')}` : '';
            html += `<li style="color: ${statusColor}; margin-bottom: 2px;">
              <span style="font-weight: bold;">${statusIcon}</span>
              <strong>${install.template_name || ''}</strong> v${install.version || ''} on ${install.host || 'N/A'}${duration}${errors}
            </li>`;
          }
          html += '</ul></div>';
        }
        
        html += '</div>';
      }
      
      html += '</div>';
    }
    
    // SSH Profile Section (standalone, after Host Summary)
    // Show if sshProfile exists and has any meaningful data (hosts, profile info, or commands)
    if (sshProfile && ((sshProfile.profile_id || sshProfile.profile_name) || (sshProfile.hosts && sshProfile.hosts.length > 0) || (sshProfile.commands && sshProfile.commands.length > 0))) {
      html += '<h4 style="margin-top: 24px; margin-bottom: 12px;">SSH Profile Execution</h4>';
      html += '<div style="border: 1px solid #d2d2d7; border-radius: 6px; padding: 16px; background: #fafafa; margin-bottom: 24px;">';
      html += '<div style="margin-bottom: 12px;">';
      html += `<div style="font-size: 13px; margin-bottom: 4px;"><strong>Profile:</strong> ${sshProfile.profile_name || 'N/A'} (ID: ${sshProfile.profile_id || 'N/A'})</div>`;
      html += `<div style="font-size: 13px; margin-bottom: 4px;"><strong>Wait Time:</strong> ${sshProfile.wait_time_seconds || 0} seconds</div>`;
      html += `<div style="font-size: 13px; margin-bottom: 4px;"><strong>Commands:</strong> ${sshProfile.commands ? sshProfile.commands.length : 0} command(s)</div>`;
      if (sshProfile.commands && sshProfile.commands.length > 0) {
        html += '<div style="margin-top: 8px; padding: 8px; background: #f9fafb; border-radius: 4px; font-family: monospace; font-size: 11px;">';
        html += '<div style="font-weight: 600; margin-bottom: 4px;">Command List:</div>';
        html += '<ul style="margin: 0; padding-left: 20px;">';
        sshProfile.commands.forEach(cmd => {
          html += `<li style="margin-bottom: 2px;">${cmd}</li>`;
        });
        html += '</ul></div>';
      }
      html += '</div>';
      
      if (sshProfile.hosts && sshProfile.hosts.length > 0) {
        html += '<div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #d2d2d7;">';
        html += '<div style="font-weight: 600; margin-bottom: 8px; font-size: 13px;">Host Results:</div>';
        html += '<ul style="margin: 0; padding-left: 20px; font-size: 12px;">';
        sshProfile.hosts.forEach(h => {
          const statusIcon = h.success ? '✓' : '✗';
          const statusColor = h.success ? '#10b981' : '#ef4444';
          html += `<li style="margin-bottom: 8px;">
            <div>
              <span style="color: ${statusColor}; font-weight: bold;">${statusIcon}</span>
              <code>${h.host}</code>: ${h.commands_executed || 0} executed, ${h.commands_failed || 0} failed${h.error ? ` - ${h.error}` : ''}
            </div>`;
          if (h.output) {
            html += `<div style="margin-top: 4px; padding: 8px; background: #f9fafb; border-radius: 4px; font-family: monospace; font-size: 11px; color: #374151; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">${h.output}</div>`;
          }
          html += `</li>`;
        });
        html += '</ul></div>';
      }
      html += '</div>';
    }
    
    // Errors
    if (report.errors && report.errors.length > 0) {
      html += '<div style="margin-top: 24px; padding: 12px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 4px;">';
      html += '<div style="font-weight: 600; color: #dc2626; margin-bottom: 8px; font-size: 13px;">Errors:</div>';
      html += '<ul style="margin: 0; padding-left: 20px; color: #991b1b; font-size: 12px;">';
      for (const error of report.errors) {
        html += `<li style="margin-bottom: 4px;">${error}</li>`;
      }
      html += '</ul></div>';
    }
    
    detailContent.innerHTML = html;
  } catch (error) {
    detailContent.innerHTML = `<p style="color: #f87171;">Error loading report: ${error.message || error}</p>`;
  }
}