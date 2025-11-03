const accessTokens = new Map(); // Map<host, token>
let confirmedHosts = []; // Array of {host, port}
let templates = []; // Array of template objects
let editingConfigId = null; // Track if we're editing an existing configuration
let editingEventId = null; // Track if we're editing an existing event
// Store decrypted NHI credentials in memory (not in DOM)
let decryptedClientId = '';
let decryptedClientSecret = '';
let storedNhiTokens = new Map(); // Store tokens from NHI credential by host: {token, expires_at}
let currentNhiId = null; // Track which NHI credential is currently loaded

const el = (id) => document.getElementById(id);
// Password modal prompt used for NHI password (hidden while typing)
async function promptForNhiPassword(titleText) {
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
    dialog.style.width = '420px';
    dialog.style.maxWidth = '90%';
    dialog.style.padding = '16px';
    dialog.style.borderRadius = '0';

    const title = document.createElement('div');
    title.textContent = titleText || 'Enter NHI credential password';
    title.style.fontWeight = '600';
    title.style.marginBottom = '10px';
    dialog.appendChild(title);

    const label = document.createElement('label');
    label.textContent = 'NHI Password';
    label.style.display = 'block';
    label.style.marginBottom = '6px';
    dialog.appendChild(label);

    const input = document.createElement('input');
    input.type = 'password';
    input.autocomplete = 'current-password';
    input.style.width = '100%';
    input.style.boxSizing = 'border-box';
    input.style.margin = '0 0 12px 0';
    input.style.padding = '6px 10px';
    input.style.border = '1px solid #d2d2d7';
    input.style.minHeight = '32px';
    dialog.appendChild(input);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.justifyContent = 'flex-end';
    actions.style.gap = '8px';

    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.onclick = () => { document.body.removeChild(overlay); resolve(null); };

    const okBtn = document.createElement('button');
    okBtn.type = 'button';
    okBtn.textContent = 'OK';
    okBtn.onclick = () => { const val = input.value; document.body.removeChild(overlay); resolve(val); };

    actions.appendChild(cancelBtn);
    actions.appendChild(okBtn);
    dialog.appendChild(actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Focus and submit on Enter/Escape
    input.focus();
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') okBtn.click();
      if (e.key === 'Escape') cancelBtn.click();
    });
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
  renderFabricHostList();
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
    console.error(`Error in populateHostsFromInput for ${targetInputId}:`, error);
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
  
  // If forced validation (e.g., on blur or confirm), validate current input if any
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

function getAllConfirmedHosts() {
  return confirmedHosts.length > 0 ? confirmedHosts : parseFabricHosts();
}

function mergeAuth(host, obj) {
  const token = accessTokens.get(host);
  return token ? { ...obj, access_token: token } : obj;
}

function renderFabricHostList() {
  const listEl = el('fabricHostList');
  if (!listEl) return;
  listEl.innerHTML = '';
  const items = parseFabricHosts();
  confirmedHosts = items; // Store confirmed hosts
  items.forEach(({host, port}, i) => {
    const li = document.createElement('li');
    const tokenStatus = accessTokens.has(host) ? ' [Token OK]' : ' [No Token]';
    li.textContent = host + (port ? (':' + port) : '') + tokenStatus;
    listEl.appendChild(li);
  });
}

async function checkRunningTasks(host, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await api('/tasks/status', { params: mergeAuth(host, { fabric_host: host }) });
      if (!res.ok) return {running: false, error: true};
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
    const token = accessTokens.get(host);
    if (!token) return {host, success: true}; // Skip if no token
    logMsg(`Checking for running tasks on ${host} before ${actionName}...`);
    const checkResult = await checkRunningTasks(host, 1000); // Quick check first
    if (!checkResult.running) {
      logMsg(`No running tasks on ${host}`);
      return {host, success: true};
    } else {
      logMsg(`Waiting for running tasks to complete on ${host}...`);
      const completed = await checkRunningTasks(host, 600000); // 10 minute wait
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
    showStatus('No hosts configured. Please confirm hosts first.');
    return;
  }
  
  // Check for running tasks before executing action
  if (options.checkTasks !== false) {
    await waitForNoRunningTasks(hosts, actionName);
  }
  
  const results = [];
  const promises = hosts.map(async ({host}) => {
    const token = accessTokens.get(host);
    if (!token) {
      showStatus(`Skipping ${host}: No token available`);
      return {host, success: false, error: 'No token'};
    }
    try {
      await actionFn(host, token);
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
async function loadNhiCredentialsForAuth() {
  const select = el('nhiCredentialSelect');
  if (!select) return;
  
  try {
    const res = await api('/nhi/list');
    if (!res.ok) {
      select.innerHTML = '<option value="">Error loading credentials</option>';
      return;
    }
    
    const data = await res.json();
    const credentials = data.credentials || [];
    
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
  } catch (error) {
    select.innerHTML = '<option value="">Error loading credentials</option>';
    console.error('Error loading NHI credentials:', error);
  }
}

// Load selected NHI credential with password
async function loadSelectedNhiCredential() {
  const select = el('nhiCredentialSelect');
  const passwordInput = el('nhiDecryptPassword');
  const statusSpan = el('nhiLoadStatus');
  
  if (!select || !passwordInput) return;
  
  const nhiId = select.value;
  const password = passwordInput.value.trim();
  
  if (!nhiId) {
    if (statusSpan) statusSpan.textContent = 'Please select a credential';
    return;
  }
  
  if (!password) {
    if (statusSpan) statusSpan.textContent = 'Please enter encryption password';
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
    const res = await api(`/nhi/get/${nhiId}?encryption_password=${encodeURIComponent(password)}`);
    
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
        showStatus(`Failed to load NHI credential: ${errorText}. Please check your encryption password.`);
      } else {
        showStatus(`Failed to load NHI credential: ${errorText}`);
      }
      
      decryptedClientId = '';
      decryptedClientSecret = '';
      currentNhiId = null;
      storedNhiTokens.clear();
      
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
          console.error('Error clearing NHI hosts:', e);
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
      
      // Keep Confirm button disabled on error
      const confirmBtn = el('btnConfirmHosts');
      if (confirmBtn) confirmBtn.disabled = true;
      return;
    }
    
    let nhiData;
    try {
      nhiData = await res.json();
    } catch (jsonError) {
      if (statusSpan) statusSpan.textContent = 'Invalid response';
      showStatus(`Failed to parse response from server: ${jsonError.message || jsonError}`);
      console.error('JSON parse error:', jsonError);
      return;
    }
    
    if (!nhiData || typeof nhiData !== 'object') {
      if (statusSpan) statusSpan.textContent = 'Invalid response';
      showStatus('Invalid response format from server');
      return;
    }
    decryptedClientId = nhiData.client_id || '';
    decryptedClientSecret = nhiData.client_secret || '';
    currentNhiId = parseInt(nhiId);
    
    // Store tokens by host from NHI credential (will be reused in acquireTokens)
    storedNhiTokens.clear();
    const nhiHosts = [];
    if (nhiData.tokens_by_host && Object.keys(nhiData.tokens_by_host).length > 0) {
      // Store tokens per host and collect host list
      for (const [host, tokenInfo] of Object.entries(nhiData.tokens_by_host)) {
        storedNhiTokens.set(host, {
          token: tokenInfo.token,
          expires_at: tokenInfo.expires_at
        });
        nhiHosts.push(host);
      }
      console.log(`NHI credential contains ${nhiHosts.length} stored token(s) for host(s): ${nhiHosts.join(', ')}`);
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
      showStatus(`NHI credential loaded. Compare hosts from credential with Host List.`);
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
    
    // Enable Confirm button after successful credential load
    const confirmBtn = el('btnConfirmHosts');
    if (confirmBtn) confirmBtn.disabled = false;
    
    // Show final success message if no specific message was already shown above
    if (nhiHosts.length === 0) {
      showStatus(`NHI credential '${nhiData.name}' loaded successfully (no hosts in credential)`);
    }
  } catch (error) {
    if (statusSpan) {
      statusSpan.textContent = 'Error';
      statusSpan.style.color = '#f87171';
    }
    showStatus(`Error loading NHI credential: ${error.message || error}`);
    decryptedClientId = '';
    decryptedClientSecret = '';
    currentNhiId = null;
    storedNhiTokens.clear();
    
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
        console.error('Error clearing NHI hosts on error:', e);
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
    
    // Keep Confirm button disabled on error
    const confirmBtn = el('btnConfirmHosts');
    if (confirmBtn) confirmBtn.disabled = true;
  }
}

// Default API base to the current page origin to avoid cross-origin mismatches (localhost vs 127.0.0.1)
// Initialize global state variables
let validatedHosts = [];
if (!window.validatedNhiHosts) window.validatedNhiHosts = [];

// Note: Preparation section initialization is now in initializePreparationSection()
// which is called when the preparation section is loaded

function logMsg(msg) {
  const out = el('out');
  if (out) {
    out.textContent += msg + "\n";
  }
}

function showStatus(msg, opts = {}) {
  const box = el('actionStatus');
  if (!box) return;
  box.textContent = msg;
  box.style.display = '';
  logMsg(msg);
  if (opts.hideAfterMs) {
    const ms = opts.hideAfterMs;
    setTimeout(() => { if (box.textContent === msg) box.style.display = 'none'; }, ms);
  }
}

function setActionsEnabled(enabled) {
  const idsToSkip = new Set(['btnInstallSelected','btnConfirmHosts','btnAddRow']);
  document.querySelectorAll('button').forEach(b => {
    if (!idsToSkip.has(b.id)) b.disabled = !enabled;
  });
  // Inputs for API config should remain enabled
  ['apiBase','fabricHost'].forEach(id => {
    const i = el(id);
    if (i) i.disabled = false;
  });
  const runBtn = el('btnInstallSelected');
  if (runBtn) {
    if (!enabled) runBtn.disabled = true; else updateCreateEnabled();
  }
}

// Generic API wrapper with optional params
async function api(path, options = {}) {
  const baseInput = el('apiBase');
  const base = baseInput ? baseInput.value.trim() : '';
  
  // Handle empty or invalid base URL
  if (!base) {
    // Try to use current origin as fallback
    const baseUrl = window.location.origin;
    const url = path.startsWith('http') ? new URL(path) : new URL(path, baseUrl);
    if (options.params && typeof options.params === 'object') {
      Object.entries(options.params).forEach(([k, v]) => url.searchParams.set(k, v));
    }
    // Add cache-busting and disable browser cache
    if ((options.method || 'GET').toUpperCase() === 'GET') {
      url.searchParams.set('_ts', Date.now());
    }
    const headers = new Headers(options.headers || {});
    headers.set('Cache-Control', 'no-cache');
    return fetch(url.toString(), { ...options, headers, cache: 'no-store' });
  }
  
  try {
    const baseUrl = new URL(base);
    const url = path.startsWith('http') ? new URL(path) : new URL(path, baseUrl);
    if (options.params && typeof options.params === 'object') {
      Object.entries(options.params).forEach(([k, v]) => url.searchParams.set(k, v));
    }
    // Add cache-busting and disable browser cache
    if ((options.method || 'GET').toUpperCase() === 'GET') {
      url.searchParams.set('_ts', Date.now());
    }
    const headers = new Headers(options.headers || {});
    headers.set('Cache-Control', 'no-cache');
    return fetch(url.toString(), { ...options, headers, cache: 'no-store' });
  } catch (error) {
    // If base URL is invalid, try using current origin as fallback
    const baseUrl = window.location.origin;
    const url = path.startsWith('http') ? new URL(path) : new URL(path, baseUrl);
    if (options.params && typeof options.params === 'object') {
      Object.entries(options.params).forEach(([k, v]) => url.searchParams.set(k, v));
    }
    if ((options.method || 'GET').toUpperCase() === 'GET') {
      url.searchParams.set('_ts', Date.now());
    }
    const headers = new Headers(options.headers || {});
    headers.set('Cache-Control', 'no-cache');
    return fetch(url.toString(), { ...options, headers, cache: 'no-store' });
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

// Minimal logging mode: disable console.log unless explicitly enabled
(() => {
  const DEBUG_LOGS = false; // set true when debugging
  if (!DEBUG_LOGS && typeof console !== 'undefined' && typeof console.log === 'function') {
    try { console.log = function(){}; } catch(_) {}
  }
})();

// Reset Preparation UI/state so it can be reused for a new run
function resetPreparationForNewRun() {
  try {
    // Reset Authentication section (keep API Base)
    const apiBase = el('apiBase');
    // intentionally keep apiBase as-is
    const nhiSelect = el('nhiCredentialSelect');
    if (nhiSelect) nhiSelect.value = '';
    const nhiPwd = el('nhiDecryptPassword');
    if (nhiPwd) nhiPwd.value = '';
    const nhiStatus = el('nhiLoadStatus');
    if (nhiStatus) nhiStatus.textContent = '';
    const tokenStatus = el('tokenStatus');
    if (tokenStatus) tokenStatus.textContent = '';
    const hostSourceManual = el('hostSourceManual');
    if (hostSourceManual) hostSourceManual.checked = true;
    const hostSourceNhi = el('hostSourceNhi');
    if (hostSourceNhi) hostSourceNhi.checked = false;

    // Clear any decrypted/stored credentials and tokens
    if (typeof decryptedClientId !== 'undefined') decryptedClientId = '';
    if (typeof decryptedClientSecret !== 'undefined') decryptedClientSecret = '';
    if (typeof currentNhiId !== 'undefined') currentNhiId = null;
    if (typeof storedNhiTokens?.clear === 'function') storedNhiTokens.clear();
    if (typeof accessTokens?.clear === 'function') accessTokens.clear();

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
    const confirmBtn = el('btnConfirmHosts');
    if (confirmBtn) confirmBtn.disabled = false;

    // Clear status/notice area
    const actionStatus = el('actionStatus');
    if (actionStatus) actionStatus.style.display = 'none';
  } catch (e) {
    // Non-fatal; log only
    console.warn('resetPreparationForNewRun error:', e);
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
  if (confirmedHosts.length === 0) {
    showStatus('Please confirm hosts first');
    return false;
  }
  // Ensure decrypted credentials using the Encryption Password field in Preparation
  try {
    if ((!decryptedClientId || !decryptedClientSecret)) {
      const nhiSelect = el('nhiCredentialSelect');
      const pwdInput = el('nhiDecryptPassword');
      const selectedId = nhiSelect ? (nhiSelect.value || '') : '';
      const encPwd = pwdInput ? (pwdInput.value || '').trim() : '';
      if (selectedId && encPwd) {
        const res = await api(`/nhi/get/${selectedId}?encryption_password=${encodeURIComponent(encPwd)}`);
        if (res.ok) {
          const data = await res.json();
          decryptedClientId = data.client_id || '';
          decryptedClientSecret = data.client_secret || '';
          currentNhiId = parseInt(selectedId);
          // preload tokens per host if any
          storedNhiTokens.clear();
          if (data.tokens_by_host) {
            for (const [host, tokenInfo] of Object.entries(data.tokens_by_host)) {
              storedNhiTokens.set(host, { token: tokenInfo.token, expires_at: tokenInfo.expires_at });
            }
          }
          showStatus('NHI credential decrypted using Encryption Password');
        } else {
          const errText = await res.text().catch(() => 'Invalid Encryption Password');
          showStatus(`Failed to decrypt NHI credential: ${errText}`);
          return false;
        }
      }
    }
  } catch (e) {
    console.error('Error ensuring decrypted credentials:', e);
    showStatus('Error decrypting NHI credential with Encryption Password');
    return false;
  }
  // Use decrypted credentials from NHI Management
  const clientId = decryptedClientId;
  const clientSecret = decryptedClientSecret;
  if (!clientId || !clientSecret) {
    showStatus('Enter Encryption Password and load NHI credential to acquire tokens');
    return false;
  }
  
  // Try to reuse stored tokens from NHI credential if available
  let reusedTokens = 0;
  let fetchedTokens = 0;
  const failures = [];
  const tokenLifetimes = []; // Store token lifetimes for display
  
  // First, try to reuse stored tokens from NHI credential per host
  for (const {host} of confirmedHosts) {
    const storedTokenInfo = storedNhiTokens.get(host);
    if (storedTokenInfo && storedTokenInfo.token && storedTokenInfo.expires_at) {
      try {
        // Check if token is still valid
        const expiresAt = new Date(storedTokenInfo.expires_at);
        const now = new Date();
        if (expiresAt > now) {
          // Token is valid, reuse it for this host
          const delta = expiresAt - now;
          const totalSeconds = Math.floor(delta / 1000);
          const hours = Math.floor(totalSeconds / 3600);
          const minutes = Math.floor((totalSeconds % 3600) / 60);
          
          accessTokens.set(host, storedTokenInfo.token);
          reusedTokens++;
          tokenLifetimes.push(`${host}: ${hours}h ${minutes}m (reused)`);
          logMsg(`Reusing stored token from NHI credential for ${host} (expires in ${hours}h ${minutes}m)`);
        } else {
          logMsg(`Stored token from NHI credential for ${host} has expired, will fetch new token`);
          storedNhiTokens.delete(host); // Remove expired token info
        }
      } catch (error) {
        logMsg(`Error checking stored token for ${host}: ${error.message || error}, will fetch new token`);
        storedNhiTokens.delete(host);
      }
    }
  }
  
  // If we reused tokens for all hosts, return early
  if (reusedTokens === confirmedHosts.length) {
    renderFabricHostList();
    let statusText = `Token OK (${reusedTokens}/${confirmedHosts.length} reused)`;
    if (tokenLifetimes.length > 0) {
      statusText += ` - Lifetime: ${tokenLifetimes.join(', ')}`;
    }
    el('tokenStatus').textContent = statusText;
    showStatus(`Reused stored tokens from NHI credential for all hosts`);
    return true;
  }
  
  // Fetch new tokens for hosts that don't have tokens yet
  for (const {host} of confirmedHosts) {
    // Skip if we already have a token for this host (from reuse above)
    if (accessTokens.has(host)) {
      continue;
    }
    
    try {
      const res = await api('/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          fabric_host: host,
        }),
      });
      if (!res.ok) {
        const errText = await res.text().catch(() => 'Unknown error');
        logMsg(`Failed to get token for ${host}: ${res.status} ${errText}`);
        failures.push({ host, status: res.status, error: errText });
        continue;
      }
      const data = await res.json();
      accessTokens.set(host, data.access_token);
      fetchedTokens++;
      
      // Save the newly fetched token to the database if we have an NHI credential loaded
      if (currentNhiId && data.access_token && data.expires_in) {
        try {
          const passwordInput = el('nhiDecryptPassword');
          const password = passwordInput ? passwordInput.value.trim() : '';
          if (password) {
            // Update token in database
            const updateRes = await api(`/nhi/update-token/${currentNhiId}?fabric_host=${encodeURIComponent(host)}&token=${encodeURIComponent(data.access_token)}&expires_in=${data.expires_in}&encryption_password=${encodeURIComponent(password)}`, {
              method: 'POST'
            });
            if (updateRes.ok) {
              // Update stored token info in memory
              storedNhiTokens.set(host, {
                token: data.access_token,
                expires_at: new Date(Date.now() + data.expires_in * 1000).toISOString()
              });
              logMsg(`Token saved to NHI credential database for ${host}`);
            } else {
              logMsg(`Warning: Failed to save token to database for ${host}`);
            }
          }
        } catch (error) {
          // Don't fail the token acquisition if database save fails
          logMsg(`Warning: Error saving token to database for ${host}: ${error.message || error}`);
        }
      }
      
      // Format token lifetime for display
      if (data.expires_in) {
        const expiresIn = data.expires_in; // seconds
        const hours = Math.floor(expiresIn / 3600);
        const minutes = Math.floor((expiresIn % 3600) / 60);
        const seconds = expiresIn % 60;
        let lifetimeText = '';
        if (hours > 0) {
          lifetimeText = `${hours}h ${minutes}m`;
        } else if (minutes > 0) {
          lifetimeText = `${minutes}m ${seconds}s`;
        } else {
          lifetimeText = `${seconds}s`;
        }
        tokenLifetimes.push(`${host}: ${lifetimeText}`);
      }
      
      logMsg(`Token acquired for ${host}${data.expires_in ? ` (expires in ${Math.floor(data.expires_in / 3600)}h ${Math.floor((data.expires_in % 3600) / 60)}m)` : ''}`);
    } catch (error) {
      logMsg(`Error getting token for ${host}: ${error.message || error}`);
    }
  }
  
  renderFabricHostList();
  const successCount = reusedTokens + fetchedTokens;
  if (successCount > 0) {
    let statusText = `Token OK (${successCount}/${confirmedHosts.length})`;
    if (reusedTokens > 0 && fetchedTokens === 0) {
      statusText += ' [reused]';
    } else if (reusedTokens > 0) {
      statusText += ` [${reusedTokens} reused, ${fetchedTokens} fetched]`;
    }
    if (tokenLifetimes.length > 0) {
      // Display token lifetimes
      statusText += ` - Lifetime: ${tokenLifetimes.join(', ')}`;
    }
    el('tokenStatus').textContent = statusText;
    return true;
  }
  // No tokens acquired – show detailed reasons
  if (failures.length > 0) {
    const details = failures.map(f => `${f.host}: ${f.status} ${f.error}`).join(' | ');
    showStatus(`Token acquisition failed for all hosts: ${details}`);
  } else {
    showStatus('Token acquisition failed for all hosts (no details).');
  }
  return false;
}

// Cache all templates from all repositories for all confirmed hosts
// Templates are stored independently (deduplicated across hosts)
async function cacheAllTemplates() {
  if (confirmedHosts.length === 0) {
    console.warn('No confirmed hosts to cache templates for');
    return;
  }
  
  const allTemplates = [];
  const uniqueTemplates = new Map(); // Key: "repo_name|template_name|version"
  let successCount = 0;
  let errorCount = 0;
  
  try {
    showStatus('Fetching repositories and templates...', { hideAfterMs: false });
    
    // For each confirmed host, get all repositories and their templates
    for (const {host} of confirmedHosts) {
      const token = accessTokens.get(host);
      if (!token) {
        console.warn(`No token available for host ${host}, skipping`);
        errorCount++;
        continue;
      }
      
      try {
        // Get all repositories for this host
        const reposRes = await api('/repo/remotes', { params: mergeAuth(host, { fabric_host: host }) });
        if (!reposRes.ok) {
          console.error(`Failed to get repositories for ${host}:`, await reposRes.text().catch(() => 'Unknown error'));
          errorCount++;
          continue;
        }
        
        const reposData = await reposRes.json();
        const repositories = reposData.repositories || [];
        console.log(`Found ${repositories.length} repositories on ${host}`);
        
        // For each repository, get all templates
        for (const repo of repositories) {
          const repoId = repo.id;
          const repoName = repo.name;
          
          if (!repoId || !repoName) {
            continue;
          }
          
          try {
            const templatesData = await apiJson('/repo/templates/list', { 
              params: mergeAuth(host, { fabric_host: host, repo_name: repoName }) 
            });
            const templates = templatesData.templates || [];
            console.log(`Found ${templates.length} templates in repo ${repoName} on ${host}`);
            
            // Add templates to collection, deduplicating by repo_name + template_name + version
            for (const tpl of templates) {
              const templateName = tpl.name;
              const version = tpl.version || null;
              const uniqueKey = `${repoName}|${templateName}|${version}`;
              
              // Only add if we haven't seen this template before
              if (!uniqueTemplates.has(uniqueKey)) {
                const templateEntry = {
                  repo_id: repoId,
                  repo_name: repoName,
                  template_id: tpl.id,
                  template_name: templateName,
                  version: version
                };
                uniqueTemplates.set(uniqueKey, templateEntry);
                allTemplates.push(templateEntry);
              }
            }
            
            successCount++;
          } catch (error) {
            console.error(`Error fetching templates for repo ${repoName} on ${host}:`, error);
            errorCount++;
          }
        }
      } catch (error) {
        console.error(`Error fetching repositories for ${host}:`, error);
        errorCount++;
      }
    }
    
    // Send all unique templates to the cache endpoint (will purge and replace all existing)
    if (allTemplates.length > 0) {
      try {
        const cacheRes = await api('/cache/templates', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ templates: allTemplates })
        });
        
        if (cacheRes.ok) {
          const cacheData = await cacheRes.json();
          showStatus(`Cached ${cacheData.count} unique templates successfully`, { hideAfterMs: 3000 });
          logMsg(`Cached ${cacheData.count} unique templates from ${confirmedHosts.length} host(s)`);
        } else {
          const errorText = await cacheRes.text().catch(() => 'Unknown error');
          console.error('Failed to cache templates:', errorText);
          showStatus(`Failed to cache templates: ${errorText}`, { hideAfterMs: 5000 });
        }
      } catch (error) {
        console.error('Error caching templates:', error);
        showStatus(`Error caching templates: ${error.message || error}`, { hideAfterMs: 5000 });
      }
    } else {
      showStatus('No templates found to cache', { hideAfterMs: 2000 });
    }
    
    if (errorCount > 0) {
      console.warn(`Completed caching with ${errorCount} error(s)`);
    }
  } catch (error) {
    console.error('Error in cacheAllTemplates:', error);
    showStatus(`Error caching templates: ${error.message || error}`, { hideAfterMs: 5000 });
  }
}

function updateInstallSelect() {
  const select = el('installSelect');
  if (!select) return;
  
  const selVal = select.value;
  select.innerHTML = '';
  
  // First, collect templates from rows (workspaces that haven't been created yet)
  const rowTemplates = new Map();
  const allRows = document.querySelectorAll('.tpl-row');
  console.log(`updateInstallSelect: Found ${allRows.length} template rows to process`);
  
  allRows.forEach((row, idx) => {
    const selects = row.querySelectorAll('select');
    const repoSelect = selects[0]; // Repo is the first select
    const templateFiltered = row._templateFiltered;
    // Version is the last select (index 2, because templateFiltered.container contains a hidden select at index 1)
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    const repo_name = repoSelect?.value || '';
    const template_name = templateFiltered ? templateFiltered.getValue() : '';
    const version = versionSelect?.value || '';
    
    console.log(`  Row ${idx + 1}: repo="${repo_name}", template="${template_name}", version="${version}"`);
    
    // Require template_name and version to be non-empty (repo_name is optional but helpful)
    if (template_name && template_name.trim() && version && version.trim()) {
      const key = `${template_name}|||${version}`;
      if (!rowTemplates.has(key)) {
        rowTemplates.set(key, { template_name, version, repo_name });
        console.log(`    -> Added to install select: ${template_name} (v${version})`);
      } else {
        console.log(`    -> Skipped (duplicate): ${template_name} (v${version})`);
      }
    } else {
      console.log(`    -> Skipped (incomplete): missing template_name or version`);
    }
  });
  
  // Then collect created/installed templates
  const created = templates.filter(t => t.status === 'created' || t.status === 'installed');
  created.forEach((t) => {
    const key = `${t.template_name}|||${t.version}`;
    if (!rowTemplates.has(key)) {
      rowTemplates.set(key, { template_name: t.template_name, version: t.version, repo_name: t.repo_name });
    }
  });
  
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
    // Button should be enabled if there are options OR if all rows are filled (for initial install)
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
    installBtn.disabled = !hasOptions && !allFilled;
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

function updateCreateEnabled() {
  const runBtn = el('btnInstallSelected');
  if (!runBtn) return;
  
  // If we're bypassing gating conditions (configuration was loaded), always enable the button
  if (bypassGatingConditions) {
    runBtn.disabled = false;
    return;
  }
  
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
  // Enable Run button if all rows are filled (even if templates aren't created yet)
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
  r.disabled = true;
  const optRepoPh = document.createElement('option');
  optRepoPh.value = '';
  optRepoPh.textContent = 'Select';
  r.appendChild(optRepoPh);
  
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

  // Function to load repositories (can be called later if token wasn't available initially)
  const loadRepositories = async () => {
    const host = getFabricHostPrimary();
    if (!host) return false;
    
    // Check if we have a token before making API call
    const token = accessTokens.get(host);
    if (!token) {
      // No token available yet - return false to indicate we should try again later
      return false;
    }
    
    try {
      // Load repositories
      const resRepos = await api('/repo/remotes', { params: mergeAuth(host, { fabric_host: host }) });
      if (resRepos.ok) {
        const data = await resRepos.json();
        const repos = (data.repositories || []).map(x => x.name).filter(Boolean);
        // Clear existing options except the first one
        while (r.options.length > 1) {
          r.remove(1);
        }
        repos.forEach(name => {
          const o = document.createElement('option');
          o.value = name;
          o.textContent = name;
          r.appendChild(o);
        });
        r.disabled = false;
        return true;
      }
    } catch (err) {
      // Silently fail - will try again later if needed
    }
    return false;
  };
  
  // Try to populate repositories immediately
  loadRepositories();
  
  // Store loadRepositories function on the row so it can be called later if tokens become available
  r._loadRepositories = loadRepositories;

  // Handle repository change
  r.addEventListener('change', async () => {
    // reset dependent selects
    templateFiltered.populateOptions([]);
    templateFiltered.disable();
    v.innerHTML = '';
    const vph = document.createElement('option');
    vph.value = '';
    vph.textContent = 'Select version';
    v.appendChild(vph);
    v.disabled = true;
    
    const repo_name = r.value;
    const host = getFabricHostPrimary();
    if (!host || !repo_name) return;
    
    // Fallback to API only if we have a token
    const token = accessTokens.get(host);
    if (!token) {
      console.log(`No token available and no cache for repo ${repo_name}, skipping API call`);
      return;
    }
    
    try {
      try {
        const data = await apiJson('/repo/templates/list', { params: mergeAuth(host, { fabric_host: host, repo_name }) });
        const uniqueNames = Array.from(new Set((data.templates || []).map(x => x.name).filter(Boolean)));
        const templateOptions = uniqueNames.map(name => {
          const o = document.createElement('option');
          o.value = name;
          o.textContent = name;
          return o;
        });
        templateFiltered.populateOptions(templateOptions);
        templateFiltered.enable();
      } catch (error) { /* surfaced via apiJson/showStatus */ }
    } catch (error) {
      console.warn('Error loading templates from API:', error);
    }
  });

  // Handle template change
  t.addEventListener('change', async () => {
    // Don't clear version if it was set from cache
    if (v._versionSetFromCache && v.value) {
      console.log(`Template changed but version already set from cache (${v.value}), skipping reload`);
      return;
    }
    
    v.innerHTML = '';
    const vph = document.createElement('option');
    vph.value = '';
    vph.textContent = 'Select version';
    v.appendChild(vph);
    v.disabled = true;
    
    const repo_name = r.value;
    // Get template name from the filtered dropdown's getValue method
    const template_name = templateFiltered ? templateFiltered.getValue() : t.value;
    const host = getFabricHostPrimary();
    if (!host || !repo_name || !template_name) {
      console.log('Template change handler: Missing values', { host, repo_name, template_name, tValue: t.value });
      return;
    }
    
    console.log('Template change: Loading versions for', { repo_name, template_name });
    
    // LIVE API only (no cache)
    try {
      const resVer = await api('/repo/versions', { params: mergeAuth(host, { fabric_host: host, repo_name, template_name }) });
      if (resVer.ok) {
        const data = await resVer.json();
        console.log('Versions loaded:', data.versions);
        (data.versions || []).forEach(ver => {
          const o = document.createElement('option');
          o.value = ver;
          o.textContent = ver;
          v.appendChild(o);
        });
        v.disabled = false;
        // Prefill version if provided
        if (prefill && prefill.version && v.options.length > 0) {
          const versionOpt = Array.from(v.options).find(opt => opt.value === prefill.version);
          if (versionOpt) v.value = prefill.version;
        }
      } else {
        console.error('Failed to load versions:', resVer.status, resVer.statusText);
      }
    } catch (error) {
      console.error('Error loading versions:', error);
    }
  });
  
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
    console.error('content-container element not found!');
    return;
  }
  
  console.log(`Loading section: ${sectionName}`);
  const url = `/frontend/${sectionName}.html`;
  console.log(`Fetching from: ${url}`);
  
  try {
    // Fetch HTML from /frontend/ path to match backend static file serving
    const response = await fetch(url);
    console.log(`Response status: ${response.status} ${response.statusText}`);
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      console.error(`Failed to load ${sectionName}: ${response.status} ${response.statusText}`, errorText);
      container.innerHTML = `<div class="content-section"><p style="color: #f87171;">Error loading ${sectionName} section: ${response.status} ${response.statusText}</p><pre>${errorText}</pre></div>`;
      return;
    }
    
    const html = await response.text();
    console.log(`Loaded HTML (${html.length} chars):`, html.substring(0, 200));
    container.innerHTML = html;
    
    // Verify content was inserted
    console.log(`Container innerHTML length after insertion: ${container.innerHTML.length}`);
    console.log(`Container has children: ${container.children.length}`);
    if (container.children.length > 0) {
      console.log(`First child:`, container.children[0]);
    }
    
    // Wait for DOM to update, then initialize section-specific functionality
    setTimeout(() => {
      console.log(`Initializing section: ${sectionName}`);
      initializeSection(sectionName);
    }, 50);
  } catch (error) {
    console.error(`Error loading section ${sectionName}:`, error);
    container.innerHTML = `<div class="content-section"><p style="color: #f87171;">Error loading ${sectionName} section: ${error.message}</p></div>`;
  }
}

function initializeSection(sectionName) {
  // Section-specific initialization
  if (sectionName === 'configurations') {
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
  } else if (sectionName === 'preparation') {
    // Initialize preparation section
    initializePreparationSection();
  }
}

function initializePreparationSection() {
  // Initialize API base
  const apiBaseInput = el('apiBase');
  if (apiBaseInput && !apiBaseInput.value) {
    apiBaseInput.value = window.location.origin;
  }
  
  // Initialize validatedHosts array
  if (typeof validatedHosts === 'undefined') {
    validatedHosts = [];
  }
  if (!window.validatedNhiHosts) {
    window.validatedNhiHosts = [];
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
  
  // Load NHI credentials for authentication section
  loadNhiCredentialsForAuth();
  
  // Set up expert mode toggle
  const exp = el('expertMode');
  if (exp) {
    exp.addEventListener('change', () => {
      const out = el('out');
      if (out) out.style.display = exp.checked ? '' : 'none';
    });
  }
  
  // Set up button handlers for preparation section
  const loadBtn = el('btnLoadNhiCredential');
  if (loadBtn) {
    loadBtn.onclick = async () => {
      await loadSelectedNhiCredential();
    };
  }
  
  const passwordInput = el('nhiDecryptPassword');
  if (passwordInput) {
    passwordInput.onkeypress = async (e) => {
      if (e.key === 'Enter') {
        await loadSelectedNhiCredential();
      }
    };
  }
  
  const confirmBtn = el('btnConfirmHosts');
  if (confirmBtn) {
    confirmBtn.onclick = async (e) => {
      e.preventDefault();
      
      // Determine which host source to use
      const hostSourceManual = el('hostSourceManual');
      const useManualHosts = hostSourceManual && hostSourceManual.checked;
      
      let sourceInput, sourceValidatedHosts, sourceChipsId, sourceStatusId;
      
      if (useManualHosts) {
        sourceInput = el('fabricHost');
        sourceValidatedHosts = validatedHosts;
        sourceChipsId = 'fabricHostChips';
        sourceStatusId = 'fabricHostStatus';
        
        // Validate any remaining input in manual field
        if (sourceInput && sourceInput.value.trim()) {
          const currentValue = sourceInput.value.trim();
          if (!currentValue.endsWith(' ')) {
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
        }
      } else {
        sourceInput = el('fabricHostFromNhi');
        if (!window.validatedNhiHosts) window.validatedNhiHosts = [];
        sourceValidatedHosts = window.validatedNhiHosts;
        sourceChipsId = 'fabricHostFromNhiChips';
        sourceStatusId = 'fabricHostFromNhiStatus';
        
        // Validate any remaining input in NHI field
        if (sourceInput && sourceInput.value.trim()) {
          const currentValue = sourceInput.value.trim();
          populateHostsFromInput(currentValue, 'fabricHostFromNhi', sourceChipsId, sourceStatusId);
        }
      }
      
      // Check if we have any hosts from selected source
      if (sourceValidatedHosts.length === 0) { 
        showStatus(`Please add at least one valid host in the ${useManualHosts ? 'Host List' : 'NHI credential'} field`); 
        return; 
      }
      
      // Update confirmed hosts from selected source
      confirmedHosts = sourceValidatedHosts.map(({host, port}) => ({host, port}));
      
      // Also update the manual input to match (for consistency)
      const fabricHostInput = el('fabricHost');
      if (fabricHostInput) {
        const confirmedHostsStr = confirmedHosts.map(({host, port}) => 
          host + (port !== undefined ? ':' + port : '')
        ).join(' ');
        fabricHostInput.value = confirmedHostsStr;
        // Update validated hosts to match
        validatedHosts = [...sourceValidatedHosts];
        renderHostChips();
        updateValidationStatus();
      }
      
      // Make both Host List and From NHI Credential inputs readonly after confirmation
      if (fabricHostInput && fabricHostInput.value.trim()) {
        const validatedStr = validatedHosts.map(({host, port}) => 
          host + (port !== undefined ? ':' + port : '')
        ).join(' ');
        fabricHostInput.value = validatedStr;
        fabricHostInput.readOnly = true;
        fabricHostInput.disabled = false;
        fabricHostInput.style.backgroundColor = '#f5f5f7';
        fabricHostInput.style.cursor = 'not-allowed';
      }
      
      // Also make the NHI credential input readonly
      const fabricHostFromNhiInput = el('fabricHostFromNhi');
      if (fabricHostFromNhiInput && fabricHostFromNhiInput.value.trim()) {
        const nhiHostsStr = window.validatedNhiHosts && window.validatedNhiHosts.length > 0 
          ? window.validatedNhiHosts.map(({host, port}) => 
              host + (port !== undefined ? ':' + port : '')
            ).join(' ')
          : fabricHostFromNhiInput.value;
        fabricHostFromNhiInput.value = nhiHostsStr;
        fabricHostFromNhiInput.readOnly = true;
        fabricHostFromNhiInput.disabled = false;
        fabricHostFromNhiInput.style.backgroundColor = '#f5f5f7';
        fabricHostFromNhiInput.style.cursor = 'not-allowed';
      }
      
      renderFabricHostList();
      // Show the hosts list after confirmation
      const hostsListRow = el('hostsListRow');
      if (hostsListRow) hostsListRow.style.display = '';
      showStatus('Hosts confirmed. Acquiring tokens...');
      // Automatically acquire tokens after confirming hosts
      if (await acquireTokens()) {
        // Enable Add Row button after successful confirmation
        const addRowBtn = el('btnAddRow');
        if (addRowBtn) addRowBtn.disabled = false;
        showStatus('Hosts confirmed and tokens acquired. Caching templates...', { hideAfterMs: 1000 });
        
        // Cache all templates from all repositories for all confirmed hosts
        await cacheAllTemplates();
      } else {
        showStatus('Hosts confirmed but token acquisition failed. Please check credentials.');
      }
    };
  }
  
  // Set up button handlers for preparation section
  const addRowBtn = el('btnAddRow');
  if (addRowBtn) {
    addRowBtn.onclick = (e) => {
      e.preventDefault();
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
  console.log('Initializing menu, found', menuItems.length, 'menu items');
  
  if (menuItems.length === 0) {
    console.error('No menu items found!');
    return;
  }
  
  menuItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const section = item.getAttribute('data-section');
      console.log('Menu item clicked, section:', section);
      
      if (!section) {
        console.error('Menu item has no data-section attribute');
        return;
      }
      
      // Remove active class from all items
      menuItems.forEach(mi => mi.classList.remove('active'));
      
      // Add active class to clicked item
      item.classList.add('active');
      
      // Load the section HTML file
      loadSection(section);
    });
  });
  
  // Load the default section (preparation) on initial load
  const activeItem = document.querySelector('.menu-item.active');
  if (activeItem) {
    const defaultSection = activeItem.getAttribute('data-section');
    console.log('Loading default section:', defaultSection);
    if (defaultSection) {
      loadSection(defaultSection);
    }
  } else {
    console.warn('No active menu item found, defaulting to preparation');
    loadSection('preparation');
  }
}

// Display configuration name at top of page
function displayConfigName(name) {
  const display = el('configNameDisplay');
  const value = el('configNameValue');
  console.log('displayConfigName called with:', name, 'display element:', display, 'value element:', value);
  if (display && value) {
    if (name && name.trim()) {
      value.textContent = name.trim();
      display.style.display = 'block';
      console.log('Configuration name banner displayed:', name.trim());
    } else {
      display.style.display = 'none';
      console.log('Configuration name banner hidden');
    }
  } else {
    console.error('Could not find configNameDisplay or configNameValue elements');
  }
}

// Clear configuration name display
function clearConfigName() {
  displayConfigName(null);
}

// Reset all inputs in FabricStudio Preparation section
function resetPreparationSection() {
  // Reset bypass flag when resetting section
  bypassGatingConditions = false;
  
  // Reset all input fields
  const apiBase = el('apiBase');
  if (apiBase) apiBase.value = window.location.origin || '';
  
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
  const nhiDecryptPassword = el('nhiDecryptPassword');
  if (nhiDecryptPassword) nhiDecryptPassword.value = '';
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
  
  // Hide hosts list
  const hostsListRow = el('hostsListRow');
  if (hostsListRow) hostsListRow.style.display = 'none';
  
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
  accessTokens.clear();
  storedNhiTokens.clear();
  decryptedClientId = '';
  decryptedClientSecret = '';
  currentNhiId = null;
  
  // Clear fabric host list
  const fabricHostList = el('fabricHostList');
  if (fabricHostList) fabricHostList.innerHTML = '';
  
  // Clear token status
  const tokenStatus = el('tokenStatus');
  if (tokenStatus) tokenStatus.textContent = '';
  
  // Reset buttons
  const btnConfirmHosts = el('btnConfirmHosts');
  if (btnConfirmHosts) btnConfirmHosts.disabled = true;
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
      console.error('Failed to load configurations for event schedule');
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
    console.error('Error loading configurations for event schedule:', error);
  }
}

// Load and display events
async function loadEvents() {
  const eventsList = el('eventsList');
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
    
    if (events.length === 0) {
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
    events.forEach(event => {
      const eventDate = new Date(event.event_date + 'T00:00:00').toLocaleDateString();
      let dateTimeDisplay = eventDate;
      if (event.event_time) {
        // Format time (HH:MM) to a readable format
        const timeParts = event.event_time.split(':');
        const hours = parseInt(timeParts[0]);
        const minutes = timeParts[1];
        const ampm = hours >= 12 ? 'PM' : 'AM';
        const displayHours = hours % 12 || 12;
        dateTimeDisplay = `${eventDate} at ${displayHours}:${minutes} ${ampm}`;
      }
      const createdDate = new Date(event.created_at).toLocaleString();
      const updatedDate = new Date(event.updated_at).toLocaleString();
      
      html += `
        <div class="event-item" data-event-id="${event.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <input type="checkbox" class="event-checkbox" value="${event.id}" id="event-${event.id}" style="margin: 0;">
            <label for="event-${event.id}" style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">
              <span style="font-size: 16px;">${event.name}</span>
              <span style="font-size: 14px; color: #86868b; margin-left: 12px;">- ${dateTimeDisplay}</span>
              ${event.auto_run ? '<span style="font-size: 12px; color: #34d399; margin-left: 12px; font-weight: 600;">[Auto Run]</span>' : ''}
            </label>
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
    console.error('Error loading events:', error);
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
    console.error('Error deleting event:', error);
  }
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
  
  configsList.innerHTML = '<p>Loading configurations...</p>';
  
  try {
    const res = await api('/config/list');
    if (!res.ok) {
      configsList.innerHTML = '<p style="color: #f87171;">Failed to load configurations</p>';
      return;
    }
    
    const data = await res.json();
    const configs = data.configurations || [];
    
    if (configs.length === 0) {
      configsList.innerHTML = '<p>No saved configurations found. Save configurations in FabricStudio Preparation</p>';
      return;
    }
    
    // Create table/list of configurations
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';
    configs.forEach((config, idx) => {
      const createdDate = new Date(config.created_at).toLocaleString();
      const updatedDate = new Date(config.updated_at).toLocaleString();
      html += `
        <div class="config-item" data-config-id="${config.id}" style="padding: 12px; border: 1px solid #d2d2d7; border-radius: 4px; background: #f5f5f7; cursor: pointer;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <input type="checkbox" class="config-checkbox" value="${config.id}" id="config-${config.id}" style="margin: 0;">
            <label for="config-${config.id}" style="margin: 0; font-weight: 600; cursor: pointer; flex: 1;">${config.name}</label>
            <button type="button" class="btn-config-load" data-config-id="${config.id}" style="padding: 4px 12px; font-size: 12px; cursor: pointer; background: #da291c; border-color: #da291c; color: white; border: 1px solid #da291c; border-radius: 0; box-shadow: 0 2px 4px rgba(218, 41, 28, 0.3);">Load</button>
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
    
    // Add event listeners for load and edit buttons
    document.querySelectorAll('.btn-config-load').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const configIdStr = btn.getAttribute('data-config-id');
        const configId = parseInt(configIdStr);
        if (isNaN(configId)) {
          console.error('Invalid config ID:', configIdStr);
          showStatus('Error: Invalid configuration ID');
          return;
        }
        console.log('Load button clicked for config ID:', configId);
        await loadConfigurationById(configId);
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
          console.error('Invalid config ID:', configIdStr);
          showStatus('Error: Invalid configuration ID');
          return;
        }
        console.log('Edit button clicked for config ID:', configId);
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
          console.error('Invalid config ID:', configIdStr);
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

async function loadConfigurationById(configId) {
  try {
    showStatus(`Loading configuration...`);
    const getRes = await api(`/config/get/${configId}`);
    if (!getRes.ok) {
      showStatus('Failed to retrieve configuration');
      return;
    }
    
    const configData = await getRes.json();
    if (!configData || !configData.config_data) {
      showStatus('Invalid configuration data received');
      return;
    }
    
    // Clear edit mode
    editingConfigId = null;
    
    // Get the configuration name first
    const configName = configData.name || 'Unknown Configuration';
    console.log('Loading configuration with name:', configName, 'Full configData:', configData);
    
    // Display configuration name at top (before switching sections)
    displayConfigName(configName);
    
    // Switch to preparation section
    const prepItem = document.querySelector('.menu-item[data-section="preparation"]');
    if (prepItem) {
      // Check if we're already on the preparation section
      const currentSection = document.querySelector('.menu-item.active');
      const isAlreadyOnPrep = currentSection && currentSection.getAttribute('data-section') === 'preparation';
      
      if (!isAlreadyOnPrep) {
        // Click to switch to preparation section
        prepItem.click();
        console.log('Switched to preparation section');
        
        // Wait for section to load
        await new Promise(resolve => setTimeout(resolve, 300));
      }
      
      // Wait for preparation section elements to be available
      let attempts = 0;
      const maxAttempts = 50; // Increased timeout
      while (attempts < maxAttempts && !el('apiBase')) {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
      
      if (!el('apiBase')) {
        console.error('Preparation section elements not found after waiting');
        showStatus('Error: Preparation section not loaded. Please try clicking on FabricStudio Preparation manually.');
        return;
      }
      
      // Wait a bit more for section to fully initialize
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Ensure preparation section is initialized
      if (typeof initializePreparationSection === 'function') {
        // Re-initialize to ensure all handlers are set up
        initializePreparationSection();
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    } else {
      showStatus('Error: Could not find preparation section menu item');
      return;
    }
    
    // Restore configuration
    await restoreConfiguration(configData.config_data);
    showStatus(`Configuration '${configName}' loaded successfully`);
    logMsg(`Configuration loaded: ${configName}`);
  } catch (error) {
    showStatus(`Error loading configuration: ${error.message || error}`);
    logMsg(`Error loading configuration: ${error.message || error}`);
    console.error('Error loading configuration:', error);
  }
}

async function editConfiguration(configId) {
  try {
    showStatus(`Loading configuration for editing...`);
    const getRes = await api(`/config/get/${configId}`);
    if (!getRes.ok) {
      showStatus('Failed to retrieve configuration');
      return;
    }
    
    const configData = await getRes.json();
    if (!configData || !configData.config_data) {
      showStatus('Invalid configuration data received');
      return;
    }
    
    // Set edit mode
    editingConfigId = configId;
    
    // Get the configuration name and data
    const configName = configData.name || 'Unknown Configuration';
    const config = configData.config_data;
    
    console.log('Editing configuration with name:', configName, 'Full configData:', configData);
    
    // Show edit view and hide list view
    const listView = el('configsListView');
    const editView = el('configEditView');
    if (listView) listView.style.display = 'none';
    if (editView) editView.style.display = 'block';
    
    // Populate edit form (async function)
    await populateConfigEditForm(configName, config);
    
    showStatus(`Configuration '${configName}' loaded for editing`);
    logMsg(`Configuration loaded for editing: ${configName} (ID: ${configId})`);
  } catch (error) {
    showStatus(`Error loading configuration for editing: ${error.message || error}`);
    logMsg(`Error loading configuration for editing: ${error.message || error}`);
  }
}

async function populateConfigEditForm(name, config) {
  console.log('Populating edit form with config:', config);
  
  // Set configuration name
  const nameInput = el('editConfigName');
  if (nameInput) nameInput.value = name || '';
  
  // Set basic fields
  const apiBaseInput = el('editApiBase');
  if (apiBaseInput) apiBaseInput.value = config.apiBase || '';
  
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
      console.log('Created validated hosts from confirmedHosts:', window.editValidatedHosts);
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
      console.log('Created validated hosts from fabricHost string:', window.editValidatedHosts);
    } else {
      fabricHostInput.value = '';
    }
  }
  
  // Render host chips - use the global array
  const chipsContainer = el('editFabricHostChips');
  const statusSpan = el('editFabricHostStatus');
  if (window.editValidatedHosts && window.editValidatedHosts.length > 0) {
    console.log('Rendering chips for', window.editValidatedHosts.length, 'hosts');
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
  console.log('NHI Credential ID from config:', nhiCredentialId);
  
  // Store NHI credential ID for saving (will be updated when dropdown changes)
  window.editNhiCredentialId = nhiCredentialId || '';
  
  if (nhiCredentialSelect) {
    try {
      const res = await api('/nhi/list');
      if (res.ok) {
        const data = await res.json();
        const credentials = data.credentials || [];
        console.log('Loaded credentials:', credentials);
        
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
            console.log('Set NHI credential dropdown to:', credential.name);
          } else {
            console.warn('NHI credential not found with ID:', nhiCredentialId);
            // Keep the value as empty or show a message
          }
        } else {
          nhiCredentialSelect.value = '';
        }
      } else {
        nhiCredentialSelect.innerHTML = '<option value="">Error loading credentials</option>';
      }
    } catch (err) {
      console.warn('Could not load NHI credentials:', err);
      nhiCredentialSelect.innerHTML = '<option value="">Error loading credentials</option>';
    }
    
    // Update stored ID when dropdown changes (only add listener once)
    if (!nhiCredentialSelect.hasAttribute('data-listener-added')) {
      nhiCredentialSelect.addEventListener('change', () => {
        window.editNhiCredentialId = nhiCredentialSelect.value || '';
        console.log('NHI credential selection changed to:', window.editNhiCredentialId);
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
  
  // Create template rows and populate install select
  const tplFormList = el('editTplFormList');
  if (tplFormList) tplFormList.innerHTML = '';
  
  console.log('Templates from config:', config.templates);
  
  // Load cached templates to populate dropdowns
  window.editCachedTemplates = [];
  try {
    const cacheRes = await api('/cache/templates');
    if (cacheRes.ok) {
      const cacheData = await cacheRes.json();
      window.editCachedTemplates = cacheData.templates || [];
      console.log('Loaded', window.editCachedTemplates.length, 'cached templates for edit form');
    }
  } catch (error) {
    console.warn('Could not load cached templates:', error);
  }
  
  // Enable Add Row button
  const addEditRowBtn = el('btnAddEditRow');
  if (addEditRowBtn) {
    addEditRowBtn.disabled = false;
  }
  
  if (config.templates && config.templates.length > 0) {
    // Add template rows (editable, using cached templates)
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
    console.log(`Waiting ${waitTime}ms for ${rowsAdded} template rows to fully initialize...`);
    
    // Get the stored installSelect value before waiting, so we can set it during initial population
    const storedInstallSelect = config.installSelect || '';
    console.log('Stored installSelect value:', storedInstallSelect || '(none)');
    
    setTimeout(() => {
      console.log('All rows initialized. Populating dropdown with stored selection from the start...');
      // Pass the stored value - this will populate the dropdown AND set the stored value in one go
      // No visual flicker because the correct value is set during initial population
      updateEditInstallSelectFromRows(storedInstallSelect);
      
      // Verify the value was set correctly
      setTimeout(() => {
        const select = el('editInstallSelect');
        if (select && storedInstallSelect) {
          if (select.value === storedInstallSelect) {
            console.log('✓ Verified: Stored selection is correctly set:', storedInstallSelect);
          } else {
            console.warn('⚠ Warning: Stored selection may not have been set correctly. Expected:', storedInstallSelect, 'Got:', select.value);
            // Try to set it one more time if it didn't match
            const match = Array.from(select.options).find(o => o.value === storedInstallSelect);
            if (match) {
              select.value = storedInstallSelect;
              console.log('✓ Corrected: Set stored selection to:', storedInstallSelect);
            }
          }
        }
      }, 200);
    }, waitTime);
  } else {
    console.log('No templates found, showing empty dropdown');
    updateEditInstallSelect([], '');
  }
}

// Initialize editFabricHost input with same logic as fabricHost in preparation section
function initializeEditFabricHostInput() {
  let fh = el('editFabricHost');
  if (!fh) {
    console.warn('editFabricHost element not found for initialization');
    return;
  }
  
  console.log('Initializing editFabricHost input listeners');
  
  // Remove existing listeners if already initialized (clone to remove all listeners)
  if (fh.hasAttribute('data-listener-added')) {
    console.log('Removing existing listeners and re-adding');
    const newInput = fh.cloneNode(true);
    fh.parentNode.replaceChild(newInput, fh);
    // Get reference to new element
    fh = el('editFabricHost');
    if (!fh) {
      console.warn('Could not get new editFabricHost element after clone');
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
    console.log('renderEditHostChips called, validated hosts:', window.editValidatedHosts);
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
      console.log('validateAndAddEditHost: empty host text');
      return false;
    }
    
    const {host, port} = splitHostPort(hostText.trim());
    console.log('validateAndAddEditHost: parsed', {host, port, hostText});
    
    const hostOk = isValidIp(host) || isValidDomain(host);
    const portOk = port === undefined || (port >= 1 && port <= 65535);
    const isValid = hostOk && portOk;
    
    console.log('validateAndAddEditHost: validation', {hostOk, portOk, isValid});
    
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
        console.log('Added host to editValidatedHosts:', {host, port}, 'Total:', window.editValidatedHosts.length);
      } else {
        console.log('Host already exists in editValidatedHosts:', {host, port});
      }
    } else {
      console.log('Host validation failed:', {host, port, hostOk, portOk});
    }
    
    return isValid;
  }
  
  fh.addEventListener('input', (e) => {
    const value = e.target.value;
    const storedLastValue = e.target._lastEditValue || '';
    console.log('editFabricHost input event:', {value, storedLastValue, lengthDiff: value.length - storedLastValue.length, endsWithSpace: value.endsWith(' ')});
    
    if (value.length > storedLastValue.length && value.endsWith(' ')) {
      const spaceIndex = value.lastIndexOf(' ');
      const parts = value.substring(0, spaceIndex).split(/\s+/).filter(p => p.trim());
      console.log('Space detected, parts:', parts);
      if (parts.length > 0) {
        const lastHost = parts[parts.length - 1];
        console.log('Validating last host:', lastHost);
        const isValid = validateAndAddEditHost(lastHost);
        console.log('Validation result:', isValid, 'Validated hosts count:', window.editValidatedHosts ? window.editValidatedHosts.length : 0);
        if (isValid) {
          const validatedStr = window.editValidatedHosts.map(({host, port}) => 
            host + (port !== undefined ? ':' + port : '')
          ).join(' ');
          e.target.value = validatedStr + ' ';
          console.log('Updated input value to:', e.target.value);
          
          setTimeout(() => {
            e.target.setSelectionRange(e.target.value.length, e.target.value.length);
          }, 0);
        } else {
          // Remove trailing space if host is invalid
          e.target.value = value.trimEnd();
          console.log('Host invalid, removed trailing space');
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
  
  // Get unique repositories from cached templates
  const cachedTemplates = window.editCachedTemplates || [];
  const repos = Array.from(new Set(cachedTemplates.map(t => t.repo_name).filter(Boolean))).sort();
  repos.forEach(repoName => {
    const opt = document.createElement('option');
    opt.value = repoName;
    opt.textContent = repoName;
    r.appendChild(opt);
  });
  
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
    // Use window.editCachedTemplates which is set globally in populateConfigEditForm
    const cacheToUse = window.editCachedTemplates || [];
    console.log(`Repo change (${repoName}): Using cache with ${cacheToUse.length} templates`);
    const templatesForRepo = cacheToUse.filter(t => t.repo_name === repoName);
    console.log(`Repo change: Found ${templatesForRepo.length} templates for repo ${repoName}`);
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
    
    console.log(`handleTemplateChange called: repo="${repoName}", template="${templateName}"`);
    
    v.innerHTML = '';
    v.appendChild(optVerPh.cloneNode(true));
    v.disabled = true;
    
    if (!repoName || !templateName) {
      console.log('handleTemplateChange: Missing repo or template, skipping version population');
      updateEditInstallSelectFromRows();
      return;
    }
    
    // Get versions for this repo+template from cache
    // Use window.editCachedTemplates which is set in populateConfigEditForm
    const cacheToUse = window.editCachedTemplates || [];
    console.log(`handleTemplateChange: Using cache with ${cacheToUse.length} templates`);
    console.log(`handleTemplateChange: Looking for repo="${repoName}", template="${templateName}"`);
    
    const matchingTemplates = cacheToUse.filter(t => {
      const repoMatch = t.repo_name === repoName;
      const templateMatch = t.template_name === templateName;
      return repoMatch && templateMatch && t.version;
    });
    
    console.log(`handleTemplateChange: Found ${matchingTemplates.length} matching templates:`, matchingTemplates);
    
    const versions = matchingTemplates
      .map(t => t.version)
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    
    console.log(`handleTemplateChange: Extracted ${versions.length} unique versions:`, versions);
    
    versions.forEach(ver => {
      const o = document.createElement('option');
      o.value = ver;
      o.textContent = ver;
      v.appendChild(o);
    });
    
    v.disabled = false;
    console.log(`handleTemplateChange: Populated version dropdown with ${versions.length} options`);
    
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
        console.log(`Row prefill: Set repo to ${prefill.repo_name}`);
        
        setTimeout(() => {
          if (prefill.template_name) {
            templateFiltered.setValue(prefill.template_name);
            console.log(`Row prefill: Set template input to ${prefill.template_name}`);
            
            // Also set the hidden select value
            if (templateFiltered.select) {
              templateFiltered.select.value = prefill.template_name;
              console.log(`Row prefill: Set template select to ${prefill.template_name}`);
            }
            
            // Trigger change event to populate versions
            t.dispatchEvent(new Event('change'));
            
            // Manually trigger handleTemplateChange to ensure versions are populated
            console.log(`Row prefill: Manually calling handleTemplateChange to populate versions`);
            setTimeout(() => {
              handleTemplateChange();
              
              // Wait for handleTemplateChange to populate versions dropdown
              setTimeout(() => {
                console.log(`Row prefill: Checking version dropdown after handleTemplateChange, options: ${v.options.length}`);
                if (v.options.length > 1) {
                  console.log(`Row prefill: Available versions:`, Array.from(v.options).slice(1).map(o => o.value));
                }
                
                if (prefill.version && v.options.length > 1) {
                  const verOpt = Array.from(v.options).find(opt => opt.value === prefill.version);
                  if (verOpt) {
                    v.value = prefill.version;
                    v.dispatchEvent(new Event('change'));
                    console.log(`Row prefill: ✓ Set version to ${prefill.version}`);
                  } else {
                    console.warn(`Row prefill: Version ${prefill.version} not found in dropdown. Available options:`, Array.from(v.options).slice(1).map(o => o.value));
                    // Select first version if available
                    if (v.options.length > 1) {
                      v.value = v.options[1].value;
                      console.log(`Row prefill: Selected first available version: ${v.value}`);
                    }
                  }
                } else {
                  console.warn(`Row prefill: Version dropdown not populated yet (options: ${v.options.length}) or no version provided. Prefill version was: ${prefill.version}`);
                  // Select first version if available
                  if (v.options.length > 1) {
                    v.value = v.options[1].value;
                    console.log(`Row prefill: Selected first available version: ${v.value}`);
                  }
                }
                
                // Wait a bit more to ensure all values are set, then update
                setTimeout(() => {
                  console.log('Row prefilled, calling updateEditInstallSelectFromRows');
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
    console.warn('editInstallSelect not found');
    return;
  }
  
  const rows = document.querySelectorAll('#editTplFormList .tpl-row');
  console.log('updateEditInstallSelectFromRows: Found', rows.length, 'rows');
  
  if (rows.length === 0) {
    console.log('No rows found, updating with empty list');
    updateEditInstallSelect([], select.value);
    return;
  }
  
  const templates = [];
  
  rows.forEach((row, idx) => {
    console.log(`\nProcessing row ${idx + 1}:`);
    const selects = row.querySelectorAll('select');
    console.log(`  Found ${selects.length} select elements in row`);
    
    const repoSelect = selects[0];
    const templateFiltered = row._templateFiltered;
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    
    console.log(`  Elements check:`, {
      repoSelect: !!repoSelect,
      templateFiltered: !!templateFiltered,
      versionSelect: !!versionSelect,
      repoValue: repoSelect?.value || 'empty',
      versionValue: versionSelect?.value || 'empty'
    });
    
    if (!repoSelect || !templateFiltered || !versionSelect) {
      console.log(`  -> Skipped: Missing required elements`);
      return;
    }
    
    // Get repo value (for logging)
    const repo_name = (repoSelect.value || '').trim();
    console.log(`  Repo: "${repo_name}"`);
    
    // Get template name - try multiple methods
    let template_name = '';
    
    // Method 1: getValue() method
    if (templateFiltered.getValue) {
      try {
        template_name = (templateFiltered.getValue() || '').trim();
        console.log(`  Template (getValue): "${template_name}"`);
      } catch (e) {
        console.warn(`  getValue() error:`, e);
      }
    }
    
    // Method 2: Check input field value
    if (!template_name && templateFiltered.input) {
      const inputVal = (templateFiltered.input.value || '').trim();
      console.log(`  Template (input.value): "${inputVal}"`);
      if (inputVal) {
        // Try to match with datalist options
        if (templateFiltered.datalist) {
          const datalistOptions = templateFiltered.datalist.querySelectorAll('option');
          const match = Array.from(datalistOptions).find(opt => opt.value === inputVal);
          if (match) {
            template_name = inputVal;
            console.log(`  Found match in datalist`);
          }
        } else {
          template_name = inputVal;
        }
      }
    }
    
    // Method 3: Check hidden select value
    if (!template_name && templateFiltered.select) {
      const selectVal = (templateFiltered.select.value || '').trim();
      console.log(`  Template (select.value): "${selectVal}"`);
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
            console.log(`  Template (matched from datalist): "${template_name}"`);
            break;
          }
        }
      }
    }
    
    // Get version
    const version = (versionSelect.value || '').trim();
    console.log(`  Version: "${version}"`);
    
    console.log(`  Final: template="${template_name}", version="${version}"`);
    
    // Add if both template name and version are present
    if (template_name && version) {
      templates.push({ template_name, version });
      console.log(`  ✓ ADDED: ${template_name} (v${version})`);
    } else {
      const missing = [];
      if (!template_name) missing.push('template_name');
      if (!version) missing.push('version');
      console.warn(`  ✗ SKIPPED: missing ${missing.join(' and ')}`);
    }
  });
  
  console.log(`\nTotal templates collected: ${templates.length}`);
  if (templates.length > 0) {
    console.log('Templates:', templates);
  }
  
  // Update the dropdown
  // Use preserveValue if provided, otherwise try to preserve current selection
  const valueToPreserve = preserveValue !== undefined ? preserveValue : select.value;
  updateEditInstallSelect(templates, valueToPreserve);
}

function updateEditInstallSelect(templates, selectedValue) {
  const select = el('editInstallSelect');
  if (!select) {
    console.warn('updateEditInstallSelect: editInstallSelect not found');
    return;
  }
  
  console.log('updateEditInstallSelect: Called with', templates ? templates.length : 0, 'templates');
  const currentValue = select.value;
  select.innerHTML = '';
  
  if (!templates || templates.length === 0) {
    console.warn('updateEditInstallSelect: No templates provided');
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No templates available (add templates in Create Workspace above)';
    select.appendChild(opt);
    select.disabled = false;
    return;
  }
  
  console.log('updateEditInstallSelect: Processing templates:', templates);
  
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
      console.log('  Moved stored selection to first position:', selectedTemplate);
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
      console.log('  Added option:', opt.textContent);
    });
  }
  
  console.log('updateEditInstallSelect: Total options created:', select.options.length);
  
  // Restore selection if possible
  select.disabled = false;
  
  // If a selectedValue was provided (e.g., stored value from config), prioritize it
  // Otherwise, try to preserve the current selection
  const valueToRestore = selectedValue !== undefined && selectedValue !== '' ? selectedValue : (currentValue || '');
  
  if (valueToRestore) {
    const match = Array.from(select.options).find(o => o.value === valueToRestore);
    if (match) {
      select.value = valueToRestore;
      console.log('  ✓ Set selection during population:', valueToRestore);
    } else {
      // If stored value not found, log a warning
      console.warn('  ⚠ Stored selection not found in options:', valueToRestore);
      // If we have options (no placeholder), select the first one
      if (select.options.length > 0) {
        select.value = select.options[0].value;
        console.log('  Selected first available option:', select.value);
      }
    }
  } else if (select.options.length > 0) {
    // No stored value - if we have options (no placeholder), select the first one
    select.value = select.options[0].value;
    console.log('  No stored selection, selected first option:', select.value);
  }
}

function collectConfigFromEditForm() {
  // Get NHI credential ID from dropdown
  const nhiCredentialSelect = el('editNhiCredentialSelect');
  const nhiCredentialId = nhiCredentialSelect ? (nhiCredentialSelect.value || '') : (window.editNhiCredentialId || '');
  
  const config = {
    apiBase: el('editApiBase')?.value || '',
    fabricHost: el('editFabricHost')?.value || '',
    nhiCredentialId: nhiCredentialId,
    expertMode: el('editExpertMode')?.checked || false,
    newHostname: el('editNewHostname')?.value || '',
    chgPass: el('editChgPass')?.value || '',
    installSelect: el('editInstallSelect')?.value || '',
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
        console.warn('Could not retrieve original config:', err);
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
    editingConfigId = null;
    
    // Return to list view
    cancelEditConfig();
    
    // Refresh configurations list
    loadConfigurations();
  } catch (error) {
    showStatus(`Error saving configuration: ${error.message || error}`);
    logMsg(`Error saving configuration: ${error.message || error}`);
  }
}

function cancelEditConfig() {
  // Clear edit mode
  editingConfigId = null;
  
  // Show list view and hide edit view
  const listView = el('configsListView');
  const editView = el('configEditView');
  if (listView) listView.style.display = 'block';
  if (editView) editView.style.display = 'none';
  
  // Clear form
  const inputs = ['editConfigName', 'editApiBase', 'editFabricHost', 'editNewHostname', 'editChgPass'];
  inputs.forEach(id => {
    const input = el(id);
    if (input) input.value = '';
  });
  
  // Clear NHI credential dropdown
  const nhiCredentialSelect = el('editNhiCredentialSelect');
  if (nhiCredentialSelect) nhiCredentialSelect.value = '';
  
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
      showStatus('Failed to delete configuration');
      return;
    }
    
    showStatus('Configuration deleted successfully');
    logMsg(`Configuration ${configId} deleted`);
    
    // Reload configurations list
    loadConfigurations();
  } catch (error) {
    showStatus(`Error deleting configuration: ${error.message || error}`);
    logMsg(`Error deleting configuration: ${error.message || error}`);
  }
}

// Initialize without default rows
document.addEventListener('DOMContentLoaded', () => {
  initMenu();
  // initEventFormValidation() and initNhiFormValidation() are called when sections load
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
      if (out) out.style.display = exp.checked ? '' : 'none';
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
  if (!timerEl) return;
  
  if (runTimerInterval) clearInterval(runTimerInterval);
  runTimerInterval = setInterval(() => {
    if (runStartTime) {
      const elapsed = Math.floor((Date.now() - runStartTime) / 1000);
      timerEl.textContent = formatTime(elapsed);
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
}

function hideRunProgress() {
  const container = el('runProgressContainer');
  const bar = el('runProgressBar');
  if (container) container.style.display = 'none';
  if (bar) {
    // Reset progress when hiding
    bar.style.setProperty('--progress', '0%');
    bar.style.width = '0%';
  }
  stopRunTimer();
  runStartTime = null;
}

// Handler function for run button
async function handleRunButton() {
  console.log('Run button clicked');
  clearConfigName();
  const hosts = getAllConfirmedHosts();
  if (hosts.length === 0) {
    showStatus('No hosts configured. Please confirm hosts first.');
    return;
  }
  
  const runBtn = el('btnInstallSelected');
  if (runBtn) runBtn.disabled = true;
  updateRunProgress(0, 'Starting...');
  startRunTimer();
  
  // Show Running Tasks section
  const runningTasksContainer = el('runningTasksContainer');
  if (runningTasksContainer) {
    runningTasksContainer.style.display = '';
  }
  
  try {
    console.log('Run operation started');
    // STEP 1: Install Workspace (if not already installed)
    // Check if tokens are available, if not try to acquire them
    const hostsWithoutTokens = hosts.filter(({host}) => !accessTokens.has(host));
    if (hostsWithoutTokens.length > 0) {
      updateRunProgress(2, 'Acquiring tokens...');
      showStatus('Acquiring tokens for missing hosts...');
      if (!await acquireTokens()) {
        showStatus('Failed to acquire tokens. Please check credentials and confirm hosts again.');
        hideRunProgress();
        return;
      }
    }
    
    // Build templates list from ALL rows
    updateRunProgress(5, 'Collecting workspace templates from rows...');
    const allRowTemplates = [];
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
        allRowTemplates.push({ template_name, repo_name, version });
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
    
    console.log(`Total templates in rows: ${allRowTemplates.length}`);
    console.log(`Templates already created: ${existingTemplates.length}`);
    console.log(`Templates to create: ${templatesToCreate.length}`, templatesToCreate.map(t => t.template_name));
    
    // If we need to create templates, run preparation steps first
    if (templatesToCreate.length > 0) {
      // Execute preparation steps (5-20%)
      updateRunProgress(7, 'Executing preparation steps...');
      showStatus('Executing preparation steps...');
      
      // Refresh repositories
      updateRunProgress(9, 'Refreshing repositories...');
      logMsg('Refreshing repositories...');
      await executeOnAllHosts('Refresh Repositories', async (fabric_host) => {
        const res = await api('/repo/refresh', { method: 'POST', params: mergeAuth(fabric_host, { fabric_host }) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Uninstall workspaces (reset)
      updateRunProgress(11, 'Uninstalling workspaces...');
      logMsg('Uninstalling workspaces...');
      await executeOnAllHosts('Uninstall Workspaces', async (fabric_host) => {
        const res = await api('/runtime/reset', { method: 'POST', params: mergeAuth(fabric_host, { fabric_host }) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Remove workspaces (batch delete)
      updateRunProgress(13, 'Removing workspaces...');
      logMsg('Removing workspaces...');
      await executeOnAllHosts('Remove Workspaces', async (fabric_host) => {
        const res = await api('/model/fabric/batch', { method: 'DELETE', params: mergeAuth(fabric_host, { fabric_host }) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      });
      
      // Change hostname (if provided)
      const hostnameBase = el('newHostname').value.trim();
      if (hostnameBase) {
        updateRunProgress(15, 'Changing hostnames...');
        logMsg('Changing hostnames...');
        // Check for running tasks before changing hostname
        await waitForNoRunningTasks(hosts, 'Change Hostname');
        const hostnamePromises = hosts.map(async ({host}, index) => {
          try {
            const hostname = hostnameBase + (index + 1);
            const res = await api('/system/hostname', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(mergeAuth(host, { fabric_host: host, hostname }))
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
        logMsg('Changing guest user password...');
        const username = 'guest';
        await executeOnAllHosts('Change password', async (fabric_host) => {
          const res = await api('/user/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(mergeAuth(fabric_host, { fabric_host, username, new_password }))
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
      console.log(`Starting sequential creation of ${totalTemplates} templates:`, templatesToCreate.map(t => `${t.template_name} v${t.version}`));
      logMsg(`Starting sequential creation of ${totalTemplates} templates: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      
      let createdCount = 0;
      
      // Process each template one at a time
      for (let i = 0; i < templatesToCreate.length; i++) {
        const rowTemplate = templatesToCreate[i];
        console.log(`Processing template ${i + 1}/${totalTemplates}: ${rowTemplate.template_name} v${rowTemplate.version}`);
        logMsg(`[${i + 1}/${totalTemplates}] Starting creation process for ${rowTemplate.template_name} v${rowTemplate.version}`);
        
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
            console.log(`Added template to tracking: ${t.template_name} v${t.version} on ${host}`);
          } else {
            t.status = 'spin';
            t.createProgress = 0;
            t.hosts = [host];
            // Ensure host field is set correctly if it was missing or incorrect
            if (!t.host || t.host === 'host' || t.host === 'Host') {
              t.host = host;
            }
            console.log(`Found existing template entry: ${t.template_name} v${t.version} on ${host}`);
          }
        });
        renderTemplates();
        
        // Update progress for starting this template
        const templateProgress = 20 + (i / totalTemplates) * 40;
        updateRunProgress(templateProgress, `Creating template ${i + 1}/${totalTemplates}: ${rowTemplate.template_name}`);
        
        // Process all hosts for this template in parallel
        const hostPromises = hosts.map(async ({host}) => {
          console.log(`  Creating ${rowTemplate.template_name} on ${host}`);
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
            const { template_id } = await apiJson('/repo/template', { params: mergeAuth(host, {
              fabric_host: host,
              template_name: t.template_name,
              repo_name: t.repo_name,
              version: t.version,
            })});
            logMsg(`Template located on ${host}`);

            // 2) create fabric
            const createPayload = mergeAuth(host, {
              fabric_host: host,
              template_id,
              template_name: t.template_name,
              version: t.version,
            });
            console.log(`  Creating fabric on ${host} for ${t.template_name} v${t.version} with template_id ${template_id}`);
            logMsg(`Creating fabric ${t.template_name} v${t.version} on ${host} (template_id: ${template_id})`);
            
            res = await api('/model/fabric', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(createPayload),
            });
            
            console.log(`  Fabric creation response from ${host}:`, res.status, res.statusText);
            if (!res.ok) {
              const errorText = await res.text().catch(() => `HTTP ${res.status}`);
              const errorMsg = `Failed to create fabric '${t.template_name}' v${t.version} on ${host}: ${errorText}`;
              logMsg(errorMsg);
              showStatus(errorMsg);
              console.error(`  Create fabric failed on ${host}:`, errorText);
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
              return {host, success: false, error: errorText || 'Create failed'};
            }
            
            const responseData = await res.json().catch(() => ({}));
            logMsg(`Fabric creation request submitted on ${host} for ${t.template_name} v${t.version} (template_id: ${template_id})`);
            console.log(`  Fabric creation request submitted on ${host} for ${t.template_name}`, responseData);

            // 3) live poll running task count until zero or timeout for creation
            const createStart = Date.now();
            const timeoutMs = 10 * 60 * 1000; // 10 minutes
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
              const sres = await api('/tasks/status', { params: mergeAuth(host, { fabric_host: host }) });
              if (!sres.ok) { clearInterval(progressInterval); break; }
              const sdata = await sres.json();
              const cnt = sdata.running_count ?? 0;
              if (cnt === 0) { clearInterval(progressInterval); break; }
              await new Promise(r => setTimeout(r, 2000));
            }
            clearInterval(progressInterval);

            // mark status
            const done = await api('/tasks/status', { params: mergeAuth(host, { fabric_host: host }) });
            if (done.ok) {
              const d = await done.json();
              if ((d.running_count ?? 0) === 0) {
                logMsg(`Template '${t.template_name}' v${t.version} created successfully on ${host}`);
                showStatus(`Template '${t.template_name}' v${t.version} created successfully on ${host}`);
                t.status = 'created';
                t.createProgress = 100;
                renderTemplates();
                return {host, success: true};
              } else {
                const errorMsg = `Template '${t.template_name}' v${t.version} creation timeout on ${host} - tasks still running`;
                logMsg(errorMsg);
                showStatus(errorMsg);
                t.status = 'err';
                t.createProgress = 0;
                renderTemplates();
                return {host, success: false, error: 'Timeout - tasks still running'};
              }
            } else {
              const errorText = await done.text().catch(() => 'Unknown error');
              const errorMsg = `Failed to check task status on ${host} for '${t.template_name}' v${t.version}: ${errorText}`;
              logMsg(errorMsg);
              showStatus(errorMsg);
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
              return {host, success: false, error: 'Status check failed'};
            }
          } catch (error) {
            const errorMsg = `Error processing template '${rowTemplate.template_name}' v${rowTemplate.version} on ${host}: ${error.message || error}`;
            logMsg(errorMsg);
            showStatus(errorMsg);
            console.error(`Error processing ${rowTemplate.template_name} on ${host}:`, error);
            if (t) {
              t.status = 'err';
              t.createProgress = 0;
              renderTemplates();
            }
            return {host, success: false, error: error.message || error};
          }
        });

        const results = await Promise.all(hostPromises);
        const successCount = results.filter(r => r.success).length;
        
        // Collect error details for failed hosts
        const failedHosts = results.filter(r => !r.success);
        
        // Status is already updated per host in the promise handlers above
        // Just update summary messages
        if (successCount > 0) {
          createdCount++;
          if (successCount < hosts.length) {
            const failedHostNames = failedHosts.map(f => f.host).join(', ');
            showStatus(`Template '${rowTemplate.template_name}' created on ${successCount}/${hosts.length} host(s). Failed on: ${failedHostNames}`);
          }
        } else {
          const errorDetails = failedHosts.map(f => `${f.host}: ${f.error || 'Unknown error'}`).join('; ');
          const errorMsg = `Template '${rowTemplate.template_name}' v${rowTemplate.version} creation failed on all hosts: ${errorDetails}`;
          showStatus(errorMsg);
        }
        renderTemplates();
        
        if (successCount > 0) {
          logMsg(`Template '${rowTemplate.template_name}' v${rowTemplate.version} creation completed on ${successCount}/${hosts.length} host(s)`);
        } else {
          const errorDetails = failedHosts.map(f => `${f.host}: ${f.error || 'Unknown error'}`).join('; ');
          logMsg(`Template '${rowTemplate.template_name}' v${rowTemplate.version} creation failed on all hosts: ${errorDetails}`);
        }
        
        // Wait for all running tasks to complete on all hosts before proceeding to next template
        logMsg(`Waiting for all running tasks to complete before proceeding to next template...`);
        await waitForNoRunningTasks(hosts, `After creating ${rowTemplate.template_name}`);
        
        // Update overall progress
        const completedProgress = 20 + ((i + 1) / totalTemplates) * 40;
        updateRunProgress(completedProgress, `Template ${i + 1}/${totalTemplates} created: ${rowTemplate.template_name}`);
      }
      
      console.log(`Sequential template creation completed. Created: ${createdCount}/${totalTemplates}`);
      updateRunProgress(60, `All workspace templates processed: ${createdCount}/${totalTemplates} created successfully`);
      renderTemplates();
      
      if (createdCount === totalTemplates) {
        showStatus(`Created all ${templatesToCreate.length} workspace template(s) successfully`);
        logMsg(`Created all ${templatesToCreate.length} workspace template(s) successfully: ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      } else {
        showStatus(`Created ${createdCount}/${templatesToCreate.length} workspace template(s) successfully`);
        logMsg(`Created ${createdCount}/${templatesToCreate.length} workspace template(s): ${templatesToCreate.map(t => t.template_name).join(', ')}`);
      }
    } else {
      // All templates already exist, skip creation
      updateRunProgress(60, 'All workspace templates already exist');
      logMsg('All workspace templates already created, skipping creation phase');
      showStatus('All workspace templates already exist');
    }
    
    // STEP 2: Install the selected workspace (60-100%)
    updateRunProgress(62, 'Preparing to install selected workspace...');
    const opt = el('installSelect').value;
    console.log('Selected template option:', opt);
    
    let template_name, version, repo_name;
    if (!opt) {
      // Auto-select first option from dropdown or first created template
      const select = el('installSelect');
      if (select && select.options.length > 0 && select.options[0].value) {
        [template_name, version] = select.options[0].value.split('|||');
        console.log('Auto-selected from dropdown:', template_name, version);
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
        console.log('Auto-selected from created templates:', template_name, version);
      }
    } else {
      [template_name, version] = opt.split('|||');
      console.log('Using selected template:', template_name, version);
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
    hosts.forEach(({host}) => {
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
    
    updateRunProgress(65, 'Installing workspace...');
    showStatus(`Installing workspace: ${template_name} v${version}...`);
    logMsg(`Starting workspace installation: ${template_name} v${version}`);
    
    // Check for running tasks before installing workspace
    await waitForNoRunningTasks(hosts, 'Install Workspace');
    
    if (!template_name || !version) {
      showStatus('Error: Template name and version are required');
      logMsg('Error: Missing template_name or version');
      console.error('Missing template info:', { template_name, version });
      hideRunProgress();
      stopRunTimer();
      return;
    }
    
    // Verify we have tokens for all hosts
    const hostsMissingTokens = hosts.filter(({host}) => !accessTokens.has(host));
    if (hostsMissingTokens.length > 0) {
      showStatus(`Error: Missing tokens for hosts: ${hostsMissingTokens.map(h => h.host).join(', ')}`);
      logMsg(`Error: Missing tokens for ${hostsMissingTokens.length} host(s)`);
      console.error('Hosts missing tokens:', hostsMissingTokens);
      hideRunProgress();
      stopRunTimer();
      return;
    }
    
    updateRunProgress(70, `Installing workspace: ${template_name} v${version}`);
    const totalHosts = hosts.length;
    const hostProgressMap = new Map(); // Track individual host progress
    
    console.log(`Starting installation on ${totalHosts} host(s) for ${template_name} v${version}`);
    logMsg(`Installing workspace ${template_name} v${version} on ${totalHosts} host(s)`);
    
    // Install on all hosts in parallel
    const installPromises = installTargets.map(async ({target, host}, hostIdx) => {
      try {
        const installStart = Date.now();
        const token = accessTokens.get(host);
        if (!token) {
          logMsg(`Skipping ${host}: No token available`);
          console.warn(`No token for host ${host}`);
          hostProgressMap.set(host, 100);
          target.status = 'err';
          target.installProgress = 0;
          renderTemplates();
          return {host, success: false, error: 'No token'};
        }
        
        const installPayload = {
          fabric_host: host,
          access_token: token,
          template_name,
          version,
        };
        console.log(`Installing workspace on ${host}:`, { fabric_host: host, template_name, version, has_token: !!token });
        logMsg(`Sending install request to ${host} for ${template_name} v${version}`);
        
        const res = await api('/runtime/fabric/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(installPayload),
        });
        
        console.log(`Install response from ${host}:`, res.status, res.statusText);
        if (!res.ok) {
          const errorText = await res.text();
          logMsg(`Install workspace failed on ${host}: HTTP ${res.status} - ${errorText}`);
          console.error(`Install failed on ${host}:`, errorText);
          hostProgressMap.set(host, 100); // Mark as done (failed)
          target.status = 'err';
          target.installProgress = 0;
          renderTemplates();
          return {host, success: false, error: `Install failed: HTTP ${res.status}`};
        }
        logMsg(`Workspace installation requested successfully on ${host}`);
        
        // Progress tracking with 10 minutes assumption
        const timeoutMs = 10 * 60 * 1000; // 10 minutes
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
          const sres = await api('/tasks/status', { params: mergeAuth(host, { fabric_host: host }) });
          if (!sres.ok) { clearInterval(progressInterval); break; }
          const sdata = await sres.json();
          const cnt = sdata.running_count ?? 0;
          if (cnt === 0) { clearInterval(progressInterval); break; }
          await new Promise(r => setTimeout(r, 2000));
        }
        clearInterval(progressInterval);
        
        const done = await api('/tasks/status', { params: mergeAuth(host, { fabric_host: host }) });
        hostProgressMap.set(host, 100); // Mark as completed
        if (done.ok) {
          const d = await done.json();
          if ((d.running_count ?? 0) === 0) {
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
        console.error(`Error installing on ${host}:`, error);
        hostProgressMap.set(host, 100); // Mark as done (error)
        target.status = 'err';
        target.installProgress = 0;
        renderTemplates();
        return {host, success: false, error: error.message || error};
      }
    });

    const results = await Promise.all(installPromises);
    const successCount = results.filter(r => r.success).length;
    
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
    console.error('Error in Run operation:', error);
    logMsg(`Run operation error: ${error.message || error}`);
    showStatus(`Error: ${error.message || error}`);
    hideRunProgress();
    stopRunTimer();
  } finally {
    // Re-enable button - check if we have options in dropdown or filled rows
    updateInstallSelect(); // This will update button state
    const runBtn = el('btnInstallSelected');
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
  const apiBaseInput = el('apiBase');
  const fabricHostInput = el('fabricHost');
  const nhiSelect = el('nhiCredentialSelect');
  const expertModeInput = el('expertMode');
  const newHostnameInput = el('newHostname');
  const chgPassInput = el('chgPass');
  const installSelectInput = el('installSelect');
  
  // Ensure confirmedHosts is an array to avoid errors
  const hostsArray = Array.isArray(confirmedHosts) ? confirmedHosts : [];
  
  let config = {
    apiBase: apiBaseInput ? apiBaseInput.value : '',
    fabricHost: fabricHostInput ? fabricHostInput.value : '',
    nhiCredentialId: nhiSelect ? (nhiSelect.value || '') : '',
    // Note: We don't save decrypted credentials or encryption password for security reasons
    // User must load NHI credential with password after restoring configuration
    expertMode: expertModeInput ? expertModeInput.checked : false,
    newHostname: newHostnameInput ? newHostnameInput.value : '',
    chgPass: chgPassInput ? chgPassInput.value : '',
    confirmedHosts: hostsArray.map(h => ({ host: h.host, port: h.port })),
    installSelect: installSelectInput ? installSelectInput.value : '',
    templates: []
  };
  
  // Collect all template rows (even if empty)
  document.querySelectorAll('.tpl-row').forEach(row => {
    const selects = row.querySelectorAll('select');
    const repoSelect = selects[0]; // Repo is the first select
    const templateFiltered = row._templateFiltered;
    // Version is the last select (hidden template select is at index 1)
    const versionSelect = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
    if (versionSelect) {
      const repo_name = repoSelect?.value || '';
      const template_name = templateFiltered ? templateFiltered.getValue() : '';
      const version = versionSelect?.value || '';
      config.templates.push({ repo_name, template_name, version });
    }
  });
  
  return config;
}

async function restoreConfiguration(config) {
  try {
    console.log('Restoring configuration:', config);
    
    // Ensure preparation section is loaded - wait for elements to exist
    let attempts = 0;
    while (attempts < 30 && !el('apiBase')) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    
    if (!el('apiBase')) {
      console.error('Preparation section elements not found after waiting');
      showStatus('Error: Preparation section not loaded. Please try again.');
      return;
    }
    
    // Restore apiBase FIRST before any API calls are made
    const apiBaseInput = el('apiBase');
    if (apiBaseInput && config.apiBase !== undefined && config.apiBase) {
      apiBaseInput.value = config.apiBase;
      console.log('Restored apiBase:', config.apiBase);
    }
    
    // Restore other basic fields - always safe, no API calls
    const fabricHostInput = el('fabricHost');
    if (fabricHostInput && config.fabricHost !== undefined) {
      fabricHostInput.value = config.fabricHost || '';
      console.log('Restored fabricHost:', config.fabricHost);
    }
    
    const expertModeInput = el('expertMode');
    if (expertModeInput && config.expertMode !== undefined) {
      expertModeInput.checked = config.expertMode || false;
      console.log('Restored expertMode:', config.expertMode);
    }
    
    // Restore NHI credential selection if available, and auto-load with password prompt
    if (config.nhiCredentialId) {
      const nhiSelect = el('nhiCredentialSelect');
      if (nhiSelect) {
        // Ensure list is fresh, then set value
        await loadNhiCredentialsForAuth();
        nhiSelect.value = String(config.nhiCredentialId);
        // Take Encryption Password from input to load the credential
        try {
          const pwdInput = el('nhiDecryptPassword');
          const pwd = pwdInput ? (pwdInput.value || '').trim() : '';
          if (pwd) {
            const res = await api(`/nhi/get/${config.nhiCredentialId}?encryption_password=${encodeURIComponent(pwd)}`);
            if (res.ok) {
              const nhiData = await res.json();
              decryptedClientId = nhiData.client_id || '';
              decryptedClientSecret = nhiData.client_secret || '';
              currentNhiId = parseInt(config.nhiCredentialId);
              storedNhiTokens.clear();
              if (nhiData.tokens_by_host) {
                for (const [host, tokenInfo] of Object.entries(nhiData.tokens_by_host)) {
                  storedNhiTokens.set(host, { token: tokenInfo.token, expires_at: tokenInfo.expires_at });
                }
              }
              // Enable confirm button now that credentials are loaded
              const confirmBtn = el('btnConfirmHosts');
              if (confirmBtn) confirmBtn.disabled = false;
              showStatus('NHI credential loaded for configuration');
            } else {
              const errText = await res.text().catch(() => 'Failed to load NHI credential');
              showStatus(`Failed to load NHI credential: ${errText}`);
            }
          } else {
            showStatus('Enter Encryption Password to load NHI credential for this configuration');
          }
        } catch (e) {
          console.error('Error auto-loading NHI credential:', e);
          showStatus('Error loading NHI credential for configuration');
        }
      }
    }
    const newHostnameInput = el('newHostname');
    if (newHostnameInput && config.newHostname !== undefined) {
      newHostnameInput.value = config.newHostname || '';
      console.log('Restored newHostname:', config.newHostname);
    }
    
    const chgPassInput = el('chgPass');
    if (chgPassInput && config.chgPass !== undefined) {
      chgPassInput.value = config.chgPass || '';
      console.log('Restored chgPass');
    }
    
    // Update expert mode visibility
    const out = el('out');
    if (out) {
      out.style.display = el('expertMode').checked ? 'block' : 'none';
    }
    
    // Restore confirmed hosts and validated hosts if available
    try {
      if (config.confirmedHosts && config.confirmedHosts.length > 0) {
        // Restore confirmed hosts
        confirmedHosts = config.confirmedHosts.map(h => ({ host: h.host, port: h.port }));
        
        // Also restore validatedHosts for chip display
        validatedHosts = config.confirmedHosts.map(h => ({ 
          host: h.host, 
          port: h.port, 
          isValid: true 
        }));
        
        // Render the host list and chips
        renderFabricHostList();
        renderHostChips();
        
        // Also update the fabricHost input to show the hosts as space-separated
        if (fabricHostInput) {
          const hostString = validatedHosts.map(({host, port}) => 
            host + (port !== undefined ? ':' + port : '')
          ).join(' ');
          fabricHostInput.value = hostString;
        }
      } else if (config.fabricHost && fabricHostInput) {
        // If we have fabricHost string, populate it and parse
        fabricHostInput.value = config.fabricHost;
        populateHostsFromInput(config.fabricHost, 'fabricHost', 'fabricHostChips', 'fabricHostStatus');
        
        // Parse and confirm hosts from fabricHost input
        const hosts = parseFabricHosts();
        confirmedHosts = hosts.map(h => ({ host: h.host, port: h.port }));
        validatedHosts = hosts.map(h => ({ host: h.host, port: h.port, isValid: true }));
        renderFabricHostList();
        renderHostChips();
      }
    } catch (err) {
      logMsg(`Warning: Error restoring hosts: ${err.message || err}`);
      console.error('Error restoring hosts:', err);
    }
    
    // Note: User must load NHI credential with password to decrypt credentials
    // We don't auto-load encrypted credentials for security reasons
    
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
      console.log('Loaded', cachedTemplates.length, 'cached templates for restoration');
      
      // Log sample of cached templates for debugging
      if (cachedTemplates.length > 0) {
        console.log('Sample cached templates (first 5):', cachedTemplates.slice(0, 5).map(t => ({
          repo_name: t.repo_name,
          template_name: t.template_name,
          version: t.version
        })));
      }
    } catch (error) {
      console.warn('Could not load cached templates:', error);
    }
    
    // Restore template rows sequentially - use cached templates if API not available
    if (config.templates && config.templates.length > 0) {
      console.log(`Restoring ${config.templates.length} template row(s)`);
      
      // First, try to populate repositories from cache or API
      const host = getFabricHostPrimary();
      const token = host ? accessTokens.get(host) : null;
      let availableRepos = [];
      
      if (cachedTemplates.length > 0) {
        // Get unique repos from cache
        availableRepos = Array.from(new Set(cachedTemplates.map(t => t.repo_name).filter(Boolean))).sort();
        console.log('Using', availableRepos.length, 'repositories from cache');
      } else if (host && token) {
        // Try to load from API
        try {
          const reposRes = await api('/repo/remotes', { params: mergeAuth(host, { fabric_host: host }) });
          if (reposRes.ok) {
            const reposData = await reposRes.json();
            availableRepos = (reposData.repositories || []).map(r => r.name).filter(Boolean);
            console.log('Loaded', availableRepos.length, 'repositories from API');
          }
        } catch (err) {
          console.warn('Could not load repositories from API:', err);
        }
      }
      
      for (let i = 0; i < config.templates.length; i++) {
        try {
          const {repo_name, template_name, version} = config.templates[i];
          console.log(`Restoring template row ${i + 1}/${config.templates.length}:`, {repo_name, template_name, version});
          
          // Check if repo_name and template_name are valid (non-empty strings)
          // Version can be empty, but if it is, we'll try to restore anyway and let the user select a version
          if (!repo_name || !template_name || (typeof repo_name !== 'string') || (typeof template_name !== 'string')) {
            console.log(`Skipping incomplete template row ${i + 1}: missing or invalid repo_name or template_name`);
            continue;
          }
          
          // Trim strings to handle whitespace-only values
          const trimmedRepo = repo_name.trim();
          const trimmedTemplate = template_name.trim();
          const trimmedVersion = (version && typeof version === 'string') ? version.trim() : '';
          
          if (!trimmedRepo || !trimmedTemplate) {
            console.log(`Skipping incomplete template row ${i + 1}: repo_name or template_name is empty after trimming`);
            continue;
          }
          
          // Use trimmed values
          const finalRepo = trimmedRepo;
          const finalTemplate = trimmedTemplate;
          const finalVersion = trimmedVersion;
          
          // Add the row first
          try {
            addTplRow({ repo_name: finalRepo, template_name: finalTemplate, version: finalVersion });
            console.log(`Added template row ${i + 1} with prefill (repo: ${finalRepo}, template: ${finalTemplate}, version: ${finalVersion || 'empty'})`);
            
            // Get the row we just added
            await new Promise(resolve => setTimeout(resolve, 200));
            const rows = document.querySelectorAll('.tpl-row');
            if (rows.length === 0) {
              console.warn(`Could not find added row ${i + 1}`);
              continue;
            }
            
            const currentRow = rows[rows.length - 1];
            const selects = currentRow.querySelectorAll('select');
            const r = selects[0]; // Repo is the first select
            const templateFiltered = currentRow._templateFiltered;
            const v = selects.length > 2 ? selects[selects.length - 1] : (selects[1] || null);
            
            if (!r || !templateFiltered || !v) {
              console.warn(`Row ${i + 1} missing required elements (repo, template, or version dropdown)`);
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
                console.log(`Populated ${availableRepos.length} repositories from cache for row ${i + 1}`);
              }
              
              // Set repo value WITHOUT triggering change event to avoid API calls
              if (availableRepos.includes(repo_name)) {
                // Temporarily remove event listeners to prevent API calls
                const originalValue = r.value;
                r.value = repo_name;
                console.log(`Set repo to ${repo_name} for row ${i + 1} (no API calls)`);
                
                // Populate templates for this repo from cache directly
                await new Promise(resolve => setTimeout(resolve, 100));
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
                console.log(`Populated ${uniqueNames.length} templates from cache for repo ${repo_name}`);
                
                // Set template value
                if (uniqueNames.includes(template_name)) {
                  await new Promise(resolve => setTimeout(resolve, 100));
                  
                  // Set template value WITHOUT triggering change events that would try to load from API
                  // We're using cache, so we'll populate versions directly from cache
                  templateFiltered.input.value = template_name;
                  if (templateFiltered.select) {
                    templateFiltered.select.value = template_name;
                  }
                  // Update datalist to show the value
                  if (templateFiltered.datalist) {
                    templateFiltered.updateDatalist();
                  }
                  console.log(`Set template to ${template_name} for row ${i + 1} (no API calls)`);
                  
                  // Populate versions for this repo+template from cache
                  await new Promise(resolve => setTimeout(resolve, 100));
                  
                  // Get all matching templates from cache
                  const matchingTemplates = cachedTemplates.filter(t => 
                    t.repo_name === repo_name && 
                    t.template_name === template_name && 
                    t.version && 
                    t.version.trim() !== ''
                  );
                  
                  console.log(`Looking for versions in cache: repo="${repo_name}", template="${template_name}"`);
                  console.log(`  Found ${matchingTemplates.length} matching templates:`, matchingTemplates.map(t => ({ repo: t.repo_name, template: t.template_name, version: t.version })));
                  
                  const versions = Array.from(new Set(matchingTemplates.map(t => t.version.trim())))
                    .filter(Boolean)
                    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
                  
                  console.log(`  Extracted ${versions.length} unique versions:`, versions);
                  
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
                      console.log(`    Added version option: ${ver}`);
                    });
                    v.disabled = false;
                    console.log(`✓ Populated ${versions.length} versions from cache for ${repo_name}/${template_name}`);
                  } else {
                    console.warn(`⚠ No versions found in cache for ${repo_name}/${template_name}`);
                    v.disabled = true;
                  }
                  
                  // Set version value (don't dispatch change event to avoid triggering updateInstallSelect too early)
                  // Always select a version if available, even if not specified in config
                  if (versions.length > 0) {
                    if (finalVersion && versions.includes(finalVersion)) {
                      await new Promise(resolve => setTimeout(resolve, 100));
                      v.value = finalVersion;
                      console.log(`✓ Set version to ${finalVersion} for row ${i + 1}`);
                    } else if (finalVersion) {
                      console.warn(`Version ${finalVersion} not found in cache for ${repo_name}/${template_name}. Available:`, versions);
                      // Select first version if available
                      if (v.options.length > 1) {
                        v.value = v.options[1].value;
                        console.log(`✓ Selected first available version: ${v.value} for row ${i + 1}`);
                      }
                    } else {
                      // No version specified in config - select first available
                      if (v.options.length > 1) {
                        v.value = v.options[1].value;
                        console.log(`✓ Auto-selected first available version: ${v.value} for row ${i + 1} (no version in config)`);
                      }
                    }
                    
                    // Double-check version is set
                    if (!v.value && v.options.length > 1) {
                      v.value = v.options[1].value;
                      console.log(`✓ Re-check: Set version to ${v.value} for row ${i + 1}`);
                    }
                    
                    // Store that we've set the version to prevent it from being cleared
                    v._versionSetFromCache = true;
                    
                    console.log(`✓ Final version for row ${i + 1}: ${v.value} (options: ${v.options.length})`);
                  } else {
                    console.warn(`⚠ Version dropdown has no options for row ${i + 1} (repo: ${repo_name}, template: ${template_name})`);
                  }
                } else {
                  console.warn(`Template ${template_name} not found in cache for repo ${repo_name}`);
                }
              } else {
                console.warn(`Repo ${repo_name} not found in cached repositories`);
              }
              
            } else {
              // Fallback to API-based loading if no cache
              // Load repositories if needed
              if (r._loadRepositories) {
                try {
                  if (host && token) {
                    console.log(`Loading repositories for row ${i + 1}...`);
                    const loaded = await r._loadRepositories();
                    if (loaded) {
                      // Wait for repos to populate
                      let repoAttempts = 0;
                      while (r.options.length <= 1 && repoAttempts < 30) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                        repoAttempts++;
                      }
                      console.log(`Repositories loaded for row ${i + 1}, found ${r.options.length} options`);
                    }
                  }
                } catch (err) {
                  console.warn(`Could not load repositories for row ${i + 1}:`, err);
                }
              }
              
              // Fallback: Set repo value and let event handlers populate templates/versions (may trigger API calls)
              // Only do this if we have tokens available
              if (finalRepo && host && token) {
                const repoOpt = Array.from(r.options).find(opt => opt.value === finalRepo);
                if (repoOpt) {
                  r.value = finalRepo;
                  r.dispatchEvent(new Event('change'));
                  await new Promise(resolve => setTimeout(resolve, 1000));
                }
              } else if (finalRepo) {
                // No token - skip API calls, just log warning
                console.warn(`Skipping API calls for row ${i + 1} (no token available). Using cached data only.`);
              }
              
              // Set template value if not already set from cache path above
              if (finalTemplate && templateFiltered) {
                const currentTemplate = templateFiltered.getValue();
                if (currentTemplate !== finalTemplate) {
                  await new Promise(resolve => setTimeout(resolve, 300));
                  templateFiltered.setValue(finalTemplate);
                  // Only dispatch change if we're using API path (have token)
                  if (host && token) {
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
                  if (host && token) {
                    v.dispatchEvent(new Event('change'));
                  }
                  console.log(`Set version to ${finalVersion} for row ${i + 1}`);
                } else {
                  console.warn(`Version ${finalVersion} not found in dropdown for row ${i + 1}. Available:`, Array.from(v.options).map(o => o.value));
                  // Select first version if available
                  if (v.options.length > 1) {
                    v.value = v.options[1].value;
                    console.log(`Selected first available version: ${v.value} for row ${i + 1}`);
                  }
                }
              } else if (v.options.length > 1) {
                // No version specified - select first available version
                v.value = v.options[1].value;
                console.log(`No version specified for row ${i + 1}, selected first available: ${v.value}`);
              }
            }
            
            // Verify final values and ensure version is set
            await new Promise(resolve => setTimeout(resolve, 300));
            
            // Double-check version is set - if not, try to set it again
            if (!v.value && v.options.length > 1) {
              v.value = v.options[1].value;
              console.log(`✓ Re-check: Set version to ${v.value} for row ${i + 1}`);
            }
            
            console.log(`Row ${i + 1} restoration complete. Final values:`, {
              repo: r.value,
              template: templateFiltered ? templateFiltered.getValue() : 'N/A',
              version: v.value || '(empty - this will cause issues!)',
              versionOptions: v.options.length
            });
            
            // Wait before adding next row
            await new Promise(resolve => setTimeout(resolve, 300));
          } catch (err) {
            logMsg(`Warning: Error adding template row ${i + 1}: ${err.message || err}`);
            console.error(`Error adding template row ${i + 1}:`, err);
            continue;
          }
        } catch (err) {
          logMsg(`Warning: Error restoring template row ${i + 1}: ${err.message || err}`);
          console.error(`Error restoring template row ${i + 1}:`, err);
        }
      }
      
      console.log(`Finished restoring ${config.templates.length} template row(s)`);
      
      // Shorter wait before updating install select - we've already set all values from cache
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Verify all rows were restored correctly and ensure versions are set
      const finalRows = document.querySelectorAll('.tpl-row');
      console.log(`Verification: Found ${finalRows.length} template rows in DOM`);
      
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
            console.log(`✓ Fixed: Set version to ${version} for row ${idx + 1}`);
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
              console.log(`✓ Populated and set version to ${versions[0]} for row ${idx + 1}`);
            }
          }
        }
      });
      
      // Minimal wait - values are already set from cache
      await new Promise(resolve => setTimeout(resolve, 100));
      
    } else {
      console.log('No templates to restore in configuration');
    }
    
    // Update install select dropdown with restored templates
    try {
      console.log('Updating install select dropdown...');
      
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
            console.log('✓ Restored install select value:', config.installSelect);
          } else {
            console.warn('Install select value not found:', config.installSelect);
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
            console.log('✓ Restored install select value (retry):', config.installSelect);
          }
        }
      }
    } catch (err) {
      logMsg(`Warning: Error updating install select: ${err.message || err}`);
      console.error('Error updating install select:', err);
    }
    
    // Bypass all gating conditions - enable all buttons and inputs
    console.log('Bypassing all gating conditions after configuration restore...');
    
    // Set flag to bypass gating conditions
    bypassGatingConditions = true;
    
    // Enable Confirm button (normally disabled until NHI credential is loaded)
    const btnConfirmHosts = el('btnConfirmHosts');
    if (btnConfirmHosts) {
      btnConfirmHosts.disabled = false;
      console.log('Enabled Confirm button (gating bypassed)');
    }
    
    // Enable Add Row button (normally disabled until hosts are confirmed)
    const btnAddRow = el('btnAddRow');
    if (btnAddRow) {
      btnAddRow.disabled = false;
      console.log('Enabled Add Row button (gating bypassed)');
    }
    
    // Enable Run button (normally disabled based on template rows being filled)
    const btnRun = el('btnInstallSelected');
    if (btnRun) {
      btnRun.disabled = false;
      console.log('Enabled Run button (gating bypassed)');
    }
    
    // Enable Install Select dropdown (normally disabled initially)
    const installSelect = el('installSelect');
    if (installSelect) {
      installSelect.disabled = false;
      console.log('Enabled Install Select dropdown (gating bypassed)');
    }
    
    // Enable all other buttons that might be disabled by setActionsEnabled
    // Call setActionsEnabled(true) to ensure all buttons are enabled
    setActionsEnabled(true);
    
    // Call updateCreateEnabled to ensure it respects the bypass flag
    updateCreateEnabled();
    
    showStatus('Configuration restored successfully - all gating conditions bypassed');
    logMsg('Configuration restored - all gating conditions bypassed, all buttons enabled');
  } catch (error) {
    // Catch any unexpected errors and still enable buttons
    logMsg(`Error during restore: ${error.message || error}`);
    showStatus('Configuration partially restored - some errors occurred, but buttons are enabled');
    
    // Still enable buttons even if restore had errors
    const btnConfirmHosts = el('btnConfirmHosts');
    if (btnConfirmHosts) btnConfirmHosts.disabled = false;
    
    const btnAddRow = el('btnAddRow');
    if (btnAddRow) btnAddRow.disabled = false;
    
    const btnRun = el('btnInstallSelected');
    if (btnRun) btnRun.disabled = false;
    
    const installSelect = el('installSelect');
    if (installSelect) installSelect.disabled = false;
    
    setActionsEnabled(true);
  }
}

// Refresh configurations button - set up when section loads
function setupConfigButtons() {
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
    
    // Populate form with event data
    el('eventName').value = eventData.name || '';
    el('eventDate').value = eventData.event_date || '';
    el('eventTime').value = eventData.event_time || '';
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
  const configId = parseInt(el('eventConfigSelect').value);
  const autoRun = el('eventAutoRun').checked;
  
  if (!name) {
    showStatus('Event name is required');
    return;
  }
  
  if (!date) {
    showStatus('Event date is required');
    return;
  }
  
  if (!configId) {
    showStatus('Please select a configuration');
    return;
  }
  
  try {
    // If auto-run is enabled, ask for NHI credential password (hidden input)
    let nhiPassword = null;
    if (autoRun) {
      nhiPassword = await promptForNhiPassword('Create Event');
      if (nhiPassword === null) {
        showStatus('Event creation cancelled');
        return;
      }
    }

    const res = await api('/event/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        event_date: date,
        event_time: time || null,
        configuration_id: configId,
        auto_run: autoRun,
        nhi_password: nhiPassword || null
      })
    });
    
    if (!res.ok) {
      const errorText = await res.text();
      showStatus(`Failed to create event: ${errorText}`);
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
      const configId = parseInt(el('eventConfigSelect').value);
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
      
      if (!configId) {
        showStatus('Please select a configuration');
        return;
      }
      
      try {
        // If auto-run is enabled, ask for NHI credential password (hidden input)
        let nhiPassword = null;
        if (autoRun) {
          nhiPassword = await promptForNhiPassword('Update Event');
          if (nhiPassword === null) {
            showStatus('Event update cancelled');
            return;
          }
        }

        const res = await api('/event/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: editingEventId,
            name: name,
            event_date: date,
            event_time: time || null,
            configuration_id: configId,
            auto_run: autoRun,
            nhi_password: nhiPassword || null
          })
        });
        
        if (!res.ok) {
          const errorText = await res.text();
          showStatus(`Failed to update event: ${errorText}`);
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
  const configSelect = el('eventConfigSelect');
  
  // Only proceed if elements exist (section is loaded)
  if (!nameInput || !dateInput || !configSelect) {
    return;
  }
  
  const name = nameInput.value.trim();
  const date = dateInput.value;
  const configId = configSelect.value;
  
  // Buttons are enabled only when all required fields are filled
  const isValid = !!(name && date && configId);
  
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
  const configSelect = el('eventConfigSelect');
  
  if (nameInput) {
    nameInput.addEventListener('input', updateCreateEventButton);
    nameInput.addEventListener('change', updateCreateEventButton);
  }
  
  if (dateInput) {
    dateInput.addEventListener('change', updateCreateEventButton);
    dateInput.addEventListener('input', updateCreateEventButton);
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
    runBtn.onclick = handleRunButton;
  }
}

// Handler function for save config button
async function handleSaveConfigButton() {
  clearConfigName();
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
    console.error('Error in collectConfiguration:', error);
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
    editingConfigId = null;
    clearConfigName();
    
    // Reset all inputs in FabricStudio Preparation section
    resetPreparationSection();
    
    // Navigate to configurations section
    const configMenuItem = document.querySelector('.menu-item[data-section="configurations"]');
    if (configMenuItem) {
      configMenuItem.click(); // This will trigger the menu click handler
    }
    
    // Refresh configurations list
    loadConfigurations();
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
    nhiList.innerHTML = '<p>Loading NHI credentials...</p>';
    
    const res = await api('/nhi/list');
    if (!res.ok) {
      nhiList.innerHTML = `<p style="color: #f87171;">Error loading NHI credentials: ${res.statusText}</p>`;
      return;
    }
    
    const data = await res.json();
    const credentials = data.credentials || [];
    
    // Debug: Log credentials to see token_lifetime
    console.log('NHI Credentials loaded:', credentials.map(c => ({
      name: c.name,
      client_id: c.client_id,
      token_lifetime: c.token_lifetime
    })));
    
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
      const createdDate = new Date(cred.created_at).toLocaleString();
      const updatedDate = new Date(cred.updated_at).toLocaleString();
      
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
    console.error('Error loading NHI credentials:', error);
  }
}

async function editNhi(nhiId) {
  try {
    showStatus(`Loading NHI credential for editing...`);
    
    // Ask for encryption password (hidden while typing)
    const encryptionPassword = await promptForNhiPassword('Edit NHI Credential');
    if (!encryptionPassword) {
      showStatus('Edit cancelled - password required');
      return;
    }
    
    const getRes = await api(`/nhi/get/${nhiId}?encryption_password=${encodeURIComponent(encryptionPassword)}`);
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
    el('nhiClientSecret').value = nhiData.client_secret || '';
    el('nhiEncryptionPassword').value = encryptionPassword; // Keep password for update
    el('nhiConfirmPassword').value = encryptionPassword; // Pre-fill confirm with same password
    
    // Populate fabric hosts field with hosts that have tokens
    const fabricHostsInput = el('nhiFabricHosts');
    if (fabricHostsInput && nhiData.tokens_by_host) {
      const hosts = Object.keys(nhiData.tokens_by_host).sort();
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
    logMsg(`NHI credential loaded for editing: ${nhiData.name} (ID: ${nhiId})`);
    
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
  el('nhiClientSecret').value = '';
  el('nhiEncryptionPassword').value = '';
  el('nhiConfirmPassword').value = '';
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
    
    // Reload NHI credentials list
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
  const encryptionPassword = el('nhiEncryptionPassword').value.trim();
  const confirmPassword = el('nhiConfirmPassword').value.trim();
  
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
  
  // Validate password match
  const passwordMatchError = el('nhiPasswordMatchError');
  let passwordsMatch = true;
  if (passwordMatchError) {
    if (confirmPassword && encryptionPassword !== confirmPassword) {
      passwordMatchError.textContent = 'Passwords do not match';
      passwordMatchError.style.display = 'inline';
      passwordsMatch = false;
    } else {
      passwordMatchError.style.display = 'none';
      passwordsMatch = true;
    }
  }
  
  const isValid = nameValid && passwordsMatch && !!(name && clientId && clientSecret && encryptionPassword && confirmPassword);
  
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
  
  if (encryptionPasswordInput) {
    encryptionPasswordInput.addEventListener('input', updateNhiButtons);
    encryptionPasswordInput.addEventListener('change', updateNhiButtons);
  }
  
  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', updateNhiButtons);
    confirmPasswordInput.addEventListener('change', updateNhiButtons);
    confirmPasswordInput.addEventListener('blur', updateNhiButtons);
  }
  
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
  const encryptionPassword = el('nhiEncryptionPassword').value.trim();
  const confirmPassword = el('nhiConfirmPassword').value.trim();
  
  if (!name || !clientId || !clientSecret || !encryptionPassword || !confirmPassword) {
    showStatus('Please fill in all fields including encryption password and confirmation');
    return;
  }
  
  // Validate name format
  if (!isValidNhiName(name)) {
    showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
    return;
  }
  
  // Validate password match
  if (encryptionPassword !== confirmPassword) {
    showStatus('Passwords do not match');
    return;
  }
  
  try {
    // Get FabricStudio hosts from input field
    const fabricHostsInput = el('nhiFabricHosts');
    const fabricHosts = fabricHostsInput ? fabricHostsInput.value.trim() : '';
    
    const res = await api('/nhi/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        client_id: clientId,
        client_secret: clientSecret,
        encryption_password: encryptionPassword,
        fabric_hosts: fabricHosts  // Optional - space-separated list of hosts for token retrieval
      })
    });
    
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to save NHI credential: ${errorText}`);
      return;
    }
    
    const data = await res.json();
    showStatus(data.message || 'NHI credential saved successfully');
    logMsg(`NHI credential saved: ${name}`);
    
    // Clear form
    cancelNhiEdit();
    
    // Reload NHI credentials list
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
  const encryptionPassword = el('nhiEncryptionPassword').value.trim();
  const confirmPassword = el('nhiConfirmPassword').value.trim();
  
  if (!editingNhiId) {
    showStatus('No NHI credential selected for editing');
    return;
  }
  
  if (!name || !clientId || !clientSecret || !encryptionPassword || !confirmPassword) {
    showStatus('Please fill in all fields including encryption password and confirmation');
    return;
  }
  
  // Validate name format
  if (!isValidNhiName(name)) {
    showStatus('Name must contain only alphanumeric characters, dashes, and underscores');
    return;
  }
  
  // Validate password match
  if (encryptionPassword !== confirmPassword) {
    showStatus('Passwords do not match');
    return;
  }
  
  try {
    // Get FabricStudio hosts from input field
    const fabricHostsInput = el('nhiFabricHosts');
    const fabricHosts = fabricHostsInput ? fabricHostsInput.value.trim() : '';
    
    const res = await api('/nhi/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: editingNhiId,
        name: name,
        client_id: clientId,
        client_secret: clientSecret,
        encryption_password: encryptionPassword,
        fabric_hosts: fabricHosts  // Optional - space-separated list of hosts for token retrieval
      })
    });
    
    if (!res.ok) {
      const errorText = await res.text().catch(() => 'Unknown error');
      showStatus(`Failed to update NHI credential: ${errorText}`);
      return;
    }
    
    const data = await res.json();
    showStatus(data.message || 'NHI credential updated successfully');
    logMsg(`NHI credential updated: ${name} (ID: ${editingNhiId})`);
    
    // Clear form and exit edit mode
    cancelNhiEdit();
    
    // Reload NHI credentials list
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

