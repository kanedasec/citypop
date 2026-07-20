var socket;

const $ = id => document.getElementById(id);
const term = $('term');
let payloads = [];
let currentCat = 'all';
let engagement = null;
let loginPending = false;
let connectionAnnounced = false;
let lastSeq = 0;
let terminalPaused = false;
let pausedOutput = [];
let timestampsEnabled = false;
let preflightPayload = null;
let preflightData = null;
let runningState = null;
let workflowPayload = null;
let activeWorkflow = null;
const runtimeItems = new Set();

$('linkHost').textContent = `kali@${location.hostname || 'localhost'}`;
$('linkPort').textContent = location.port || ({'http:': '80', 'https:': '443'}[location.protocol] || '—');

function authHeaders(json = false) {
  const headers = {'X-CityPop-Token': localStorage.cityToken || ''};
  if (json) headers['Content-Type'] = 'application/json';
  return headers;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[char]);
}

function slug(value) {
  return String(value || 'engagement').replace(/[^a-zA-Z0-9_-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'engagement';
}

function formatBytes(value) {
  let bytes = Number(value || 0);
  const units = ['B', 'KB', 'MB', 'GB'];
  let index = 0;
  while (bytes >= 1024 && index < units.length - 1) { bytes /= 1024; index += 1; }
  return `${bytes.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function terminalClass(kind) {
  return {output: 'line-cy', start: 'line-hot', finished: 'line-ok'}[kind] || 'line-sys';
}

function appendLine(text, cls = 'line-sys', timestamp = null) {
  const raw = String(text ?? '').replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, '');
  const previous = term.lastElementChild;
  if (previous && previous.dataset.raw === raw && previous.dataset.cls === cls) {
    const count = Number(previous.dataset.repeat || 1) + 1;
    previous.dataset.repeat = count;
    let badge = previous.querySelector('.repeat');
    if (!badge) { badge = document.createElement('span'); badge.className = 'repeat'; previous.append(' ', badge); }
    badge.textContent = `×${count}`;
    return;
  }
  const row = document.createElement('div');
  row.className = `term-line ${cls}`;
  row.dataset.raw = raw;
  row.dataset.cls = cls;
  row.dataset.timestamp = timestamp || new Date().toISOString();
  const time = document.createElement('time');
  time.textContent = new Date(row.dataset.timestamp).toLocaleTimeString();
  time.hidden = !timestampsEnabled;
  row.append(time, document.createTextNode(raw));
  term.append(row);
  applyTerminalSearch();
  term.scrollTop = term.scrollHeight;
}

function line(text, cls = 'line-sys', timestamp = null) {
  if (terminalPaused) {
    pausedOutput.push({text, cls, timestamp});
    $('pauseTerm').textContent = `RESUME (${pausedOutput.length})`;
    return;
  }
  appendLine(text, cls, timestamp);
}

function applyTerminalSearch() {
  const query = $('termSearch').value.trim().toLowerCase();
  term.querySelectorAll('.term-line').forEach(row => {
    row.hidden = Boolean(query && !row.dataset.raw.toLowerCase().includes(query));
  });
}

function requireEngagement() {
  if (engagement) return true;
  line('! create an engagement first', 'line-warn');
  $('engagementDialog').showModal();
  return false;
}

async function login() {
  if (loginPending) return;
  loginPending = true;
  try {
    const token = $('token').value.trim();
    const response = await fetch('/api/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token}),
    });
    if (!response.ok) { $('loginMsg').textContent = 'Invalid token'; return; }
    localStorage.cityToken = token;
    const data = await response.json();
    $('login').hidden = true;
    $('app').hidden = false;
    if (!data.acknowledged && !$('ack').open) $('ack').showModal();
    connect();
    await loadPayloads();
  } catch (error) {
    $('loginMsg').textContent = 'City Pop is unreachable';
  } finally {
    loginPending = false;
  }
}

function connect() {
  if (socket) return;
  socket = io({auth: {token: localStorage.cityToken}});
  window.socket = socket;
  socket.on('connect', async () => {
    $('status').textContent = 'LINKED';
    $('led').parentElement.classList.add('live');
    if (!connectionAnnounced) { line('» secure session established', 'line-ok'); connectionAnnounced = true; }
    await recoverRuntime();
  });
  socket.on('disconnect', () => {
    $('status').textContent = 'RECONNECTING';
    $('led').parentElement.classList.remove('live');
  });
  socket.on('output', data => consumeOutput(data));
  socket.on('finished', data => {
    if (data.output) consumeOutput(data.output);
    else line(`» finished · exit ${data.exit_code} · ${data.duration_seconds || 0}s · log ${data.log}`, data.exit_code ? 'line-warn' : 'line-ok');
    setRunning(null);
    (data.artifacts || []).forEach(path => addRuntimeItem('artifact', path, path));
    finishWorkflow(data.exit_code);
  });
  socket.on('runtime_link', data => addRuntimeItem('link', data.url, data.label || data.url));
  socket.on('artifact', data => addRuntimeItem('artifact', data.path, data.path));
  socket.on('stopped', data => {
    line(data.ok ? '» operation stopped' : '! no operation was running', 'line-warn');
    if (data.ok) {
      if (activeWorkflow) activeWorkflow.stopRequested = true;
      finishWorkflow('stopped');
    }
  });
  socket.on('error', data => line(`! ${data.message}`, 'line-hot'));
}

function consumeOutput(item) {
  if (item.seq && item.seq <= lastSeq) return;
  if (item.seq) lastSeq = item.seq;
  line(item.line, terminalClass(item.kind), item.time);
}

async function recoverRuntime() {
  try {
    const response = await fetch(`/api/runtime?since=${lastSeq}`, {headers: authHeaders()});
    if (!response.ok) return;
    const data = await response.json();
    (data.output || []).forEach(consumeOutput);
    lastSeq = Math.max(lastSeq, Number(data.last_seq || 0));
    setRunning(data.running || null);
    restoreWorkflowFromRun(data.running || null);
    if (data.running?.pending_input && window.renderCityPopInput) window.renderCityPopInput(data.running.pending_input);
  } catch (error) {
    line('! unable to recover runtime state', 'line-warn');
  }
}

function setRunning(state) {
  runningState = state;
  const panel = $('runningPanel');
  const active = Boolean(state);
  panel.hidden = !active;
  $('stopCommand').disabled = !active;
  document.querySelector('.terminal').classList.toggle('is-running', active);
  if (!active) { panel.textContent = ''; return; }
  panel.innerHTML = `<div><span class="eyebrow">NOW RUNNING</span><strong>${escapeHtml(state.name || state.payload_id)}</strong><small>${escapeHtml(state.engagement || '')} · log ${escapeHtml(state.log || 'pending')}</small></div><div class="run-clock" data-start="${escapeHtml(state.started_at || '')}">${Math.round(state.elapsed_seconds || 0)}s</div>`;
}

function addRuntimeItem(type, value, label) {
  const key = `${type}:${value}`;
  if (runtimeItems.has(key)) return;
  runtimeItems.add(key);
  if (type === 'link') updateWorkflowStage('dashboard', 'done');
  if (type === 'artifact') updateWorkflowStage('artifacts', 'done');
  const box = $('runtimeLinks');
  box.hidden = false;
  const row = document.createElement('div');
  row.className = `runtime-item ${type}`;
  const title = document.createElement('span');
  title.innerHTML = `<b>${type === 'link' ? 'LIVE ENDPOINT' : 'NEW ARTIFACT'}</b><small>${escapeHtml(label)}</small>`;
  const link = document.createElement('a');
  if (type === 'link') {
    link.href = value; link.target = '_blank'; link.rel = 'noopener'; link.textContent = 'OPEN';
  } else {
    link.href = `/api/loot/download/${encodeURIComponent(value)}?token=${encodeURIComponent(localStorage.cityToken)}`;
    link.textContent = 'GET';
  }
  row.append(title, link);
  box.prepend(row);
}

async function loadPayloads() {
  const response = await fetch('/api/payloads', {headers: authHeaders()});
  if (!response.ok) return;
  const data = await response.json();
  payloads = data.payloads || [];
  const categories = [...new Set([...(data.category_order || []), ...payloads.map(item => item.category)])]
    .filter(category => payloads.some(item => item.category === category));
  $('tabs').innerHTML = `<button data-cat="all">ALL <span>${payloads.length}</span></button>${categories.map(category => `<button data-cat="${escapeHtml(category)}">${escapeHtml(category.replaceAll('_', ' '))} <span>${payloads.filter(item => item.category === category).length}</span></button>`).join('')}`;
  currentCat = currentCat === 'all' || categories.includes(currentCat) ? currentCat : 'all';
  $('workflowCategory').innerHTML = `<option value="all">All categories (${payloads.length})</option>${categories.map(category => `<option value="${escapeHtml(category)}">${escapeHtml(category.replaceAll('_', ' '))} (${payloads.filter(item => item.category === category).length})</option>`).join('')}`;
  renderWorkflowOptions();
  renderPayloads();
  if (runningState) restoreWorkflowFromRun(runningState);
}

function renderWorkflowOptions() {
  const category = $('workflowCategory').value || 'all';
  const selected = $('workflowSelect').value;
  const visible = payloads
    .filter(payload => payload.web !== false && (category === 'all' || payload.category === category))
    .sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  if (category === 'all') {
    const groups = [...new Set(visible.map(payload => payload.category))];
    $('workflowSelect').innerHTML = groups.map(group => `<optgroup label="${escapeHtml(group.replaceAll('_', ' '))}">${visible.filter(payload => payload.category === group).map(payload => `<option value="${escapeHtml(payload.id)}">${escapeHtml(payload.name)}</option>`).join('')}</optgroup>`).join('');
  } else {
    $('workflowSelect').innerHTML = visible.map(payload => `<option value="${escapeHtml(payload.id)}">${escapeHtml(payload.name)}</option>`).join('');
  }
  if (visible.some(payload => payload.id === selected)) $('workflowSelect').value = selected;
  $('workflowStart').disabled = !visible.length;
}

function favoriteIds() {
  try { return new Set(JSON.parse(localStorage.cityFavorites || '[]')); } catch (error) { return new Set(); }
}

function matchesCapability(payload, capability, favorites) {
  const text = `${payload.name} ${payload.desc} ${payload.category}`.toLowerCase();
  if (capability === 'all') return true;
  if (capability === 'favorites') return favorites.has(payload.id);
  if (capability === 'monitor') return /monitor mode|mon0|promiscuous/.test(text);
  if (capability === 'hardware') return /adapter|bluetooth|gps|sdr|nfc|usb|camera|zigbee|rfid/.test(text);
  if (capability === 'dashboard') return /dashboard|portal|web interface|http|endpoint/.test(text);
  if (capability === 'loot') return /save|loot|capture|report|export|pcap|credential/.test(text);
  return true;
}

function renderPayloads() {
  if (!engagement) { $('grid').innerHTML = '<div class="empty-state">Create or reopen an engagement to unlock the payload catalog.</div>'; return; }
  const query = $('payloadSearch').value.trim().toLowerCase();
  const impact = $('impactFilter').value;
  const capability = $('capabilityFilter').value;
  const favorites = favoriteIds();
  document.querySelectorAll('#tabs button').forEach(button => {
    const active = button.dataset.cat === currentCat;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const items = payloads.filter(payload => currentCat === 'all' || payload.category === currentCat)
    .filter(payload => !query || `${payload.name} ${payload.desc} ${payload.id}`.toLowerCase().includes(query))
    .filter(payload => impact === 'all' || (impact === 'active') === Boolean(payload.danger))
    .filter(payload => matchesCapability(payload, capability, favorites))
    .sort((a, b) => Number(favorites.has(b.id)) - Number(favorites.has(a.id)) || a.name.localeCompare(b.name));
  $('grid').innerHTML = items.map(payload => `<article class="payload-card ${payload.danger ? 'hot' : ''}"><button class="op ${payload.danger ? 'hot' : ''}" data-id="${escapeHtml(payload.id)}" ${payload.web === false ? 'disabled' : ''}><b>${escapeHtml(payload.name)}</b><small>${payload.web === false ? 'DEVICE CONTROLS ONLY · ' : ''}${escapeHtml(payload.desc)}</small><span class="impact">${payload.danger ? 'ACTIVE' : 'NORMAL'}</span></button><button type="button" class="favorite ${favorites.has(payload.id) ? 'on' : ''}" data-favorite="${escapeHtml(payload.id)}" aria-label="${favorites.has(payload.id) ? 'Remove from' : 'Add to'} favorites">★</button></article>`).join('') || '<div class="empty-state">No payloads match these filters.</div>';
}

async function showPreflight(payload) {
  if (!requireEngagement()) return;
  if (!activeWorkflow || activeWorkflow.payload.id !== payload.id) beginWorkflow(payload);
  updateWorkflowStage('preflight', 'current');
  preflightPayload = payload;
  preflightData = null;
  $('preflightTitle').textContent = `${payload.name} · PREFLIGHT`;
  $('preflightBody').innerHTML = '<div class="loading">Checking this Pi-Tail…</div>';
  $('preflightRun').disabled = true;
  $('preflightDialog').showModal();
  try {
    const response = await fetch(`/api/preflight/${encodeURIComponent(payload.id)}`, {headers: authHeaders()});
    const data = await response.json();
    preflightData = data;
    const failed = (data.checks || []).filter(check => check.blocking && !check.ok);
    $('preflightBody').innerHTML = `<div class="impact-banner ${payload.danger ? 'danger' : ''}">${payload.danger ? 'ACTIVE / HIGH-IMPACT OPERATION' : 'NORMAL OPERATION'}</div><div class="capability-summary"><span>${data.capabilities.static_inputs || 0} launch inputs</span><span>${data.capabilities.runtime_inputs || 0} runtime prompts</span><span>${data.capabilities.dashboard ? 'dashboard' : 'terminal output'}</span><span>${data.capabilities.produces_loot ? 'artifacts' : 'log only'}</span></div>${(data.checks || []).map(check => `<div class="check-row ${check.ok ? 'ok' : check.blocking ? 'bad' : 'optional'}"><i>${check.ok ? '✓' : check.blocking ? '!' : '○'}</i><span><b>${escapeHtml(check.label)}</b><small>${escapeHtml(check.detail)}${check.blocking ? '' : ' · optional'}</small></span></div>`).join('')}${(data.warnings || []).map(warning => `<p class="preflight-warning">⚠ ${escapeHtml(warning)}</p>`).join('')}${failed.length ? `<label class="preflight-override"><input id="preflightOverride" type="checkbox"><span>I reviewed ${failed.length} failed required check${failed.length === 1 ? '' : 's'} and explicitly choose to continue anyway.</span></label>` : ''}`;
    if (failed.length) {
      updateWorkflowStage('preflight', 'failed');
      $('preflightRun').disabled = true;
      $('preflightOverride').onchange = event => {
        $('preflightRun').disabled = !event.target.checked;
        updateWorkflowStage('preflight', event.target.checked ? 'override' : 'failed');
      };
    } else {
      updateWorkflowStage('preflight', 'done');
      $('preflightRun').disabled = false;
    }
  } catch (error) {
    updateWorkflowStage('preflight', 'failed');
    $('preflightBody').innerHTML = '<p class="preflight-warning">Preflight service is unavailable. Automatic verification did not complete.</p><label class="preflight-override"><input id="preflightOverride" type="checkbox"><span>I understand that preflight could not run and explicitly choose to continue.</span></label>';
    $('preflightRun').disabled = true;
    $('preflightOverride').onchange = event => {
      $('preflightRun').disabled = !event.target.checked;
      updateWorkflowStage('preflight', event.target.checked ? 'override' : 'failed');
    };
  }
}

function openPayloadOptions(payload) {
  const specs = Array.isArray(payload.inputs) ? payload.inputs : [];
  const box = $('payloadInputs');
  box.textContent = '';
  $('payloadTitle').textContent = `${payload.name} · OPTIONS`;
  $('payloadForm').dataset.id = payload.id;
  specs.forEach(spec => {
    const label = document.createElement('label');
    label.append(document.createTextNode(spec.label || spec.name || 'Value'));
    let control;
    if (spec.type === 'select') {
      control = document.createElement('select');
      (spec.choices || []).forEach(choice => {
        const option = document.createElement('option');
        option.value = typeof choice === 'object' ? choice.value : choice;
        option.textContent = typeof choice === 'object' ? choice.label : choice;
        control.append(option);
      });
    } else {
      control = document.createElement('input');
      control.type = spec.type === 'number' ? 'number' : spec.type === 'password' ? 'password' : 'text';
      control.placeholder = spec.placeholder || '';
    }
    control.dataset.payloadInput = '1';
    control.required = spec.required !== false;
    if (spec.default != null) control.value = spec.default;
    label.append(control);
    box.append(label);
  });
  if (specs.length) {
    updateWorkflowStage('configuration', 'current');
    $('payloadDialog').showModal();
  } else runPayload(payload.id, []);
}

function runPayload(id, args = []) {
  if (!requireEngagement()) return;
  socket.emit('run_payload', {
    id, args: args.map(String), target: engagement.scope, engagement: engagement.name,
    authorized: true, in_scope: true,
  });
  setRunning({payload_id: id, name: payloads.find(item => item.id === id)?.name || id, engagement: engagement.name, args, started_at: new Date().toISOString(), elapsed_seconds: 0, log: 'pending'});
  const runtimePrompts = activeWorkflow?.payload.id === id ? activeWorkflow.capabilities.runtime_inputs : 0;
  updateWorkflowStage(runtimePrompts ? 'configuration' : 'execution', 'current');
  requestAnimationFrame(() => document.querySelector('.terminal').scrollIntoView({behavior: 'smooth', block: 'start'}));
}

function renderEngagement() {
  const banner = $('engagement');
  if (!engagement) { banner.hidden = true; renderPayloads(); return; }
  banner.hidden = false;
  banner.textContent = `ENGAGEMENT · ${engagement.name} · ${engagement.date} · SCOPE: ${engagement.scope}`;
  renderPayloads();
}

async function showLoot() {
  const currentOnly = $('lootScope').value !== 'all';
  if (currentOnly && !requireEngagement()) return;
  const query = currentOnly ? `?engagement=${encodeURIComponent(engagement.name)}` : '';
  const response = await fetch(`/api/loot${query}`, {headers: authHeaders()});
  const data = await response.json();
  $('lootList').innerHTML = (data.files || []).map(file => `<div class="lootrow"><span>${escapeHtml(file.path)}<br><small>${formatBytes(file.size)}</small></span><span><a href="/api/loot/preview/${encodeURIComponent(file.path)}?token=${encodeURIComponent(localStorage.cityToken)}">view</a> · <a href="/api/loot/download/${encodeURIComponent(file.path)}?token=${encodeURIComponent(localStorage.cityToken)}">get</a> · <button type="button" class="lootdelete" data-loot="${encodeURIComponent(file.path)}">delete</button></span></div>`).join('') || 'No artifacts yet.';
  if (!$('loot').open) $('loot').showModal();
}

async function showHardware() {
  $('hardwareBody').innerHTML = '<div class="loading">Inspecting the Pi-Tail…</div>';
  $('hardwareDialog').showModal();
  const response = await fetch('/api/hardware', {headers: authHeaders()});
  const data = await response.json();
  const system = data.system || {};
  $('hardwareBody').innerHTML = `<div class="system-vitals"><div><b>${escapeHtml(system.hostname)}</b><small>HOST</small></div><div><b>${system.temperature_c == null ? '—' : `${system.temperature_c}°C`}</b><small>CPU</small></div><div><b>${formatBytes(system.memory?.available)}</b><small>RAM FREE</small></div><div><b>${formatBytes(system.disk?.free)}</b><small>DISK FREE</small></div></div><div class="hardware-flags"><span class="${system.bluetooth ? 'ok' : ''}">BT</span><span class="${system.gps ? 'ok' : ''}">GPS</span><span class="${system.sdr ? 'ok' : ''}">SDR</span><span class="${system.nfc ? 'ok' : ''}">NFC</span></div><h3>NETWORK INTERFACES</h3>${(data.interfaces || []).map(item => `<div class="interface-row ${item.default_route ? 'protected' : ''}"><div><b>${escapeHtml(item.name)}</b><small>${escapeHtml(item.driver || 'virtual')} · ${escapeHtml(item.mode || item.state)}</small></div><div><span class="state ${item.state === 'up' ? 'ok' : ''}">${escapeHtml(item.state)}</span><small>${escapeHtml((item.addresses || []).join(', ') || item.mac || 'no address')}</small></div>${item.default_route ? '<em>PROTECTED ROUTE</em>' : ''}</div>`).join('')}`;
}

async function showExecutions() {
  if (!requireEngagement()) return;
  $('executionsList').innerHTML = '<div class="loading">Loading execution timeline…</div>';
  $('executionsDialog').showModal();
  const response = await fetch(`/api/executions?engagement=${encodeURIComponent(slug(engagement.name))}`, {headers: authHeaders()});
  const data = await response.json();
  $('executionsList').innerHTML = (data.executions || []).map(item => `<div class="execution-row"><div><b>${escapeHtml(item.name)}</b><small>${new Date(item.started_at).toLocaleString()} · ${item.exit_code == null ? 'RUNNING' : `EXIT ${item.exit_code}`} · ${item.duration_seconds || 0}s</small><small>${escapeHtml(item.log || '')}</small></div>${item.payload_id !== 'command' ? `<button type="button" data-rerun="${escapeHtml(item.payload_id)}">REOPEN</button>` : ''}</div>`).join('') || 'No executions recorded for this engagement.';
}

function renderWorkflow(payload) {
  workflowPayload = payload;
  beginWorkflow(payload);
  $('workflowBody').innerHTML = `<div class="guide-heading"><span>${escapeHtml(payload.category.replaceAll('_', ' '))}</span><h3>${escapeHtml(payload.name)}</h3><p>${escapeHtml(payload.desc)}</p></div><ol class="workflow-steps">${activeWorkflow.steps.map((step, index) => `<li class="${index === 0 ? 'current' : ''}"><b>${index + 1} · ${escapeHtml(step.label)}</b><small>${escapeHtml(step.detail)}</small></li>`).join('')}</ol>`;
  $('workflowNext').textContent = 'BEGIN PREFLIGHT';
}

function workflowSteps(payload) {
  const capabilities = payload.capabilities || {};
  const dependencies = (capabilities.commands?.length || 0) + (capabilities.python_modules?.length || 0) + (capabilities.hardware?.length || 0) + (capabilities.services?.length || 0) + (capabilities.device_paths?.length || 0) + (capabilities.data_paths?.length || 0) + (capabilities.kernel_capabilities?.length || 0);
  const steps = [
    {key: 'scope', label: 'Confirm engagement scope', detail: `Use ${engagement?.name || 'the active engagement'} and verify its authorized targets.`},
    {key: 'preflight', label: 'Verify this Pi-Tail', detail: `Check ${dependencies || 'standard-library'} requirements${capabilities.hardware?.length ? ` and ${capabilities.hardware.join(', ')} hardware` : ''}.`},
  ];
  if ((capabilities.static_inputs || 0) + (capabilities.runtime_inputs || 0) > 0) {
    steps.push({key: 'configuration', label: 'Configure requested options', detail: `${capabilities.static_inputs || 0} launch input${capabilities.static_inputs === 1 ? '' : 's'} and ${capabilities.runtime_inputs || 0} possible runtime prompt${capabilities.runtime_inputs === 1 ? '' : 's'}.`});
  }
  steps.push({key: 'execution', label: 'Run and observe', detail: 'Follow live terminal output and use Stop if behavior is unexpected.'});
  if (capabilities.dashboard) steps.push({key: 'dashboard', label: 'Open live dashboard', detail: 'Use the tokenized endpoint printed in the terminal.'});
  if (capabilities.produces_loot) steps.push({key: 'artifacts', label: 'Review engagement artifacts', detail: 'Preview or download files created under this engagement.'});
  steps.push({key: 'complete', label: 'Confirm completion', detail: capabilities.produces_loot ? 'Review the exit status, log, and generated artifacts.' : 'Review the exit status and engagement log.'});
  return steps;
}

function beginWorkflow(payload) {
  activeWorkflow = {
    payload,
    capabilities: payload.capabilities || {},
    steps: workflowSteps(payload),
    status: {scope: 'done'},
    sawDashboard: false,
    sawArtifacts: false,
  };
  renderWorkflowTracker();
}

function restoreWorkflowFromRun(run) {
  if (!run || run.payload_id === 'command') return;
  const payload = payloads.find(item => item.id === run.payload_id);
  if (!payload || activeWorkflow?.payload.id === payload.id) return;
  beginWorkflow(payload);
  updateWorkflowStage('preflight', 'done');
  if (activeWorkflow.steps.some(step => step.key === 'configuration')) {
    updateWorkflowStage('configuration', run.pending_input ? 'current' : 'done');
  }
  if (!run.pending_input) updateWorkflowStage('execution', 'current');
}

function updateWorkflowStage(key, status) {
  if (!activeWorkflow || !activeWorkflow.steps.some(step => step.key === key)) return;
  if (key === 'dashboard' && status === 'done') activeWorkflow.sawDashboard = true;
  if (key === 'artifacts' && status === 'done') activeWorkflow.sawArtifacts = true;
  if (status === 'current') {
    activeWorkflow.steps.forEach(step => {
      if (activeWorkflow.status[step.key] === 'current') activeWorkflow.status[step.key] = 'done';
    });
  }
  activeWorkflow.status[key] = status;
  renderWorkflowTracker();
}

function finishWorkflow(exitCode) {
  if (!activeWorkflow) return;
  if (activeWorkflow.stopRequested && typeof exitCode === 'number' && exitCode < 0) exitCode = 'stopped';
  if (activeWorkflow.status.configuration === 'current') updateWorkflowStage('configuration', 'skipped');
  updateWorkflowStage('execution', exitCode === 0 ? 'done' : exitCode === 'stopped' ? 'stopped' : 'failed');
  if (activeWorkflow.steps.some(step => step.key === 'dashboard') && !activeWorkflow.sawDashboard) updateWorkflowStage('dashboard', 'skipped');
  if (activeWorkflow.steps.some(step => step.key === 'artifacts') && !activeWorkflow.sawArtifacts) updateWorkflowStage('artifacts', 'skipped');
  updateWorkflowStage('complete', exitCode === 0 ? 'done' : exitCode === 'stopped' ? 'stopped' : 'failed');
}

window.citypopWorkflowInputRequested = () => updateWorkflowStage('configuration', 'current');
window.citypopWorkflowInputSubmitted = () => updateWorkflowStage('execution', 'current');

function renderWorkflowTracker() {
  const tracker = $('workflowTracker');
  if (!activeWorkflow) { tracker.hidden = true; return; }
  tracker.hidden = false;
  tracker.innerHTML = `<div class="tracker-head"><span>GUIDED WORKFLOW</span><b>${escapeHtml(activeWorkflow.payload.name)}</b></div><ol>${activeWorkflow.steps.map((step, index) => { const status = activeWorkflow.status[step.key] || 'pending'; return `<li class="${status}"><i>${status === 'done' ? '✓' : status === 'failed' ? '!' : status === 'override' ? '⚠' : status === 'skipped' ? '–' : index + 1}</i><span><b>${escapeHtml(step.label)}</b><small>${status === 'override' ? 'operator override accepted' : status === 'skipped' ? 'not produced during this run' : status}</small></span></li>`; }).join('')}</ol>`;
}

function stopCurrent() {
  if (!socket) return;
  if (activeWorkflow) activeWorkflow.stopRequested = true;
  socket.emit('stop');
  line('» stop requested', 'line-warn');
}

$('loginBtn').onclick = login;
$('token').addEventListener('keydown', event => { if (event.key === 'Enter') login(); });
$('disconnect').onclick = () => { localStorage.removeItem('cityToken'); location.reload(); };
$('tabs').onclick = event => {
  const button = event.target.closest('[data-cat]');
  if (!button) return;
  const selected = button.dataset.cat;
  currentCat = selected === 'all' || currentCat === selected ? 'all' : selected;
  renderPayloads();
};
$('grid').onclick = event => {
  const favorite = event.target.closest('[data-favorite]');
  if (favorite) {
    const values = favoriteIds();
    values.has(favorite.dataset.favorite) ? values.delete(favorite.dataset.favorite) : values.add(favorite.dataset.favorite);
    localStorage.cityFavorites = JSON.stringify([...values]);
    renderPayloads();
    return;
  }
  const button = event.target.closest('[data-id]:not(:disabled)');
  if (button) showPreflight(payloads.find(item => item.id === button.dataset.id));
};
['payloadSearch', 'impactFilter', 'capabilityFilter'].forEach(id => $(id).addEventListener(id === 'payloadSearch' ? 'input' : 'change', renderPayloads));
$('preflightRun').onclick = () => {
  $('preflightDialog').close();
  if (activeWorkflow?.status.preflight === 'current') updateWorkflowStage('preflight', 'done');
  if (preflightPayload) openPayloadOptions(preflightPayload);
};
$('payloadCancel').onclick = () => $('payloadDialog').close();
$('payloadForm').onsubmit = event => {
  event.preventDefault();
  if (!event.currentTarget.reportValidity()) return;
  const args = [...$('payloadInputs').querySelectorAll('[data-payload-input]')].map(input => input.value);
  const id = event.currentTarget.dataset.id;
  $('payloadDialog').close();
  runPayload(id, args);
};

$('engage').onclick = () => { $('engDate').value = new Date().toISOString().slice(0, 10); $('engagementDialog').showModal(); };
$('engCancel').onclick = () => $('engagementDialog').close('cancel');
$('engConfirm').onclick = event => {
  event.preventDefault();
  const form = event.currentTarget.form;
  $('engName').setCustomValidity($('engName').value.trim() ? '' : 'Enter an engagement name.');
  $('engScope').setCustomValidity($('engScope').value.trim() ? '' : 'Enter the authorized scope.');
  if (!form.reportValidity()) return;
  engagement = {name: $('engName').value.trim(), date: $('engDate').value, scope: $('engScope').value.trim()};
  const history = JSON.parse(localStorage.engagements || '[]').filter(item => item.name !== engagement.name || item.date !== engagement.date);
  history.unshift(engagement);
  localStorage.engagements = JSON.stringify(history.slice(0, 50));
  sessionStorage.engagement = JSON.stringify(engagement);
  $('engagementDialog').close();
  renderEngagement();
};
$('history').onclick = () => {
  const history = JSON.parse(localStorage.engagements || '[]');
  $('historyList').innerHTML = history.length ? history.map((item, index) => `<div class="lootrow"><span><b>${escapeHtml(item.name)}</b><br>${escapeHtml(item.date)}<br><small>${escapeHtml(item.scope)}</small></span><button type="button" data-hist="${index}">REOPEN</button></div>`).join('') : 'No engagements yet.';
  $('historyDialog').showModal();
};
$('historyList').onclick = event => {
  const button = event.target.closest('[data-hist]');
  if (!button) return;
  engagement = JSON.parse(localStorage.engagements || '[]')[button.dataset.hist];
  sessionStorage.engagement = JSON.stringify(engagement);
  $('historyDialog').close();
  renderEngagement();
};
$('endEngage').onclick = () => { engagement = null; sessionStorage.removeItem('engagement'); renderEngagement(); line('» engagement ended', 'line-warn'); };

$('lootBtn').onclick = showLoot;
$('lootScope').onchange = showLoot;
$('lootList').onclick = async event => {
  const button = event.target.closest('[data-loot]');
  if (!button) return;
  const name = decodeURIComponent(button.dataset.loot);
  if (!confirm(`Delete loot file?\n\n${name}`)) return;
  const response = await fetch(`/api/loot/${encodeURIComponent(name)}`, {method: 'DELETE', headers: authHeaders()});
  if (!response.ok) { line('! loot deletion failed', 'line-hot'); return; }
  line(`» deleted loot · ${name}`, 'line-warn');
  showLoot();
};
$('deleteAllLoot').onclick = async () => {
  const currentOnly = $('lootScope').value !== 'all';
  const label = currentOnly ? `the ${engagement?.name || 'current'} engagement` : 'EVERY engagement';
  if (prompt(`Permanently delete loot for ${label}? Type DELETE ALL to confirm.`) !== 'DELETE ALL') return;
  const response = await fetch('/api/loot', {method: 'DELETE', headers: authHeaders(true), body: JSON.stringify({confirm: 'DELETE ALL', engagement: currentOnly ? engagement.name : ''})});
  if (!response.ok) { line('! loot deletion failed', 'line-hot'); return; }
  const data = await response.json();
  line(`» deleted ${data.deleted} loot file(s) · ${label}`, 'line-warn');
  showLoot();
};

$('hardwareBtn').onclick = showHardware;
$('executionsBtn').onclick = showExecutions;
$('executionsList').onclick = event => {
  const button = event.target.closest('[data-rerun]');
  if (!button) return;
  const payload = payloads.find(item => item.id === button.dataset.rerun);
  $('executionsDialog').close();
  if (payload) showPreflight(payload);
};
$('reportBtn').onclick = () => { if (requireEngagement()) { $('reportResult').textContent = ''; $('reportDialog').showModal(); } };
$('reportCancel').onclick = () => $('reportDialog').close();
$('reportForm').onsubmit = async event => {
  event.preventDefault();
  const response = await fetch('/api/report', {method: 'POST', headers: authHeaders(true), body: JSON.stringify({engagement: engagement.name, notes: $('reportNotes').value})});
  const data = await response.json();
  if (!response.ok) { $('reportResult').textContent = data.error || 'Report generation failed.'; return; }
  $('reportResult').innerHTML = `Report created: <a href="/api/loot/download/${encodeURIComponent(data.path)}?token=${encodeURIComponent(localStorage.cityToken)}">${escapeHtml(data.path)}</a>`;
  addRuntimeItem('artifact', data.path, data.path);
};

$('workflowStart').onclick = () => {
  if (!requireEngagement()) return;
  const payload = payloads.find(item => item.id === $('workflowSelect').value);
  if (!payload) return;
  renderWorkflow(payload);
  $('workflowDialog').showModal();
};
$('workflowCategory').onchange = renderWorkflowOptions;
$('workflowNext').onclick = () => {
  if (!workflowPayload) return;
  const payload = workflowPayload;
  $('workflowDialog').close();
  showPreflight(payload);
};

$('clear').onclick = () => { term.textContent = ''; line('» terminal cleared'); };
$('stopCommand').onclick = stopCurrent;
$('termSearch').oninput = applyTerminalSearch;
$('pauseTerm').onclick = () => {
  terminalPaused = !terminalPaused;
  $('pauseTerm').classList.toggle('active', terminalPaused);
  if (terminalPaused) { $('pauseTerm').textContent = 'RESUME'; return; }
  const queued = pausedOutput; pausedOutput = []; $('pauseTerm').textContent = 'PAUSE';
  queued.forEach(item => appendLine(item.text, item.cls, item.timestamp));
};
$('timestampTerm').onclick = () => {
  timestampsEnabled = !timestampsEnabled;
  $('timestampTerm').classList.toggle('active', timestampsEnabled);
  term.querySelectorAll('.term-line time').forEach(time => { time.hidden = !timestampsEnabled; });
};
$('copyTerm').onclick = async () => { await navigator.clipboard.writeText(term.innerText); $('copyTerm').textContent = 'COPIED'; setTimeout(() => { $('copyTerm').textContent = 'COPY'; }, 1200); };

$('command').onsubmit = event => {
  event.preventDefault();
  const command = $('cmd').value.trim();
  if (!command || !requireEngagement()) return;
  if (!$('unlock').checked) { line('! unlock and confirm authorization before using the command bar', 'line-warn'); return; }
  socket.emit('run_command', {command, target: engagement.scope, engagement: engagement.name, authorized: true, in_scope: true, unlocked: true});
  $('cmd').value = '';
  setRunning({payload_id: 'command', name: 'command', engagement: engagement.name, started_at: new Date().toISOString(), log: 'pending'});
  line(`# ${command}`, 'line-hot');
};
$('ackBtn').onclick = () => fetch('/api/acknowledge', {method: 'POST', headers: authHeaders()});

setInterval(() => {
  $('clock').textContent = new Date().toLocaleTimeString();
  const counter = document.querySelector('.run-clock');
  if (counter && runningState) {
    const elapsed = Math.max(0, Math.round((Date.now() - new Date(runningState.started_at).getTime()) / 1000));
    counter.textContent = `${elapsed}s`;
  }
}, 1000);

try { if (sessionStorage.engagement) engagement = JSON.parse(sessionStorage.engagement); } catch (error) { engagement = null; }
renderEngagement();
if (localStorage.cityToken) { $('token').value = localStorage.cityToken; setTimeout(login, 0); }
if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
