const $ = (selector) => document.querySelector(selector);
const titleInput = $('#reportTitle');
const textInput = $('#reportText');
const statusText = $('#syncText');
const statusLight = $('#syncLight');
const saveButton = $('#saveBtn');
const sharePanel = $('#sharePanel');
const shareUrl = $('#shareUrl');
const remoteNotice = $('#remoteNotice');
const savedLabel = $('#lastSaved');

let currentId = null;
let lastLoaded = null;
let busy = false;
let pendingRemote = false;
let toastTimeout;

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => el.classList.remove('show'), 2800);
}

function setStatus(message, kind = 'idle') {
  statusText.textContent = message;
  statusLight.classList.toggle('saved', kind === 'saved');
  statusLight.classList.toggle('error', kind === 'error');
}

function isDirty() {
  if (!lastLoaded) return !!(titleInput.value.trim() || textInput.value.trim());
  return titleInput.value !== lastLoaded.title || textInput.value !== lastLoaded.content;
}

function pasteUrl(id) {
  return window.location.origin + '/?paste=' + encodeURIComponent(id);
}

function updateEditor() {
  const text = textInput.value;
  const lines = text.length ? text.split('\n').length : 0;
  $('#editorMeta').textContent = lines.toLocaleString() + ' lines · ' + text.length.toLocaleString() + ' characters';
  if (!busy) {
    if (currentId) {
      setStatus(isDirty() ? 'Unsaved local changes' : 'Saved · checking for edits', isDirty() ? 'idle' : 'saved');
    } else {
      setStatus(text.length ? 'Draft ready to share' : 'Ready to create a report');
    }
  }
}

function setShareState() {
  sharePanel.hidden = !currentId;
  shareUrl.value = currentId ? pasteUrl(currentId) : '';
  saveButton.innerHTML = currentId ? 'Save changes <span aria-hidden="true">↗</span>' : 'Save &amp; create link <span aria-hidden="true">↗</span>';
  $('#openId').value = currentId || '';
}

function applyRemote(data) {
  currentId = data.id;
  titleInput.value = data.title;
  textInput.value = data.content;
  lastLoaded = { title: data.title, content: data.content, version: data.version };
  pendingRemote = false;
  remoteNotice.hidden = true;
  setShareState();
  updateEditor();
  setStatus('Live · version ' + data.version + ' synced', 'saved');
  savedLabel.textContent = 'SAVED ' + new Date(data.updatedAt).toLocaleString();
}

async function api(url, options) {
  const response = await fetch(url, { cache: 'no-store', ...options });
  let data;
  try { data = await response.json(); }
  catch (_) { throw new Error('The server did not return a valid response.'); }
  if (!response.ok) {
    const error = new Error(data.error || 'Request failed.');
    error.status = response.status;
    throw error;
  }
  return data;
}

async function openPaste(id, saveHistory = true) {
  if (!/^[a-zA-Z0-9_-]{24}$/.test(id)) {
    toast('Enter a valid report link or report ID.');
    return;
  }
  if (isDirty() && !confirm('Your current changes are not saved. Open another report anyway?')) return;
  busy = true;
  setStatus('Loading shared report…');
  try {
    const data = await api('/api/paste?id=' + encodeURIComponent(id));
    applyRemote(data);
    if (saveHistory) history.replaceState({}, '', '/?paste=' + encodeURIComponent(id) + '#workspace');
    toast('Shared report loaded. Editing is enabled.');
  } catch (err) {
    setStatus(err.message, 'error');
    toast(err.message);
  } finally {
    busy = false;
  }
}

function parseId(input) {
  const raw = input.trim();
  if (/^[a-zA-Z0-9_-]{24}$/.test(raw)) return raw;
  try {
    const url = new URL(raw, window.location.origin);
    return url.searchParams.get('paste') || '';
  } catch (_) {
    return '';
  }
}

async function savePaste() {
  if (busy) return;
  const content = textInput.value;
  if (content.length > 600000) {
    toast('Report too large. Maximum 600,000 characters.');
    return;
  }
  if (!content.trim()) {
    toast('Paste a report before saving.');
    textInput.focus();
    return;
  }
  if (pendingRemote) {
    toast('A teammate changed the report. Load their version first.');
    remoteNotice.hidden = false;
    return;
  }
  busy = true;
  saveButton.disabled = true;
  setStatus('Saving to shared storage…');
  const payload = { title: titleInput.value, content };
  try {
    const created = !currentId;
    const data = created
      ? await api('/api/paste', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      : await api('/api/paste', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...payload, id: currentId, version: lastLoaded.version }) });
    currentId = data.id;
    lastLoaded = { title: data.title, content: data.content, version: data.version };
    if (!titleInput.value.trim()) titleInput.value = data.title;
    setShareState();
    history.replaceState({}, '', '/?paste=' + encodeURIComponent(data.id) + '#workspace');
    savedLabel.textContent = 'SAVED ' + new Date(data.updatedAt).toLocaleString();
    setStatus('Saved · version ' + data.version, 'saved');
    toast(created ? 'Report created. Copy your share link below.' : 'Changes saved for everyone with the link.');
    if (created) sharePanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (err) {
    if (err.status === 409) {
      pendingRemote = true;
      remoteNotice.hidden = false;
    }
    setStatus(err.message, 'error');
    toast(err.message);
  } finally {
    busy = false;
    saveButton.disabled = false;
    updateEditor();
  }
}

async function poll() {
  if (!currentId || busy || document.visibilityState === 'hidden') return;
  try {
    const data = await api('/api/paste?id=' + encodeURIComponent(currentId));
    if (!lastLoaded || data.version <= lastLoaded.version) return;
    if (isDirty()) {
      pendingRemote = true;
      remoteNotice.hidden = false;
      setStatus('Newer shared version available', 'error');
    } else {
      applyRemote(data);
      toast('A teammate updated the report.');
    }
  } catch (_) {
    if (!isDirty()) setStatus('Connection interrupted · retrying', 'error');
  }
}

async function copy(value) {
  if (!value) return toast('Nothing to copy yet.');
  try { await navigator.clipboard.writeText(value); toast('Copied to clipboard.'); }
  catch (_) {
    const input = document.createElement('textarea');
    input.value = value;
    input.style.position = 'fixed';
    input.style.opacity = '0';
    document.body.appendChild(input);
    input.select();
    const ok = document.execCommand('copy');
    input.remove();
    toast(ok ? 'Copied to clipboard.' : 'Copy was blocked by your browser.');
  }
}

function newPaste() {
  if (isDirty() && !confirm('Discard your unsaved changes and start a new report?')) return;
  currentId = null;
  lastLoaded = null;
  pendingRemote = false;
  titleInput.value = '';
  textInput.value = '';
  $('#openId').value = '';
  sharePanel.hidden = true;
  remoteNotice.hidden = true;
  savedLabel.textContent = 'UNSAVED DRAFT';
  history.replaceState({}, '', '/#workspace');
  setShareState();
  updateEditor();
  textInput.focus();
}

function downloadText() {
  if (!textInput.value) return toast('No report text to download.');
  const text = textInput.value;
  const file = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const link = document.createElement('a');
  const safe = (titleInput.value.trim() || 'lead-report').replace(/[^a-zA-Z0-9_-]+/g, '-').slice(0, 65);
  link.download = safe + '.txt';
  link.href = URL.createObjectURL(file);
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

titleInput.addEventListener('input', updateEditor);
textInput.addEventListener('input', updateEditor);
textInput.addEventListener('keydown', (event) => {
  if (event.key === 'Tab') {
    event.preventDefault();
    const start = textInput.selectionStart;
    textInput.setRangeText('    ', start, textInput.selectionEnd, 'end');
    updateEditor();
  }
});
document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
    event.preventDefault();
    savePaste();
  }
});
$('#saveBtn').addEventListener('click', savePaste);
$('#openBtn').addEventListener('click', () => openPaste(parseId($('#openId').value)));
$('#openId').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') openPaste(parseId($('#openId').value));
});
$('#newBtn').addEventListener('click', newPaste);
$('#copyLinkBtn').addEventListener('click', () => copy(shareUrl.value));
$('#copyTextBtn').addEventListener('click', () => copy(textInput.value));
$('#downloadTextBtn').addEventListener('click', downloadText);
$('#reloadBtn').addEventListener('click', async () => {
  if (!confirm('Load your teammate\'s version? Your unsaved edits will be replaced.')) return;
  lastLoaded = null;
  await openPaste(currentId, false);
});
$('#importBtn').addEventListener('click', () => $('#importFile').click());
$('#importFile').addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  if (file.size > 1800000) return toast('Import must be smaller than 1.8 MB.');
  if (isDirty() && !confirm('Replace current unsaved text with the imported file?')) return;
  textInput.value = await file.text();
  if (!titleInput.value.trim()) titleInput.value = file.name.replace(/\.(txt|log|out|md)$/i, '');
  updateEditor();
  toast('Report imported. Save to share it.');
  event.target.value = '';
});
document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', () => copy(button.getAttribute('data-copy')));
});

const queryId = new URL(window.location.href).searchParams.get('paste');
if (queryId) {
  // A URL can be opened on any other device and fetches the latest saved version.
  openPaste(queryId, false);
  requestAnimationFrame(() => setTimeout(() => $('#workspace').scrollIntoView({ behavior: 'smooth', block: 'start' }), 130));
} else {
  setShareState();
  updateEditor();
}
setInterval(poll, 6000);
