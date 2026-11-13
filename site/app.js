'use strict';

const REPOSITORY = 'randharrison1-png/Cyber-Patriot-Round-2';
const ROOT = 'https://raw.githubusercontent.com/' + REPOSITORY + '/main/';
const WEB = 'https://github.com/' + REPOSITORY + '/blob/main/';
const MAX_CONTENT = 200000;
const STORAGE_KEY = 'leadhub.recent.v1';

const SCRIPTS = [
  { name: 'Leads.ps1', path: 'portal/scripts/Leads.ps1', kind: 'Lead finder', platform: 'Windows', category: 'lead-finder', summary: 'Find likely remaining scored checks on Windows 11 and Windows Server 2022. Start with report-only mode.', command: 'powershell -ExecutionPolicy Bypass -File .\\Leads.ps1 -ReportOnly' },
  { name: 'leads.sh', path: 'portal/scripts/leads.sh', kind: 'Lead finder', platform: 'Linux', category: 'lead-finder', summary: 'Review Debian 12 accounts, services, SSH, firewall, files, and other likely unscored checks.', command: 'sudo bash leads.sh --report-only' },
  { name: 'Harden-Win11.ps1', path: 'Harden-Win11.ps1', kind: 'Hardening', platform: 'Windows', category: 'hardening', summary: 'Windows 11 competition-image hardening script. Review the README and source before running.', command: '' },
  { name: 'Harden-Server2022.ps1', path: 'Harden-Server2022.ps1', kind: 'Hardening', platform: 'Windows', category: 'hardening', summary: 'Windows Server 2022 competition-image hardening script. Review the README and source before running.', command: '' },
  { name: 'harden-debian12.sh', path: 'harden-debian12.sh', kind: 'Hardening', platform: 'Linux', category: 'hardening', summary: 'Debian 12 competition-image hardening script. Review the README and source before running.', command: '' }
];
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const config = window.LEADHUB_CONFIG || {};
const configured = /^https:\/\/[a-z0-9.-]+\.supabase\.co\/?$/i.test(config.url || '') &&
  /^sb_publishable_|^eyJ/.test(config.publishableKey || '') &&
  typeof window.supabase?.createClient === 'function';
const db = configured ? window.supabase.createClient(config.url.replace(/\/$/, ''), config.publishableKey, {
  auth: { persistSession: false, autoRefreshToken: false }
}) : null;
let tab = 'library';
let filter = 'all';
let selectedScript = null;
let currentPaste = null;
let savedSnapshot = null;
let pendingRemote = false;
let saving = false;
let latestRemote = null;
let toastTimer;

function icon(name) {
  const i = document.createElement('i');
  i.setAttribute('data-lucide', name);
  i.setAttribute('aria-hidden', 'true');
  return i;
}
function icons() {
  if (window.lucide?.createIcons) window.lucide.createIcons();
}
function notify(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3800);
}
function setEditorStatus(msg) { $('#editor-state').textContent = msg; }
function rows() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch (_) { return []; }
}
function registerPaste(paste, source) {
  const entry = { slug: paste.slug, title: paste.title || 'Untitled report', updated_at: paste.updated_at || new Date().toISOString(), source };
  const list = rows().filter(x => x.slug !== entry.slug);
  list.unshift(entry);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list.slice(0, 60)));
  renderRecent();
}
function cleanTitle(text) { return (text || '').trim().slice(0, 100) || 'Untitled report'; }
function randomSlug() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function pasteLink(slug) { const url = new URL(window.location.href); url.search = '?paste=' + encodeURIComponent(slug); url.hash = ''; return url.toString(); }
function updateQuery(slug = '') {
  const url = new URL(location.href);
  if (slug) { url.searchParams.set('paste', slug); url.searchParams.delete('tab'); }
  else { url.searchParams.delete('paste'); url.searchParams.set('tab', tab); }
  history.replaceState({}, '', url.pathname + url.search);
}
function switchTab(which, keepQuery = false) {
  tab = which === 'pastes' ? 'pastes' : 'library';
  $$('.nav-button, .panel-tab').forEach(button => {
    const active = button.dataset.tab === tab;
    button.classList.toggle('active', active && button.classList.contains('nav-button'));
    button.classList.toggle('selected', active && button.classList.contains('panel-tab'));
    if (button.getAttribute('role') === 'tab') button.setAttribute('aria-selected', String(active));
    if (button.classList.contains('nav-button')) active ? button.setAttribute('aria-current', 'page') : button.removeAttribute('aria-current');
  });
  $('#library-panel').hidden = tab !== 'library';
  $('#pastes-panel').hidden = tab !== 'pastes';
  $('#crumb').textContent = tab === 'library' ? 'Library' : 'Pastes';
  if (!keepQuery) updateQuery(currentPaste && tab === 'pastes' && currentPaste.source === 'remote' ? currentPaste.slug : '');
  icons();
}
function createButton(text, iconName, action, style = 'secondary') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'button ' + style;
  button.append(icon(iconName), document.createTextNode(text));
  button.addEventListener('click', action);
  return button;
}
function renderScripts() {
  const q = $('#script-search').value.trim().toLowerCase();
  const matches = SCRIPTS.filter(s =>
    (filter === 'all' || filter === s.platform.toLowerCase() || filter === s.category) &&
    [s.name, s.summary, s.platform, s.kind].some(t => t.toLowerCase().includes(q))
  );
  $('#script-count').textContent = matches.length + ' of ' + SCRIPTS.length + ' scripts';
  const list = $('#script-list'); list.replaceChildren();
  $('#scripts-empty').hidden = matches.length > 0;
  for (const s of matches) {
    const card = document.createElement('article');
    card.className = 'script-card';
    const top = document.createElement('div');
    top.className = 'script-card-top';
    const badge = document.createElement('div'); badge.className = 'script-icon'; badge.append(icon(s.platform === 'Windows' ? 'monitor' : 'terminal'));
    const kind = document.createElement('span'); kind.className = 'script-kind'; kind.textContent = s.platform + ' · ' + s.kind;
    top.append(badge, kind);
    const h = document.createElement('h2'); h.textContent = s.name;
    const description = document.createElement('p'); description.textContent = s.summary;
    const foot = document.createElement('div'); foot.className = 'card-foot';
    foot.append(createButton('View code', 'code-2', () => openSource(s)), createButton('Download', 'download', () => downloadScript(s), 'primary'));
    card.append(top, h, description, foot);
    list.append(card);
  }
  icons();
}

async function downloadScript(s) {
  const url = ROOT + s.path;
  try {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error('GitHub returned ' + response.status);
    const content = await response.blob();
    const objectURL = URL.createObjectURL(content);
    const link = document.createElement('a');
    link.href = objectURL; link.download = s.name; document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(objectURL), 2000);
    notify(s.name + ' downloaded');
  } catch (_) {
    window.open(url, '_blank', 'noopener,noreferrer');
    notify('Opened source file. Use Save As to download.');
  }
}
async function openSource(s) {
  selectedScript = s;
  $('#source-title').textContent = s.name;
  $('#source-subtitle').textContent = s.platform + ' · ' + s.kind;
  $('#source-content').textContent = 'Loading original source from GitHub…';
  $('#source-github').href = WEB + s.path;
  $('#source-dialog').showModal();
  try {
    const response = await fetch(ROOT + s.path);
    if (!response.ok) throw new Error('HTTP ' + response.status);
    $('#source-content').textContent = await response.text();
  } catch (e) {
    $('#source-content').textContent = 'Could not load source: ' + e.message + '. Use Open on GitHub to inspect it directly.';
  }
}
function renderRecent() {
  const list = $('#recent-list'); list.replaceChildren();
  const q = $('#paste-search').value.toLowerCase().trim();
  const results = rows().filter(p => (p.title + ' ' + p.slug).toLowerCase().includes(q));
  $('#recent-count').textContent = String(results.length);
  if (!results.length) {
    const el = document.createElement('div'); el.className = 'recent-empty';
    el.textContent = q ? 'No saved reports match your search.' : 'No reports opened on this device yet. Create one, or open a shared link.';
    list.append(el); return;
  }
  results.forEach(entry => {
    const button = document.createElement('button'); button.type = 'button';
    button.className = 'recent-row';
    if (currentPaste?.slug === entry.slug) button.classList.add('active');
    const name = document.createElement('strong'); name.textContent = entry.title;
    const sub = document.createElement('small');
    sub.textContent = (entry.source === 'local' ? 'Local draft · ' : 'Shared report · ') + new Date(entry.updated_at).toLocaleString();
    button.append(name, sub);
    button.addEventListener('click', () => openPaste(entry.slug));
    list.append(button);
  });
}
function isDirty() {
  if (!savedSnapshot) return Boolean($('#paste-title').value.trim() || $('#paste-body').value.trim());
  return $('#paste-title').value !== savedSnapshot.title || $('#paste-body').value !== savedSnapshot.content;
}
function refreshEditor() {
  const count = $('#paste-body').value.length;
  $('#char-count').textContent = count.toLocaleString() + ' characters' + (count > MAX_CONTENT ? ' · TOO LONG' : '');
  if (!saving && !pendingRemote) {
    setEditorStatus(isDirty() ? 'Unsaved changes' : currentPaste ? 'Saved · version ' + (currentPaste.revision || 1) : 'New draft');
  }
}
function updateShare() {
  const remote = currentPaste && currentPaste.source === 'remote';
  $('#share-panel').hidden = !remote;
  if (remote) $('#share-url').value = pasteLink(currentPaste.slug);
  $('#save-label').textContent = configured ? remote ? 'Save changes' : 'Save and share' : 'Save local draft';
}
function applyPaste(paste, source) {
  currentPaste = { ...paste, source };
  savedSnapshot = { title: paste.title, content: paste.content };
  $('#paste-title').value = paste.title;
  $('#paste-body').value = paste.content;
  pendingRemote = false; latestRemote = null;
  $('#remote-warning').hidden = true;
  updateShare(); refreshEditor();
  setEditorStatus(source === 'local' ? 'Saved on this device' : 'Shared · version ' + paste.revision);
  registerPaste(paste, source);
  updateQuery(source === 'remote' ? paste.slug : '');
}
function newPaste() {
  if (isDirty() && !confirm('Discard your unsaved changes?')) return;
  currentPaste = null; savedSnapshot = null; pendingRemote = false; latestRemote = null;
  $('#paste-title').value = ''; $('#paste-body').value = ''; $('#remote-warning').hidden = true;
  updateShare(); refreshEditor(); renderRecent(); updateQuery(); $('#paste-title').focus();
}
function parseId(raw) {
  let value = String(raw || '').trim();
  try {
    const url = new URL(value);
    value = url.searchParams.get('paste') || '';
  } catch (_) { /* entered an id */ }
  return /^(?:local-)?[0-9a-f]{36}$/i.test(value) ? value : '';
}
async function openPaste(raw, force = false) {
  const slug = parseId(raw);
  if (!slug) return notify('Enter a valid report ID or paste link.');
  if (!force && isDirty() && !confirm('Discard unsaved edits and open this report?')) return;
  setEditorStatus('Loading report…');
  try {
    if (slug.startsWith('local-')) {
      const data = localStorage.getItem('leadhub.draft.' + slug);
      if (!data) throw new Error('Local draft not found on this device.');
      applyPaste(JSON.parse(data), 'local');
    } else {
      if (!db) throw new Error('Supabase is not connected. Shared links cannot open yet.');
      const { data, error } = await db.rpc('get_paste', { p_slug: slug });
      if (error) throw error;
      if (!data?.length) throw new Error('This shared report was not found.');
      applyPaste(data[0], 'remote');
    }
    switchTab('pastes', true);
    notify('Report loaded');
  } catch (e) { setEditorStatus('Load failed'); notify(e.message || 'Unable to load report'); }
}

async function savePaste() {
  if (saving) return;
  const title = cleanTitle($('#paste-title').value);
  const content = $('#paste-body').value;
  if (!content.trim()) return notify('Add some report text before saving.');
  if (content.length > MAX_CONTENT) return notify('Report must be 200,000 characters or fewer.');
  if (pendingRemote) return notify('A newer revision exists. Load it before saving.');
  saving = true;
  $('#save-paste').disabled = true;
  setEditorStatus('Saving…');
  try {
    if (!db) {
      const slug = currentPaste?.source === 'local' ? currentPaste.slug : 'local-' + randomSlug();
      const paste = { slug, title, content, revision: (currentPaste?.revision || 0) + 1, updated_at: new Date().toISOString() };
      localStorage.setItem('leadhub.draft.' + slug, JSON.stringify(paste));
      applyPaste(paste, 'local');
      notify('Saved on this device only. Connect Supabase to share it.');
    } else {
      const args = currentPaste?.source === 'remote'
        ? { p_slug: currentPaste.slug, p_expected_revision: currentPaste.revision, p_title: title, p_content: content }
        : { p_slug: randomSlug(), p_title: title, p_content: content };
      const action = currentPaste?.source === 'remote' ? 'update_paste' : 'create_paste';
      const { data, error } = await db.rpc(action, args);
      if (error) throw error;
      if (!data?.length) {
        pendingRemote = true; $('#remote-warning').hidden = false;
        throw new Error('Someone else saved an update. Load the latest version first.');
      }
      applyPaste(data[0], 'remote');
      notify('Report saved. Copy your link to share it.');
    }
  } catch (e) {
    setEditorStatus('Save failed');
    notify(e.message || 'Unable to save');
  } finally {
    saving = false; $('#save-paste').disabled = false;
  }
}
async function checkRemote() {
  if (!db || saving || !currentPaste || currentPaste.source !== 'remote' || document.visibilityState === 'hidden') return;
  try {
    const { data, error } = await db.rpc('get_paste', { p_slug: currentPaste.slug });
    if (error || !data?.length) return;
    const incoming = data[0];
    if (incoming.revision <= currentPaste.revision) return;
    if (isDirty()) {
      latestRemote = incoming; pendingRemote = true; $('#remote-warning').hidden = false;
      setEditorStatus('New revision available');
    } else {
      applyPaste(incoming, 'remote'); notify('Report updated by another editor.');
    }
  } catch (_) { /* recover on next poll */ }
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); notify('Copied to clipboard'); }
  catch (_) {
    const el = document.createElement('textarea');
    el.value = text; el.style.position = 'fixed'; el.style.opacity = '0';
    document.body.append(el); el.select();
    const ok = document.execCommand('copy');
    el.remove(); notify(ok ? 'Copied to clipboard' : 'Clipboard unavailable');
  }
}
function exportPaste() {
  const text = $('#paste-body').value;
  if (!text.trim()) return notify('No report text to export');
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = href;
  a.download = cleanTitle($('#paste-title').value).replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 75) + '.txt';
  a.click(); setTimeout(() => URL.revokeObjectURL(href), 2000);
}

$$('[data-tab]').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
$$('[data-filter]').forEach(b => b.addEventListener('click', () => {
  filter = b.dataset.filter;
  $$('.filter-button').forEach(x => x.classList.toggle('chosen', x === b));
  renderScripts();
}));
$('#script-search').addEventListener('input', renderScripts);
$('#paste-search').addEventListener('input', renderRecent);
$('#close-source').addEventListener('click', () => $('#source-dialog').close());
$('#download-source').addEventListener('click', () => { if (selectedScript) downloadScript(selectedScript); });
$('#new-paste').addEventListener('click', newPaste);
$('#open-paste').addEventListener('click', () => openPaste($('#open-id').value));
$('#open-id').addEventListener('keydown', e => { if (e.key === 'Enter') openPaste($('#open-id').value); });
$('#paste-title').addEventListener('input', refreshEditor);
$('#paste-body').addEventListener('input', refreshEditor);
$('#save-paste').addEventListener('click', savePaste);
$('#copy-link').addEventListener('click', () => copyText($('#share-url').value));
$('#export-paste').addEventListener('click', exportPaste);
$('#import-paste').addEventListener('click', () => $('#file-import').click());
$('#file-import').addEventListener('change', async e => {
  const f = e.target.files?.[0]; if (!f) return;
  if (f.size > MAX_CONTENT) { notify('File too large to import'); e.target.value = ''; return; }
  if (isDirty() && !confirm('Replace unsaved content with the imported file?')) { e.target.value = ''; return; }
  $('#paste-body').value = await f.text();
  if (!$('#paste-title').value.trim()) $('#paste-title').value = f.name;
  refreshEditor(); e.target.value = ''; notify('File imported; save to keep your changes');
});
$('#load-remote').addEventListener('click', () => {
  if (!currentPaste?.slug || !confirm('Replace local edits with the newest shared revision?')) return;
  if (latestRemote) applyPaste(latestRemote, 'remote'); else openPaste(currentPaste.slug, true);
});
document.addEventListener('keydown', e => {
  if (e.key === '/' && tab === 'library' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
    e.preventDefault(); $('#script-search').focus();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
    e.preventDefault(); if (tab === 'pastes') savePaste();
  }
});
window.addEventListener('popstate', () => {
  const params = new URL(location.href).searchParams;
  if (params.has('paste')) openPaste(params.get('paste'), true);
  else switchTab(params.get('tab'), true);
});

$('#connection-label').textContent = db ? 'Shared report storage connected' : 'Local drafts only · Supabase not connected';
$('#storage-banner').hidden = Boolean(db);
renderScripts(); renderRecent(); refreshEditor(); updateShare(); icons();
const url = new URL(location.href);
if (url.searchParams.get('paste')) {
  switchTab('pastes', true);
  openPaste(url.searchParams.get('paste'), true);
} else switchTab(url.searchParams.get('tab'), true);
setInterval(checkRemote, 8000);
