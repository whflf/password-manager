/* ═══════════════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════════════ */
const state = {
    token:          null,
    masterPassword: null,
    email:          null,
    entries:        [],
    editingId:      null,
    generatedPw:    null,
    authMode:       'login',   // 'login' | 'register'
};

/* ═══════════════════════════════════════════════════════════════
   API
═══════════════════════════════════════════════════════════════ */
const API = '/api';

async function request(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (state.token)          headers['Authorization']    = `Bearer ${state.token}`;
    if (state.masterPassword) headers['X-Master-Password'] = state.masterPassword;

    const res = await fetch(API + path, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 204) return null;

    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
}

/* ═══════════════════════════════════════════════════════════════
   AUTH
═══════════════════════════════════════════════════════════════ */
function switchTab(mode) {
    state.authMode = mode;
    document.querySelectorAll('.tab').forEach((t, i) => {
        t.classList.toggle('active', (i === 0) === (mode === 'login'));
    });
    document.getElementById('auth-submit').textContent =
        mode === 'login' ? 'Sign in' : 'Create account';
    document.getElementById('auth-error').textContent = '';
}

async function submitAuth() {
    const email    = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    const errEl    = document.getElementById('auth-error');
    errEl.textContent = '';

    if (!email || !password) { errEl.textContent = 'Fill in all fields.'; return; }

    try {
        const endpoint = state.authMode === 'login' ? '/auth/login' : '/auth/register';
        const data = await request('POST', endpoint, { email, masterPassword: password });

        state.token          = data.token;
        state.masterPassword = password;
        state.email          = email;

        document.getElementById('nav-email').textContent = email;
        ['btn-gen','btn-add','btn-logout'].forEach(id =>
            document.getElementById(id).style.display = '');

        await loadEntries();
        showScreen('vault');
    } catch (e) {
        errEl.textContent = e.message;
    }
}

function logout() {
    Object.assign(state, { token: null, masterPassword: null, email: null, entries: [] });
    document.getElementById('nav-email').textContent = '';
    ['btn-gen','btn-add','btn-logout'].forEach(id =>
        document.getElementById(id).style.display = 'none');
    document.getElementById('auth-email').value    = '';
    document.getElementById('auth-password').value = '';
    document.getElementById('auth-error').textContent = '';
    showScreen('auth');
}

/* ═══════════════════════════════════════════════════════════════
   ENTRIES
═══════════════════════════════════════════════════════════════ */
async function loadEntries() {
    const data = await request('GET', '/vault');
    state.entries = data;
    renderEntries();
}

function renderEntries() {
    const q    = document.getElementById('search').value.toLowerCase();
    const grid = document.getElementById('entries-grid');
    const list = state.entries.filter(e =>
        e.site.toLowerCase().includes(q) || e.login.toLowerCase().includes(q)
    );

    if (!list.length) {
        grid.innerHTML = `
      <div class="empty">
        <div class="empty-icon">🔐</div>
        <strong>${q ? 'No results' : 'No passwords yet'}</strong>
        <p>${q ? 'Try a different search.' : 'Click "+ Add" to save your first password.'}</p>
      </div>`;
        return;
    }

    grid.innerHTML = list.map(e => {
        const masked = '•'.repeat(Math.min(e.password.length, 16));
        const badges = [
            e.pwned     ? `<span class="badge badge-danger">⚠ leaked</span>` : '',
            e.duplicate ? `<span class="badge badge-warn">⚠ reused</span>`  : '',
        ].join('');

        return `
    <div class="entry-card">
      <div>
        <div class="entry-site">${esc(e.site)}</div>
        <div class="entry-login">${esc(e.login)}</div>
      </div>
      <div class="entry-actions">
        <button class="btn-icon" title="Copy password" onclick="copyPw(${e.id})">⎘</button>
        <button class="btn-icon" title="Edit" onclick="openEditModal(${e.id})">✎</button>
        <button class="btn-icon btn-danger" title="Delete" onclick="deleteEntry(${e.id})">✕</button>
      </div>
      <div class="pw-row">
        <span class="pw-value" id="pw-${e.id}">${masked}</span>
        <button class="btn-icon btn-sm" onclick="togglePw(${e.id})">👁</button>
      </div>
      <div class="entry-badges">${badges}</div>
    </div>`;
    }).join('');
}

function togglePw(id) {
    const entry = state.entries.find(e => e.id === id);
    if (!entry) return;
    const pw = entry.password;
    const el = document.getElementById(`pw-${id}`);
    if (el.classList.contains('revealed')) {
        el.textContent = '•'.repeat(Math.min(pw.length, 16));
        el.classList.remove('revealed');
    } else {
        el.textContent = pw;
        el.classList.add('revealed');
    }
}

async function copyPw(id) {
    const entry = state.entries.find(e => e.id === id);
    if (!entry) return;
    await navigator.clipboard.writeText(entry.password);
    toast('Password copied');
}

/* ═══════════════════════════════════════════════════════════════
   ADD / EDIT MODAL
═══════════════════════════════════════════════════════════════ */
function openAddModal() {
    state.editingId = null;
    document.getElementById('modal-title').textContent   = 'New entry';
    document.getElementById('entry-site').value          = '';
    document.getElementById('entry-login').value         = '';
    document.getElementById('entry-password').value      = '';
    document.getElementById('entry-error').textContent   = '';
    document.getElementById('modal-entry').classList.add('open');
}

function openEditModal(id) {
    const e = state.entries.find(x => x.id === id);
    if (!e) return;
    state.editingId = id;
    document.getElementById('modal-title').textContent   = 'Edit entry';
    document.getElementById('entry-site').value          = e.site;
    document.getElementById('entry-login').value         = e.login;
    document.getElementById('entry-password').value      = e.password;
    document.getElementById('entry-error').textContent   = '';
    document.getElementById('modal-entry').classList.add('open');
}

function closeEntryModal() {
    document.getElementById('modal-entry').classList.remove('open');
}

async function saveEntry() {
    const site     = document.getElementById('entry-site').value.trim();
    const login    = document.getElementById('entry-login').value.trim();
    const password = document.getElementById('entry-password').value;
    const errEl    = document.getElementById('entry-error');
    errEl.textContent = '';

    if (!site || !login || !password) {
        errEl.textContent = 'All fields are required.';
        return;
    }

    try {
        if (state.editingId) {
            const updated = await request('PUT', `/vault/${state.editingId}`, { site, login, password });
            state.entries = state.entries.map(e => e.id === state.editingId ? updated : e);
            toast('Entry updated');
        } else {
            const created = await request('POST', '/vault', { site, login, password });
            state.entries.push(created);
            toast('Entry saved');
        }
        closeEntryModal();
        renderEntries();
    } catch (e) {
        errEl.textContent = e.message;
    }
}

async function deleteEntry(id) {
    if (!confirm('Delete this entry?')) return;
    await request('DELETE', `/vault/${id}`);
    state.entries = state.entries.filter(e => e.id !== id);
    renderEntries();
    toast('Entry deleted');
}

/* ═══════════════════════════════════════════════════════════════
   GENERATOR
═══════════════════════════════════════════════════════════════ */
function openGenerator() {
    generatePassword();
    document.getElementById('modal-gen').classList.add('open');
}

function closeGenerator() {
    document.getElementById('modal-gen').classList.remove('open');
}

function updateGenLen() {
    const v = document.getElementById('gen-length').value;
    document.getElementById('gen-len-val').textContent = v;
    generatePassword();
}

function generatePassword() {
    const len   = +document.getElementById('gen-length').value;
    const upper = document.getElementById('gen-upper').checked;
    const lower = document.getElementById('gen-lower').checked;
    const nums  = document.getElementById('gen-nums').checked;
    const syms  = document.getElementById('gen-syms').checked;

    let chars = '';
    if (upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (nums)  chars += '0123456789';
    if (syms)  chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!chars) { document.getElementById('gen-output').textContent = 'Select at least one option'; return; }

    const arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    const pw = Array.from(arr).map(n => chars[n % chars.length]).join('');

    state.generatedPw = pw;
    document.getElementById('gen-output').textContent = pw;
}

function copyGenerated() {
    if (!state.generatedPw) return;
    navigator.clipboard.writeText(state.generatedPw);
    toast('Password copied');
}

function fillFromGenerator() {
    if (!state.generatedPw) generatePassword();
    document.getElementById('entry-password').value = state.generatedPw;
    document.getElementById('entry-password').type  = 'text';
}

/* ═══════════════════════════════════════════════════════════════
   UTILS
═══════════════════════════════════════════════════════════════ */
function showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(`screen-${name}`).classList.add('active');
}

function esc(str) {
    return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

let toastTimer;
function toast(msg) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2200);
}

/* ── close modals on overlay click ── */
document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
        if (e.target === overlay) overlay.classList.remove('open');
    });
});

/* ── enter key in auth form ── */
document.getElementById('auth-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') submitAuth();
});
