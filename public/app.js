// Lineage Scan: browser app. Talks to Octopai through the local proxy (/octopai/*), keeps a per-tenant cache
// through /cache/<tenant> and streams lineage downloads to /export/<tenant>/<run>. The token lives in memory only.
const $ = (s) => document.querySelector(s)
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

const DEPTH = 12              // lineage hops to traverse
const LINEAGE_LIMIT = 5000    // starting max nodes per lineage graph
const LINEAGE_MAX_LIMIT = 200000
const CONCURRENCY = 6         // parallel lineage requests (browsers allow about 6 connections to the local server)
const PAGE_WORKERS = 3        // parallel asset pages per asset type
const PAGE = 10000            // asset page size (API max)
const MAX_PAGES = 500         // safety cap on asset pages
const ORPHAN_CAP = 50000     // most orphans kept in memory per asset type
const FIND_CAP = 5000        // most broken-lineage findings kept per kind
const EVENT_PAGE = 500
const REQ_TIMEOUT_MS = 3 * 60 * 1000   // a request Octopai has not answered within this is cancelled and retried
const MAX_EVENT_PAGES = 400
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000
// At login, assets and user events are read from the files saved in data/ when they are younger than this.
// Older than this (or missing) and they are reloaded from Octopai. Reload assets and events always reloads.
// Set to Infinity to never reload automatically, or 0 to always reload at login.
const SAVED_MAX_AGE_HOURS = 24 * 10   // 10 days
const TYPE_NAME = { 1: 'cross-system', 2: 'column-level' }
const DIR_NAME = { 1: 'upstream', 2: 'downstream' }
const PRESETS = ['email', 'ssn', 'phone', 'customer_id', 'address', 'birth', 'salary', 'account']
const MODES = {
  source: { direction: 1, label: 'Source columns', help: 'Traces where the matched columns get their data from (data provenance, audit).' },
  consumer: { direction: 2, label: 'Consumer columns', help: 'Shows everything downstream that uses the matched columns (exposure, compliance/PII).' },
}

const state = {
  tenant: '', token: '', exp: 0, user: '', username: '', run: null, cache: { lineage: {} }, cacheDirty: false,
  assets: { 1: null, 2: null }, events: null, loadAbort: null, loadStartedAt: 0, loadFinishedAt: 0, loading: false,
  dl: null, showAllConns: false, reauth: null, findings: null,
}

// ---------- helpers ----------
const sleep = (ms, signal) => new Promise((res, rej) => {
  const t = setTimeout(res, ms)
  signal?.addEventListener('abort', () => { clearTimeout(t); rej(new DOMException('Aborted', 'AbortError')) }, { once: true })
})
// Field names differ in casing between tenants and endpoints (the API has odd ones like objecT_NAME_FULL).
const norm = (k) => String(k).toLowerCase().replace(/_/g, '')
function pick(o, ...names) {
  const map = new Map(Object.keys(o || {}).map((k) => [norm(k), o[k]]))
  for (const n of names) { const v = map.get(norm(n)); if (v !== undefined && v !== null && v !== '') return v }
  return ''
}
function normalizeAsset(a) {
  return {
    key: pick(a, '_key', 'objectGUID'),
    column: String(pick(a, 'assetName', 'columnName', 'objectName')),
    table: String(pick(a, 'tableName')),
    schema: String(pick(a, 'schemaName')),
    db: String(pick(a, 'databaseName')),
    connection: String(pick(a, 'connLogicName', 'connName', 'connectionName', 'connectionId')),
    tool: String(pick(a, 'toolName')),
    objectType: String(pick(a, 'objectType')),
    toolType: String(pick(a, 'toolType')),
    container: String(pick(a, 'containerObjectType')),
  }
}
const numOrNull = (v) => (v === '' || v == null || !Number.isFinite(Number(v)) ? null : Number(v))
const colPath = (c) => c.label || [c.db, c.schema, c.table, c.column].filter(Boolean).join('.')
const fmtDur = (s) => s < 90 ? `${Math.round(s)}s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`

// ---------- API ----------
async function api(path, { method = 'POST', body, signal } = {}) {
  const isLogin = path.includes('/UserAccount/Login')
  let why = ''
  for (let attempt = 1; attempt <= 5; attempt++) {
    const used = state.token
    const headers = { 'Content-Type': 'application/json', 'X-Octopai-Host': `${state.tenant}.octopai.com` }
    if (used && !isLogin) headers.Authorization = `Bearer ${used}`
    let res
    // Each try gets its own time limit, so one request that Octopai never answers cannot stall a load forever.
    const sig = signal ? AbortSignal.any([signal, AbortSignal.timeout(REQ_TIMEOUT_MS)]) : AbortSignal.timeout(REQ_TIMEOUT_MS)
    try {
      res = await fetch(`/octopai${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: sig })
    } catch (e) {
      if (signal?.aborted) throw e
      why = e.name === 'TimeoutError' ? `Octopai did not answer within ${REQ_TIMEOUT_MS / 60000} minutes` : 'Could not reach the local server or the Octopai site.'
      await sleep(1000 * 2 ** (attempt - 1), signal); continue
    }
    if (res.status === 401 && !isLogin) {
      // Token expired. If someone already refreshed it, just retry; otherwise ask for the password and carry on.
      if (state.token === used) await ensureAuth()
      attempt--; continue
    }
    if ([429, 500, 502, 503, 504].includes(res.status)) { why = `HTTP ${res.status}`; await sleep(1000 * 2 ** (attempt - 1), signal); continue }
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      if (isLogin && res.status === 401) {
        let detail = ''; try { detail = JSON.parse(txt).error || '' } catch { /* not JSON */ }
        throw new Error(`${state.tenant}.octopai.com rejected this username or password${detail ? ` (${detail})` : ''}. Check that the account exists on this site, the password is right, and the account is not SSO-only or locked.`)
      }
      throw new Error(`HTTP ${res.status} ${txt.slice(0, 200)}`)
    }
    if (res.status === 204) return {}
    try { return await res.json() } catch (e) {
      if (signal?.aborted) throw e
      why = e.name === 'TimeoutError' ? `Octopai did not finish sending within ${REQ_TIMEOUT_MS / 60000} minutes` : 'Octopai sent an incomplete answer'
      await sleep(1000 * 2 ** (attempt - 1), signal); continue
    }
  }
  throw new Error(`Gave up after 5 tries (${why}).`)
}

function jwtExp(token) {
  try { return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).exp * 1000 || 0 } catch { return 0 }
}
async function doLogin(username, password) {
  const r = await api('/api/UserAccount/Login', { body: { Username: username, Password: password } })
  if (r.error || !r.accessToken) throw new Error(r.error || 'Login failed.')
  state.token = r.accessToken
  state.exp = jwtExp(r.accessToken) || Date.now() + 55 * 60 * 1000
  state.user = r.displayName || r.userName || username
  state.username = username
  tick()
  return r
}

// ---------- Login / session / re-auth ----------
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault()
  const tenant = $('#tenant').value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.octopai\.com.*$/, '')
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(tenant)) { $('#loginError').textContent = 'Enter just the site name, like "demo" or "demo.eu".'; return }
  state.tenant = tenant; state.token = ''
  $('#loginBtn').disabled = true; $('#loginError').textContent = ''
  try {
    await doLogin($('#username').value.trim(), $('#password').value)
    $('#password').value = ''
    await enterApp()
  } catch (err) {
    $('#loginError').textContent = err.message
  } finally { $('#loginBtn').disabled = false }
})

function ensureAuth() {
  if (state.reauth) return state.reauth.promise
  const r = state.reauth = {}
  r.promise = new Promise((resolve, reject) => { r.resolve = resolve; r.reject = reject })
  $('#reauthUser').value = state.username; $('#reauthError').textContent = ''
  $('#reauth').hidden = false; $('#reauthPass').focus()
  return r.promise
}
$('#reauthForm').addEventListener('submit', async (e) => {
  e.preventDefault()
  try {
    await doLogin(state.username, $('#reauthPass').value)
    $('#reauthPass').value = ''; $('#reauth').hidden = true
    const r = state.reauth; state.reauth = null; r?.resolve()
  } catch (err) { $('#reauthError').textContent = err.message }
})
$('#reauthCancel').addEventListener('click', () => disconnect())

async function enterApp() {
  $('#loginCard').hidden = true; $('#appView').hidden = false
  $('#tenantName').textContent = `${state.tenant}.octopai.com`
  $('#userName').textContent = state.user
  document.title = `Lineage Scan · ${state.tenant}`
  state.showAllConns = false; state.dl = null; state.local = null; state.srcTouched = false
  srcFilter.off = loadFilter(); coverage.data = {}; fvMemo.clear(); itemsMemo.clear(); healthMemo.clear(); xMemo.clear(); statsMemo.clear(); xUi.imp = null; xUi.q = ''; $('#xSearch').value = ''; buildSources()
  $('#dlCard').hidden = true; $('#lineagePrompt').hidden = true; $('#dlReopen').hidden = true
  await loadCache()
  { let t = 'overview'; try { t = localStorage.getItem('lineage-tab') || t } catch { /* none */ } setTab(document.querySelector(`.tab[data-tab=${t}]`) ? t : 'overview') }
  tick()
  renderOverview(); renderEvents()
  refreshLocalStatus()
  startLoad()   // assets and user events load first; then the page asks about lineage
}

function disconnect() {
  state.run?.abort.abort(); state.loadAbort?.abort(); state.dl?.abort.abort()
  if (state.reauth) { state.reauth.reject(Object.assign(new Error('Disconnected.'), { auth: true })); state.reauth = null }
  state.token = ''; state.run = null; state.assets = { 1: null, 2: null }; state.events = null; state.dl = null; state.loading = false; state.findings = null
  $('#reauth').hidden = true; $('#statusBar').hidden = true
  $('#appView').hidden = true; $('#loginCard').hidden = false; $('#results').hidden = true
  document.title = 'Lineage Scan'
}
$('#logout').addEventListener('click', disconnect)
window.addEventListener('beforeunload', (e) => { if (state.dl?.status === 'running' || state.saving) { e.preventDefault(); e.returnValue = '' } })

function tick() {
  if (!state.token) return
  const left = state.exp - Date.now()
  const el = $('#timer')
  if (left <= 0) { el.textContent = 'Token expired'; el.className = 'timer bad' }
  else {
    const m = Math.floor(left / 60000)
    el.textContent = `Token expires in ${m}m`
    el.className = 'timer' + (m < 5 ? ' bad' : m < 15 ? ' warn' : '')
  }
}
setInterval(tick, 15000)

// ---------- Cache (per tenant, on disk via the local server) ----------
async function loadCache() {
  state.cache = { lineage: {} }
  try {
    const r = await fetch(`/cache/${state.tenant}`)
    if (r.ok) { state.cache = await r.json(); state.cache.lineage ||= {} }
  } catch { /* no cache is fine */ }
  updateCacheNote()
}
function updateCacheNote() {
  const n = Object.keys(state.cache.lineage || {}).length
  $('#cacheNote').textContent = n ? `Cache: ${n.toLocaleString()} columns of lineage saved for this site (last saved ${new Date(state.cache.savedAt).toLocaleString()}).` : 'No cached lineage for this site yet. The first scan will be slower.'
}
async function saveCache() {
  if (!state.cacheDirty) return
  state.cache.savedAt = Date.now(); state.cache.tenant = state.tenant; state.cacheDirty = false
  try { await fetch(`/cache/${state.tenant}`, { method: 'PUT', body: JSON.stringify(state.cache) }) } catch { /* ignore */ }
}

// ---------- Paging ----------
// Limit + Offset is the supported paging (Cloudera engineering confirmed the documented hasMore/cursorId scroll does
// not work), so pages are independent and can be requested several at a time. Repeated rows are dropped by _key,
// and a page that is short or adds nothing new ends the scan.
async function pageAssets(baseBody, signal, onItems, workers = PAGE_WORKERS) {
  const seen = new Set()
  let nextPage = 0, stop = false, pages = 0, hitCap = false
  const worker = async () => {
    while (!stop) {
      if (nextPage >= MAX_PAGES) { hitCap = true; stop = true; return }
      const offset = nextPage++ * PAGE
      const resp = await api('/api/v2.0/assets/query', { signal, body: { ...baseBody, limit: PAGE, offset } })
      const items = resp.items || []
      state.lastProgress = Date.now()
      const fresh = items.filter((x) => { const k = x && x._key; if (k == null) return !!x; if (seen.has(k)) return false; seen.add(k); return true })
      pages++
      if (fresh.length) onItems(fresh, seen.size)
      if (items.length < PAGE || fresh.length === 0) stop = true
    }
  }
  await Promise.all(Array.from({ length: workers }, worker))
  return { count: seen.size, pages, hitCap }
}
async function findColumns(names, signal, onPage) {
  const out = []
  await pageAssets({ AssetNames: names, assetType: 2 }, signal, (items, n) => { out.push(...items); onPage?.(n) }, 2)
  return out
}

// ---------- Stage 1 and 2: assets and user events ----------
const newAssets = (t) => ({ t, running: true, total: 0, tools: new Set(), dbs: new Set(), schemas: new Set(), conns: new Map(), combos: new Map(), items: [], linkCounted: 0, orphanTotal: 0, orphans: [], orphanCombos: new Map(), sources: 0, endpoints: 0, flagged: 0, flaggedList: [], done: false, hitCap: false, error: '' })
const newEvents = () => ({ running: true, rows: [], skipped: '', error: '', done: false, hitCap: false })

async function startLoad({ force = false } = {}) {
  if (!state.token || state.loading) return
  state.loading = true
  state.loadAbort?.abort()
  const ac = state.loadAbort = new AbortController()
  state.loadStartedAt = Date.now(); state.loadFinishedAt = 0; state.lastProgress = Date.now(); state.saveNote = ''
  state.assets = { 1: newAssets(1), 2: newAssets(2) }; state.events = newEvents(); state.fromSaved = 0
  $('#catalogBtn').disabled = true; $('#catalogBtn').textContent = 'Loading…'
  $('#lineagePrompt').hidden = true; $('#dlReopen').hidden = true
  renderOverview(); renderEvents()
  const timer = setInterval(() => {
    renderOverview()
    if (state.tab === 'explorer' && !state.assets[selType()]?.done) renderExplorer()
    if (state.tab === 'health' && !state.assets[selType()]?.done) renderHealth()
  }, 1000)
  // Each asset type comes from its saved file when that is fresh enough, otherwise from Octopai.
  const useSaved = { 1: false, 2: false }
  let savedEvents = false
  try {
    if (!force) {
      for (const t of [1, 2]) {
        useSaved[t] = !!(await readSaved(t, ac.signal, SAVED_MAX_AGE_HOURS * 3600 * 1000))
        if (!useSaved[t]) state.assets[t] = newAssets(t)
      }
      savedEvents = await loadSavedEvents(ac.signal)
    }
    await Promise.all([
      useSaved[1] ? null : loadAssets(1, ac.signal), useSaved[2] ? null : loadAssets(2, ac.signal),
      savedEvents ? null : loadEvents(ac.signal),
    ])
    // A live load that failed falls back to the saved copy, however old, so the page is never left empty.
    for (const t of [1, 2]) {
      const a = state.assets[t]
      if (a.done || !a.error) continue
      let fb = null
      try { fb = await readSaved(t, ac.signal) } catch { fb = null }
      if (fb) fb.fallback = a.error
      else state.assets[t] = a
    }
  } catch (err) { if (err.name !== 'AbortError') throw err } finally { clearInterval(timer) }
  if (ac.signal.aborted) { state.loading = false; return }
  const usedSaved = [1, 2].filter((t) => state.assets[t].savedAt)
  state.fromSaved = usedSaved.length ? Math.min(...usedSaved.map((t) => state.assets[t].savedAt)) : 0
  const liveTypes = [1, 2].filter((t) => !state.assets[t].savedAt && state.assets[t].done)
  if (!savedEvents && state.events.done) fetch(`/events/${state.tenant}`, { method: 'PUT', body: JSON.stringify({ savedAt: Date.now(), rows: state.events.rows }) }).catch(() => {})
  state.loadFinishedAt = Date.now(); state.loading = false
  const types = {}
  for (const t of liveTypes) { const a = state.assets[t]; types[t] = { total: a.total, tools: a.tools.size, dbs: a.dbs.size, schemas: a.schemas.size, conns: [...a.conns.values()], combos: [...a.combos.values()], orph: orphSummary(a) } }
  if (liveTypes.length) {
    const old = state.cache.catalog
    const prev = old?.types ? { savedAt: old.savedAt, totals: { 1: old.types[1]?.total, 2: old.types[2]?.total } } : old?.prev
    state.cache.catalog = { savedAt: Date.now(), prev, types: { ...(state.cache.catalog?.types || {}), ...types }, events: state.events.done ? { total: state.events.rows.length } : state.cache.catalog?.events }
    state.cacheDirty = true; saveCache()
    saveAssetsLocal(liveTypes)
  }
  $('#catalogBtn').disabled = false; $('#catalogBtn').textContent = 'Reload assets and events'
  fvMemo.clear(); itemsMemo.clear(); healthMemo.clear(); xMemo.clear(); statsMemo.clear(); coverage.data = {}
  buildSources(); renderOverview(); renderEvents(); if (state.tab === 'health') renderHealth(); if (state.tab === 'explorer') renderExplorer()
  showPrompt()
}
$('#catalogBtn').addEventListener('click', () => startLoad({ force: true }))

// Adds one asset to the running totals. Used both for assets from Octopai and for assets read back from data/.
function ingest(a, item) {
  a.total++
  if (item.tool) a.tools.add(item.tool)
  if (item.d) a.dbs.add(item.d)
  if (item.d || item.s) a.schemas.add(`${item.d}.${item.s}`)
  const c = a.conns.get(item.c) || { name: item.c, tool: item.tool, tt: item.tt, count: 0 }
  c.count++; a.conns.set(item.c, c)
  const ck = [item.tool, item.tt, item.ot, item.ct].join('\u0001')
  const cb = a.combos.get(ck) || { tool: item.tool, toolType: item.tt, objectType: item.ot, container: item.ct, count: 0 }
  cb.count++; a.combos.set(ck, cb)
  if (item.k) a.items.push(item)
  if (item.ins != null && item.outs != null) {
    a.linkCounted++
    if (item.ins === 0 && item.outs === 0) {
      a.orphanTotal++; if (a.orphans.length < ORPHAN_CAP) a.orphans.push(item)
      const oc = a.orphanCombos.get(ck) || { tool: item.tool, toolType: item.tt, objectType: item.ot, container: item.ct, count: 0 }
      oc.count++; a.orphanCombos.set(ck, oc)
    } else if (item.ins === 0) a.sources++
    else if (item.outs === 0) a.endpoints++
  }
  if (item.fo) { a.flagged++; if (a.flaggedList.length < ORPHAN_CAP) a.flaggedList.push(item) }
}

// Saved asset lists in data/ (see server.js for the format). The file is read as a stream and parsed in batches, so
// lists with millions of assets never have to fit in one string. Returns null (and leaves nothing half-loaded) when
// there is no saved list, it is older than maxAgeMs, or it was written by a version without the schema fields.
function savedRowToItem(row, dict) {
  if (!Array.isArray(row)) return row
  const [k, n, c, tool, tt, ot, ct, d, sc, tb, ins, outs, fo] = row
  const D = (i) => dict[i] ?? ''
  const item = { k, n, c: D(c), tool: D(tool), tt: D(tt), ot: D(ot), ct: D(ct), d: D(d), s: D(sc), tb: D(tb), ins, outs }
  item.l = [item.d, item.s, item.tb, n].filter(Boolean).join('.') || String(k)
  if (fo) item.fo = true
  return item
}
async function readSaved(t, signal, maxAgeMs = Infinity) {
  const r = await fetch(`/assets/${state.tenant}/${t}`, { signal })
  if (!r.ok || !r.body) return null
  const reader = r.body.pipeThrough(new TextDecoderStream()).getReader()
  let buf = '', meta = null, dict = null, a = null
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (value) buf += value
      const cut = done ? buf.length : buf.lastIndexOf('\n')
      if (cut < 0) continue
      const lines = buf.slice(0, cut).split('\n'); buf = buf.slice(cut + 1)
      const rows = []
      for (const L of lines) {
        if (!L) continue
        if (!meta) {
          meta = JSON.parse(L).meta
          if (!meta?.savedAt || !(meta.v >= 2) || Date.now() - meta.savedAt > maxAgeMs) { reader.cancel().catch(() => {}); return null }
          a = state.assets[t] = newAssets(t); a.reading = true
          continue
        }
        if (meta.v >= 3 && !dict) { dict = JSON.parse(L).dict || []; continue }
        rows.push(L)
      }
      if (rows.length) for (const row of JSON.parse(`[${rows.join(',')}]`)) ingest(a, savedRowToItem(row, dict))
      if (done) break
    }
  } catch (err) {
    reader.cancel().catch(() => {})
    if (a) state.assets[t] = newAssets(t)
    if (err.name === 'AbortError') throw err
    return null
  }
  if (!a) return null
  a.done = true; a.running = false; a.reading = false; a.savedAt = meta.savedAt
  return a
}
async function loadSavedEvents(signal) {
  try {
    const r = await fetch(`/events/${state.tenant}`, { signal })
    if (!r.ok) return false
    const j = await r.json()
    if (!j.savedAt || Date.now() - j.savedAt > SAVED_MAX_AGE_HOURS * 3600 * 1000 || !Array.isArray(j.rows)) return false
    Object.assign(state.events, { rows: j.rows, running: false, done: true, savedAt: j.savedAt })
    return true
  } catch { return false }
}

async function loadAssets(t, signal) {
  const a = state.assets[t]
  try {
    const pg = await pageAssets({ assetType: t }, signal, (items) => {
      for (const raw of items) {
        const x = normalizeAsset(raw)
        const item = { k: x.key, l: colPath(x) || String(x.key), n: x.column, c: x.connection, tool: x.tool, tt: x.toolType, ot: x.objectType, ct: x.container, ins: numOrNull(pick(raw, 'ins', 'inCount')), outs: numOrNull(pick(raw, 'outs', 'outCount')), d: x.db, s: x.schema, tb: x.table }
        if (pick(raw, 'isSrcColumnOrphan') === true) item.fo = true
        ingest(a, item)
      }
      renderOverview()
    })
    a.done = true; a.hitCap = pg.hitCap
  } catch (err) { if (err.name !== 'AbortError') a.error = err.message } finally { a.running = false }
}

async function loadEvents(signal) {
  const ev = state.events
  const pagesRows = []
  let next = 1, stop = false
  const worker = async () => {
    while (!stop) {
      if (next > MAX_EVENT_PAGES) { ev.hitCap = true; stop = true; return }
      const p = next++
      try {
        const r = await api('/api/UserAccount/UserEvents', { signal, body: { PageNumber: p, RowsInPage: EVENT_PAGE } })
        const list = Array.isArray(r) ? r : ['events', 'items', 'data', 'rows'].map((k) => r?.[k]).find(Array.isArray)
        if (!list) { if (p === 1) ev.skipped = 'The events endpoint returned a format I do not recognise.'; stop = true; return }
        pagesRows[p] = list; state.lastProgress = Date.now()
        if (list.length < EVENT_PAGE) stop = true
      } catch (err) {
        if (err.name === 'AbortError') { stop = true; return }
        stop = true
        if (p === 1) ev.skipped = `This needs an admin account (${err.message}).`; else ev.error = err.message
      }
    }
  }
  await Promise.all([worker(), worker()])
  ev.rows = pagesRows.filter(Boolean).flat().filter((r) => r && typeof r === 'object')
  ev.running = false; ev.done = !ev.skipped && !ev.error
  renderEvents()
}

// ---------- Rendering: assets and events ----------
const orphSummary = (a) => ({ linkCounted: a.linkCounted, orphanTotal: a.orphanTotal, sources: a.sources, endpoints: a.endpoints, flagged: a.flagged, combos: [...a.orphanCombos.values()] })
function typeView(t) {
  const a = state.assets[t]
  if (a?.done && filterActive()) return filteredView(t)
  if (a && (a.total || a.done)) return { total: a.total, tools: a.tools.size, dbs: a.dbs.size, schemas: a.schemas.size, conns: [...a.conns.values()], combos: [...a.combos.values()], orph: orphSummary(a) }
  return state.cache.catalog?.types?.[t] || null
}
// ---------- KPI strip, freshness chip, tabs ----------
const fmtBig = (n) => (n == null ? '–' : n < 100000 ? n.toLocaleString() : new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 2 }).format(n))
const selType = () => Number(document.querySelector('input[name=bdtype]:checked').value)
function renderKpis() {
  const v1 = typeView(1), v2 = typeView(2), t = selType(), vt = typeView(t)
  const prev = state.cache.catalog?.prev, finished = !state.loading
  const delta = (ty, cur) => {
    const p = prev?.totals?.[ty]
    if (!finished || p == null || cur == null || filterActive()) return ['', '']
    const d = cur - p, when = new Date(prev.savedAt).toLocaleDateString()
    return [d === 0 ? `no change since ${when}` : `${d > 0 ? '+' : '−'}${Math.abs(d).toLocaleString()} since ${when}`, d > 0 ? 'up' : d < 0 ? 'down' : '']
  }
  const conns = new Set(), tools = new Set()
  for (const ty of [1, 2]) for (const c of typeView(ty)?.conns || []) { conns.add(c.name); if (c.tool) tools.add(c.tool) }
  const o = vt?.orph, orph = o?.linkCounted ? o.orphanTotal : null
  const ev = state.events, evRows = ev?.rows || [], { userK } = evKeys(evRows)
  const tile = (label, val, full, sub, cls = '', subcls = '') => `<div class="kpi ${cls}"><div class="kl">${esc(label)}</div><div class="kv" title="${esc(full ?? val)}">${esc(val)}</div><div class="kd ${subcls}">${esc(sub || '')}</div></div>`
  const [d2, c2] = delta(2, v2?.total), [d1, c1] = delta(1, v1?.total)
  $('#kpis').innerHTML = [
    tile('Column-level assets', fmtBig(v2?.total), v2?.total?.toLocaleString(), d2 || (v2 ? `${v2.dbs} databases · ${v2.schemas} schemas` : ''), '', c2),
    tile('Cross-system assets', fmtBig(v1?.total), v1?.total?.toLocaleString(), d1 || (v1 ? `${v1.dbs} databases · ${v1.schemas} schemas` : ''), '', c1),
    tile('Connections', v1 || v2 ? String(conns.size) : '–', null, `${tools.size} tools`),
    tile(`Orphans (${TYPE_NAME[t]})`, orph == null ? '–' : fmtBig(orph), orph?.toLocaleString(), orph == null ? 'needs lineage' : `${vt.total ? (orph / vt.total * 100).toFixed(1) : 0}% of assets`, orph > 0 ? 'alert' : ''),
    tile('User events', ev?.rows?.length ? fmtBig(evRows.length) : state.cache.catalog?.events ? fmtBig(state.cache.catalog.events.total) : '–', null, userK && evRows.length ? `${new Set(evRows.map((r) => r[userK])).size} users` : ev?.skipped ? 'admin account needed' : ''),
  ].join('')
  const ob = $('#tabOrph'); ob.hidden = !(orph > 0); ob.textContent = orph > 0 ? fmtBig(orph) : ''
}
function renderChip() {
  const parts = []
  const cat = state.loadFinishedAt || state.cache.catalog?.savedAt
  if (state.loading) parts.push('refreshing catalog…')
  else if (state.fromSaved) parts.push(`Catalog saved ${new Date(state.fromSaved).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}`)
  else if (cat) parts.push(`Catalog ${new Date(cat).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}`)
  const l = state.local?.lineage
  if (l && (l.up || l.down)) parts.push(`lineage saved: ${l.up.toLocaleString()} up · ${l.down.toLocaleString()} down`)
  $('#fresh2').textContent = parts.join(' · ')
}
function setTab(name) {
  state.tab = name
  document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('on', b.dataset.tab === name))
  document.querySelectorAll('.panel').forEach((p) => { p.hidden = p.dataset.panel !== name })
  $('#typeSeg').style.visibility = ['overview', 'explorer', 'orphans', 'health'].includes(name) ? 'visible' : 'hidden'
  try { localStorage.setItem('lineage-tab', name) } catch { /* storage unavailable */ }
  if (name === 'health') renderHealth()
  if (name === 'explorer') renderExplorer()
  if (name === 'overview') renderStats()
}
document.querySelector('.tabs').addEventListener('click', (e) => { const b = e.target.closest('.tab'); if (b) setTab(b.dataset.tab) })
$('#dlOpen').addEventListener('click', () => { if (counts()[1] || counts()[2]) showPrompt(); else $('#dlEmpty p').textContent = 'Load the catalog first (use Reload assets and events), then choose what to download.' })
document.querySelectorAll('input[name=bdtype]').forEach((r) => r.addEventListener('change', () => { renderKpis(); renderStats(); if (state.tab === 'health') renderHealth(); if (state.tab === 'explorer') renderExplorer() }))
function renderOverview() {
  const n = (v) => (v ?? 0).toLocaleString()
  renderKpis()
  const loading = state.loading
  const live = state.assets[1] || state.assets[2]
  const cachedOnly = !live?.total && state.cache.catalog
  if (!loading && state.fromSaved) $('#catState').textContent = `from saved files · saved ${new Date(state.fromSaved).toLocaleString()}`
  else $('#catState').textContent = loading ? (cachedOnly ? `showing saved numbers from ${new Date(state.cache.catalog.savedAt).toLocaleString()}, refreshing…` : 'still fetching…')
    : state.loadFinishedAt ? `up to date · ${new Date(state.loadFinishedAt).toLocaleTimeString()}` : cachedOnly ? `saved ${new Date(state.cache.catalog.savedAt).toLocaleString()}` : ''

  const warns = []
  for (const t of [1, 2]) {
    const a = state.assets[t]
    if (a?.hitCap) warns.push(`The ${TYPE_NAME[t]} list stopped at the ${MAX_PAGES}-page safety cap, so it may be larger than shown.`)
    else if (a?.done && a.total > 0 && a.total % PAGE === 0) warns.push(`The ${TYPE_NAME[t]} total is an exact multiple of 10,000, so the API may have stopped early. Treat it as a minimum.`)
  }
  for (const t of [1, 2]) {
    const a = state.assets[t]
    if (a?.fallback) warns.push(`Could not load ${TYPE_NAME[t]} assets from Octopai (${a.fallback}). Showing the saved copy from ${new Date(a.savedAt).toLocaleString()}. Click Reload assets and events to try again.`)
    else if (a?.error && !a.done && !loading) warns.push(`Could not load ${TYPE_NAME[t]} assets from Octopai: ${a.error}. No saved copy is available yet. Click Reload assets and events to try again.`)
  }
  $('#catWarn').hidden = !warns.length; $('#catWarn').textContent = warns.join(' ')

  const merged = new Map()
  for (const t of [1, 2]) for (const c of typeView(t)?.conns || []) {
    const m = merged.get(c.name) || { name: c.name, tool: c.tool, c1: 0, c2: 0 }
    m[`c${t}`] += c.count; merged.set(c.name, m)
  }
  const conns = [...merged.values()].sort((a, b) => (b.c1 + b.c2) - (a.c1 + a.c2))
  $('#connHead').textContent = `(${conns.length})`
  const shown = state.showAllConns ? conns : conns.slice(0, 8)
  const max = (conns[0]?.c1 + conns[0]?.c2) || 1
  $('#conns').innerHTML = shown.map((c) => `<div class="conn"><span class="nm">${esc(c.name || '(unnamed)')}</span><span class="tl">${esc(c.tool)}</span><span class="ct">${c.c2.toLocaleString()}</span><span class="ct">${c.c1.toLocaleString()}</span><span class="share" style="width:${Math.max(1, Math.round(Math.sqrt((c.c1 + c.c2) / max) * 100))}%"></span></div>`).join('')
  $('#moreConns').hidden = conns.length <= 8
  $('#moreConns').textContent = state.showAllConns ? 'Show fewer' : `+${conns.length - 8} more`
  renderBreakdown()
  renderStatus()
  renderChip()
  renderStats()
}
$('#moreConns').addEventListener('click', () => { state.showAllConns = !state.showAllConns; renderOverview() })

// Bottom bar: shows whatever is running now (lineage download, then asset loading, then a keyword scan).
function renderStatus() {
  const bar = $('#statusBar'), dl = state.dl, run = state.run
  let text = '', time = '', pct = null
  if (dl?.status === 'running') {
    const secs = (Date.now() - dl.startedAt) / 1000, rate = dl.done / Math.max(secs, 1)
    text = `Downloading lineage: ${dl.done.toLocaleString()} of ${dl.total.toLocaleString()} graphs` + (dl.done > 20 ? ` · about ${fmtDur((dl.total - dl.done) / rate)} left` : '')
    time = fmtDur(secs); pct = dl.done / Math.max(dl.total, 1) * 100
  } else if (state.loading) {
    const a1 = state.assets[1], a2 = state.assets[2], ev = state.events
    const idle = (Date.now() - (state.lastProgress || state.loadStartedAt)) / 1000
    const part = (a, name) => `${a.total.toLocaleString()} ${name}${a.reading ? ' (reading saved file)' : ''}${a.done ? ' ✓' : a.error ? ' (failed)' : ''}`
    text = `Loading: ${part(a2, 'column-level')}, ${part(a1, 'cross-system')} assets, ${ev.rows.length.toLocaleString()} events${ev.running ? '' : ' ✓'}…` +
      (idle > 30 ? ` · waiting on Octopai, no new data for ${fmtDur(idle)} (a request is retried if it takes over ${REQ_TIMEOUT_MS / 60000} min)` : '')
    time = `${Math.round((Date.now() - state.loadStartedAt) / 1000)}s`; pct = null
  } else if (state.saving) {
    const sv = state.saving
    text = sv.compressing ? `Saving ${TYPE_NAME[sv.t]} assets on this computer: compressing… keep this page open` : `Saving ${TYPE_NAME[sv.t]} assets on this computer: ${sv.done.toLocaleString()} of ${sv.total.toLocaleString()}… keep this page open`
    time = ''; pct = sv.compressing ? null : sv.done / Math.max(sv.total, 1) * 100
  } else if (run && ['finding', 'lineage', 'running'].some((s) => String(run.status).startsWith(s))) {
    text = `Keyword scan: ${run.status === 'lineage' ? `lineage ${run.done.toLocaleString()} of ${run.columns.length.toLocaleString()}` : run.status}`
    time = fmtDur((Date.now() - run.startedAt) / 1000); pct = run.columns.length ? run.done / run.columns.length * 100 : null
  } else if (state.loadFinishedAt) {
    const a1 = state.assets[1], a2 = state.assets[2]
    const failed = [1, 2].filter((t) => state.assets[t]?.error && !state.assets[t].done).map((t) => TYPE_NAME[t])
    text = (failed.length ? `Could not load ${failed.join(' or ')} assets (see the message above) · ` : '') + `Loaded ${a2.total.toLocaleString()} column-level and ${a1.total.toLocaleString()} cross-system assets` + (() => {
      const st = [1, 2].filter((t) => state.assets[t]?.savedAt)
      if (st.length === 2) return ` from saved files (saved ${new Date(state.fromSaved).toLocaleString()}; use Reload assets and events to refresh)`
      if (st.length === 1) return ` (${TYPE_NAME[st[0]]} from saved files, saved ${new Date(state.assets[st[0]].savedAt).toLocaleString()})`
      return ''
    })() + (state.saveNote ? ` · ${state.saveNote}` : '') + (state.dl ? ` · lineage download ${state.dl.status}` : '')
    time = `${Math.round((state.loadFinishedAt - state.loadStartedAt) / 1000)}s`; pct = 100
  }
  bar.hidden = !text || $('#appView').hidden
  $('#catText').textContent = text; $('#catTime').textContent = time
  $('#catBar').parentElement.classList.toggle('indet', pct === null)
  $('#catBar').style.width = pct === null ? '' : `${Math.round(pct)}%`
}
setInterval(() => { if (state.dl?.status === 'running' || state.loading || state.saving || state.run?.status === 'lineage') renderStatus() }, 1000)

// Breakdown of assets by category (rules in categories.js) with a subtotal per tool.
let bdChosen = false
document.querySelectorAll('input[name=bdtype]').forEach((r) => r.addEventListener('change', () => { bdChosen = true; renderBreakdown() }))
function renderBreakdown() {
  const el = $('#bd')
  let t = Number(document.querySelector('input[name=bdtype]:checked').value)
  if (!bdChosen && !(typeView(t)?.total) && typeView(t === 1 ? 2 : 1)?.total) { t = t === 1 ? 2 : 1; document.querySelector(`input[name=bdtype][value="${t}"]`).checked = true }
  const v = typeView(t)
  if (!v) { el.innerHTML = '<p class="muted small">Waiting for assets…</p>'; return }
  if (!v.combos) { el.innerHTML = '<p class="muted small">These saved numbers have no tool details. Reload assets to see the breakdown.</p>'; return }
  const cats = new Map(CATEGORY_ORDER.map((c) => [c.id, { ...c, total: 0, tools: new Map() }]))
  for (const c of v.combos) {
    const cat = cats.get(classify(c)) || cats.get('other')
    const name = c.tool || '(unknown tool)'
    const tl = cat.tools.get(name) || { name, type: c.toolType, count: 0 }
    tl.count += c.count; cat.total += c.count; cat.tools.set(name, tl)
  }
  const grand = [...cats.values()].reduce((s, c) => s + c.total, 0)
  const pct = (n) => (grand ? `${(n / grand * 100).toFixed(1)}%` : '')
  const shown = [...cats.values()].filter((c) => c.id !== 'other' || c.total)
  const stack = `<div class="stack" role="img" aria-label="Share of assets by category">${shown.filter((c) => c.total).map((c) => `<i style="width:${c.total / grand * 100}%;background:var(--c-${c.id})" title="${esc(c.name)}: ${c.total.toLocaleString()} (${pct(c.total)})"></i>`).join('')}</div><div class="legend">${shown.filter((c) => c.total).map((c) => `<span style="--c:var(--c-${c.id})">${esc(c.name)} ${pct(c.total)}</span>`).join('')}</div>`
  el.innerHTML = filterNote() + stack + shown.map((c) => {
    const rows = [...c.tools.values()].sort((a, b) => b.count - a.count)
      .map((x) => `<div class="toolrow"><span>${esc(x.name)}</span><span class="badge">${esc(x.type)}</span><span class="ct">${x.count.toLocaleString()}</span><span class="pct">${pct(x.count)}</span></div>`).join('')
    return `<details class="cat" style="--c:var(--c-${c.id})" ${c.total && c.total / grand > 0.02 ? 'open' : ''}><summary><span>${esc(c.name)}</span><span class="ct">${c.total.toLocaleString()}</span><span class="pct">${pct(c.total)}</span></summary>${rows || '<div class="toolrow muted"><span>No assets</span></div>'}</details>`
  }).join('') + `<div class="cattotal"><span>Total (${TYPE_NAME[t]})</span><span>${grand.toLocaleString()}</span><span></span></div>`
  renderOrphans()
}

// ---------- Orphans and broken lineage ----------
const newFindings = () => ({ dangling: [], danglingTotal: 0, mismatch: [], mismatchTotal: 0, failed: [], failedTotal: 0, confirmed: [], confirmedTotal: 0 })
const orphUi = { show: 15 }
const nf = (x) => (x ?? 0).toLocaleString()

function categorize(combos) {
  const cats = new Map(CATEGORY_ORDER.map((c) => [c.id, { ...c, total: 0, tools: new Map() }]))
  for (const c of combos || []) {
    const cat = cats.get(classify(c)) || cats.get('other')
    const name = c.tool || '(unknown tool)'
    const tl = cat.tools.get(name) || { name, type: c.toolType, count: 0 }
    tl.count += c.count; cat.total += c.count; cat.tools.set(name, tl)
  }
  return cats
}

function renderOrphans() {
  const el = $('#orph')
  const t = Number(document.querySelector('input[name=bdtype]:checked').value)
  const v = typeView(t), a = state.assets[t], f = state.findings
  if (!v) { el.innerHTML = '<p class="muted small">Waiting for assets…</p>'; return }
  const o = v.orph
  let html = filterNote()
  if (o && o.linkCounted) {
    const pct = v.total ? (o.orphanTotal / v.total * 100).toFixed(1) : '0.0'
    html += `<div class="pairs"><span><b>${nf(o.orphanTotal)}</b> orphans with no connections (${pct}% of ${TYPE_NAME[t]} assets)</span><span>${nf(o.sources)} sources (outputs only)</span><span>${nf(o.endpoints)} end points (inputs only)</span></div>`
    if (o.linkCounted < v.total) html += `<p class="muted small">Only ${nf(o.linkCounted)} of ${nf(v.total)} assets carry link counts, so the orphan count may be low.</p>`
    const cats = [...categorize(o.combos).values()].filter((c) => c.total)
    const allCats = categorize(v.combos)
    if (o.orphanTotal) {
      const worst = [...cats].sort((x, y) => y.total - x.total)[0]
      const other = cats.find((c) => c.id === 'other')
      html = `<div class="verdict"><b>${pct}%</b> of ${TYPE_NAME[t]} assets have no connections. ${worst.id === 'other' ? 'Most are unclassified' : `Most are in <b>${esc(worst.name)}</b>`} (${(worst.total / o.orphanTotal * 100).toFixed(0)}% of orphans).${other && worst.id !== 'other' ? ` ${nf(other.total)} are unclassified, so check <code>categories.js</code>.` : ''}</div>` + html
    } else html = '<div class="verdict fine">No orphans: every asset has at least one connection.</div>' + html
    html += `<h4>Orphan rate by category</h4><div class="hbars">${cats.map((c) => { const tot = allCats.get(c.id)?.total || 0, r = tot ? c.total / tot * 100 : 0; return `<div class="hbar"><span>${esc(c.name)}</span><span class="tr"><i style="width:${Math.min(100, r)}%;--c:var(--c-${c.id})"></i></span><span class="v">${nf(c.total)} of ${nf(tot)} · ${r.toFixed(1)}%</span></div>` }).join('')}</div>`
    html += cats.map((c) => `<details class="cat" style="--c:var(--c-${c.id})"><summary><span>${esc(c.name)}</span><span class="ct">${nf(c.total)}</span><span class="pct">${o.orphanTotal ? (c.total / o.orphanTotal * 100).toFixed(1) + '%' : ''}</span></summary>${[...c.tools.values()].sort((x, y) => y.count - x.count).map((x) => `<div class="toolrow"><span>${esc(x.name)}</span><span class="badge">${esc(x.type)}</span><span class="ct">${nf(x.count)}</span><span class="pct"></span></div>`).join('')}</details>`).join('')
    const list = v.orphans || a?.orphans || []
    if (list.length) {
      html += `<div class="scroll"><table class="ev"><tr><th>Orphan asset</th><th>Connection</th><th>Tool</th></tr>${list.slice(0, orphUi.show).map((x) => `<tr><td title="${esc(x.l)}">${esc(x.l)}</td><td>${esc(x.c)}</td><td>${esc(x.tool)}</td></tr>`).join('')}</table></div>`
      html += `<div class="muted small">Showing ${Math.min(orphUi.show, list.length).toLocaleString()} of ${nf(o.orphanTotal)}${list.length < o.orphanTotal ? ` (the list holds the first ${nf(list.length)})` : ''}. ${list.length > orphUi.show ? '<button class="linkbtn" id="orphMore" type="button">Show 50 more</button> ' : ''}<button class="linkbtn" id="orphCsv" type="button">Download orphans as CSV</button></div>`
    } else if (o.orphanTotal) html += '<p class="muted small">These are saved numbers. Reload assets to list the individual orphans.</p>'
    else html += '<p class="good small">No orphans found.</p>'
  } else {
    html += `<p class="muted small">These ${TYPE_NAME[t]} assets do not include link counts, so orphans cannot be found from the asset list alone. Download lineage (step 3): any asset with no links in either direction is then listed as a confirmed orphan.</p>`
  }

  html += '<h4>Broken lineage</h4>'
  const flagged = o?.flagged ?? 0
  html += `<div class="findrow"><span>Source columns Octopai itself flags as orphans</span><b>${nf(flagged)}</b></div>`
  if (f) {
    const lbl = state.dl?.status === 'running' ? ' (download still running)' : ''
    html += `<div class="findrow"><span>Links pointing to an asset that is not in the asset list${lbl}</span><b class="${f.danglingTotal ? 'bad' : ''}">${nf(f.danglingTotal)}</b></div>`
    html += `<div class="findrow"><span>Assets whose reported in/out count differs from the links found</span><b class="${f.mismatchTotal ? 'bad' : ''}">${nf(f.mismatchTotal)}</b></div>`
    html += `<div class="findrow"><span>Lineage requests that failed</span><b class="${f.failedTotal ? 'bad' : ''}">${nf(f.failedTotal)}</b></div>`
    html += `<div class="findrow"><span>Orphans confirmed by lineage (no links in either direction)</span><b>${nf(f.confirmedTotal)}</b></div>`
    if (state.dl?.truncated) html += `<div class="findrow"><span>Graphs that may be incomplete (hit the node limit)</span><b>${nf(state.dl.truncated)}</b></div>`
  } else html += '<p class="muted small">Links to missing assets, count mismatches and failed requests are found while lineage is downloaded (step 3).</p>'
  if (flagged || f) html += '<div class="muted small"><button class="linkbtn" id="findCsv" type="button">Download broken-lineage findings as CSV</button></div>'
  el.innerHTML = html
}
$('#orph').addEventListener('click', (e) => {
  if (e.target.id === 'orphMore') { orphUi.show += 50; renderOrphans(); return }
  if (e.target.id === 'orphCsv') {
    const t = Number(document.querySelector('input[name=bdtype]:checked').value)
    const rows = (typeView(t)?.orphans || state.assets[t]?.orphans || []).map((x) => [t, x.k, x.l, x.c, x.tool, x.tt, x.ot, CATEGORY_ORDER.find((c) => c.id === classify({ tool: x.tool, toolType: x.tt, objectType: x.ot, container: x.ct }))?.name])
    downloadBlob(new Blob(['﻿' + [['asset_type', 'key', 'asset', 'connection', 'tool', 'tool_type', 'object_type', 'category'], ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }), `orphans-${state.tenant}-${TYPE_NAME[t]}-${new Date().toISOString().slice(0, 10)}.csv`)
  }
  if (e.target.id === 'findCsv') {
    const f = state.findings || newFindings()
    const rows = []
    for (const t of [1, 2]) for (const x of state.assets[t]?.flaggedList || []) rows.push(['flagged by Octopai as orphan source column', t, x.l, '', ''])
    for (const x of f.dangling) rows.push(['link to missing asset', x.t, x.asset, x.dir, x.detail])
    for (const x of f.mismatch) rows.push(['in/out count mismatch', x.t, x.asset, x.dir, x.detail])
    for (const x of f.failed) rows.push(['request failed', x.t, x.asset, x.dir, x.detail])
    for (const x of f.confirmed) rows.push(['orphan confirmed by lineage', x.t, x.asset, '', 'no links in either direction'])
    downloadBlob(new Blob(['﻿' + [['finding', 'asset_type', 'asset', 'direction', 'detail'], ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }), `broken-lineage-${state.tenant}-${new Date().toISOString().slice(0, 10)}.csv`)
  }
})

// Checks one downloaded lineage graph for broken lineage.
function analyzeGraph(dl, t, it, d, r) {
  const f = state.findings
  const nodeKeys = new Set(r.nodes.map((n) => n.key)); nodeKeys.add(it.k)
  for (const [from, to] of r.edges) {
    const missing = [from, to].find((k) => k && !nodeKeys.has(k) && !dl.keySets[t].has(k))
    if (missing) { f.danglingTotal++; if (f.dangling.length < FIND_CAP) f.dangling.push({ t, asset: it.l, dir: DIR_NAME[d], detail: `link ${from} to ${to} points at ${missing}, which is not in the asset list` }); break }
  }
  if (!r.truncated && it.ins != null && it.outs != null) {
    const found = new Set()
    for (const [from, to] of r.edges) { if (d === 1 && to === it.k && from) found.add(from); if (d === 2 && from === it.k && to) found.add(to) }
    const reported = d === 1 ? it.ins : it.outs
    if (found.size !== reported) { f.mismatchTotal++; if (f.mismatch.length < FIND_CAP) f.mismatch.push({ t, asset: it.l, dir: DIR_NAME[d], detail: `reported ${reported}, found ${found.size}` }) }
  }
  const sk = `${t}|${it.k}`
  const s = dl.seen.get(sk) || {}
  s[d] = !r.truncated && !r.nodes.length && !r.edges.length
  dl.seen.set(sk, s)
  if (dl.dirs.length === 2 && s[1] && s[2]) { f.confirmedTotal++; if (f.confirmed.length < FIND_CAP) f.confirmed.push({ t, asset: it.l }); dl.seen.delete(sk) }
}
let lastFindSig = ''
function refreshOrphans() {
  const f = state.findings
  const sig = f ? `${f.danglingTotal}|${f.mismatchTotal}|${f.failedTotal}|${f.confirmedTotal}|${state.dl?.status}|${state.dl?.truncated}` : ''
  if (sig !== lastFindSig) { lastFindSig = sig; renderOrphans() }
}

function findKey(rows, candidates) {
  const keys = new Set(); rows.slice(0, 200).forEach((r) => Object.keys(r).forEach((k) => keys.add(k)))
  for (const c of candidates) for (const k of keys) if (norm(k) === norm(c)) return k
  return null
}
const topN = (rows, key, n) => { const m = new Map(); for (const r of rows) { const v = String(r[key] ?? ''); if (v) m.set(v, (m.get(v) || 0) + 1) } return [...m].sort((a, b) => b[1] - a[1]).slice(0, n) }

const evFilter = { types: new Set(), user: '', show: 25 }
const evKeys = (rows) => ({
  typeK: findKey(rows, ['eventType', 'eventName', 'event', 'action', 'type', 'eventTypeName']),
  userK: findKey(rows, ['userName', 'user', 'userEmail', 'email', 'displayName']),
  dateK: findKey(rows, ['eventDate', 'eventDateTime', 'eventTime', 'timestamp', 'createdDate', 'createdAt', 'date', 'time']),
})
function filteredEvents() {
  const rows = state.events?.rows || [], { typeK, userK } = evKeys(rows)
  return rows.filter((r) => (!evFilter.types.size || (typeK && evFilter.types.has(String(r[typeK])))) && (!evFilter.user || (userK && String(r[userK]) === evFilter.user)))
}

function renderEvents() {
  const ev = state.events
  const body = $('#evBody')
  if (!ev) { body.textContent = state.cache.catalog?.events ? `Last load: ${state.cache.catalog.events.total.toLocaleString()} events.` : 'Waiting…'; $('#evState').textContent = ''; return }
  $('#evState').textContent = ev.running ? 'loading…' : ev.skipped ? 'skipped' : ev.error ? 'stopped early' : 'loaded'
  renderKpis()
  if (ev.running && !ev.rows.length) { body.textContent = 'Loading events…'; return }
  if (ev.skipped) { body.textContent = `Skipped. ${ev.skipped}`; return }
  const all = ev.rows
  if (!all.length) { body.textContent = ev.error ? `Could not load events: ${ev.error}` : 'No user events were returned.'; return }
  const { typeK, userK, dateK } = evKeys(all)
  const rows = filteredEvents()
  let html = ''
  if (typeK || userK) {
    html += '<div class="filters">'
    if (typeK) html += `<div class="chips" id="evTypes">${topN(all, typeK, 40).map(([k, n]) => `<button type="button" class="chip${evFilter.types.has(k) ? ' on' : ''}" data-evtype="${esc(k)}">${esc(k)} (${n.toLocaleString()})</button>`).join('')}</div>`
    if (userK) html += `<label class="small">User <select id="evUser"><option value="">All users</option>${topN(all, userK, 500).map(([k, n]) => `<option value="${esc(k)}"${evFilter.user === k ? ' selected' : ''}>${esc(k)} (${n})</option>`).join('')}</select></label>`
    if (evFilter.types.size || evFilter.user) html += '<button type="button" class="linkbtn" id="evClear">Clear filters</button>'
    html += '</div>'
  }
  const parts = [`<span><b>${rows.length.toLocaleString()}</b>${rows.length === all.length ? '' : ` of ${all.length.toLocaleString()}`} events</span>`]
  if (typeK) parts.push(`<span><b>${new Set(rows.map((r) => r[typeK])).size}</b> event types</span>`)
  if (userK) parts.push(`<span><b>${new Set(rows.map((r) => r[userK])).size}</b> users</span>`)
  if (dateK) { const ds = rows.map((r) => r[dateK]).filter(Boolean).map(String).sort(); if (ds.length) parts.push(`<span>${esc(ds[0].slice(0, 19))} to ${esc(ds[ds.length - 1].slice(0, 19))}</span>`) }
  html += `<div class="pairs">${parts.join('')}</div>`
  if (dateK && rows.length) {
    const days = new Map(); for (const r of rows) { const d = String(r[dateK] || '').slice(0, 10); if (d) days.set(d, (days.get(d) || 0) + 1) }
    const list = [...days].sort((x, y) => x[0].localeCompare(y[0])).slice(-90), mx = Math.max(...list.map((x) => x[1]), 1)
    if (list.length > 1) html += `<div class="timeline" role="img" aria-label="Events per day">${list.map(([d, n]) => `<i style="height:${Math.max(3, n / mx * 100)}%" title="${esc(d)}: ${n.toLocaleString()} events"></i>`).join('')}</div><div class="tlabels"><span>${esc(list[0][0])}</span><span>events per day (peak ${mx.toLocaleString()})</span><span>${esc(list[list.length - 1][0])}</span></div>`
  }
  if (userK && rows.length) html += `<div class="muted small">Most active: ${topN(rows, userK, 5).map(([k, v]) => `${esc(k)} (${v})`).join(', ')}</div>`
  if (!rows.length) html += '<p class="muted">No events match these filters.</p>'
  else {
    const freq = new Map(); all.slice(0, 500).forEach((r) => Object.keys(r).forEach((k) => freq.set(k, (freq.get(k) || 0) + 1)))
    const filled = (k) => all.slice(0, 500).some((r) => r[k] !== null && r[k] !== undefined && r[k] !== '')
    const cols = [...freq].filter(([k]) => filled(k)).sort((x, y) => y[1] - x[1]).map(([k]) => k).slice(0, 6)
    html += `<div class="scroll"><table class="ev"><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr>${rows.slice(0, evFilter.show).map((r) => `<tr>${cols.map((c) => `<td title="${esc(r[c])}">${esc(typeof r[c] === 'object' ? JSON.stringify(r[c]) : r[c])}</td>`).join('')}</tr>`).join('')}</table></div>`
    html += `<div class="muted small">Showing ${Math.min(evFilter.show, rows.length).toLocaleString()} of ${rows.length.toLocaleString()}. ${rows.length > evFilter.show ? '<button class="linkbtn" id="evMore" type="button">Show 50 more</button> ' : ''}${ev.hitCap ? `Stopped at the ${MAX_EVENT_PAGES}-page cap. ` : ''}${ev.error ? `Stopped early: ${esc(ev.error)}. ` : ''}<button class="linkbtn" id="evCsv" type="button">Download ${rows.length === all.length ? 'all' : 'these'} events as CSV</button></div>`
  }
  body.innerHTML = html
}
$('#evBody').addEventListener('click', (e) => {
  const chip = e.target.closest('[data-evtype]')
  if (chip) { const k = chip.dataset.evtype; evFilter.types.has(k) ? evFilter.types.delete(k) : evFilter.types.add(k); evFilter.show = 25; renderEvents(); return }
  if (e.target.id === 'evClear') { evFilter.types.clear(); evFilter.user = ''; evFilter.show = 25; renderEvents(); return }
  if (e.target.id === 'evMore') { evFilter.show += 50; renderEvents(); return }
  if (e.target.id === 'evCsv') {
    const rows = filteredEvents()
    const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))]
    const csv = [cols, ...rows.map((r) => cols.map((c) => (typeof r[c] === 'object' && r[c] !== null ? JSON.stringify(r[c]) : r[c])))].map((row) => row.map(csvCell).join(',')).join('\r\n')
    downloadBlob(new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' }), `user-events-${state.tenant}-${new Date().toISOString().slice(0, 10)}.csv`)
  }
})
$('#evBody').addEventListener('change', (e) => { if (e.target.id === 'evUser') { evFilter.user = e.target.value; evFilter.show = 25; renderEvents() } })

// ---------- Stage 3: ask before downloading lineage ----------
function counts() { return { 1: activeItems(1).length, 2: activeItems(2).length } }
function showPrompt() {
  const c = counts()
  $('#lineagePrompt').hidden = false; $('#dlReopen').hidden = true; $('#dlEmpty p').textContent = 'Download the lineage graphs for your assets to find confirmed orphans and broken links. Results are saved on this computer and also feed the local keyword scan.'
  const ev = state.events
  $('#promptSummary').textContent = (filterActive() ? 'The source filter is on, so only assets from the selected sources are counted. ' : '') + `Assets are loaded (${c[2].toLocaleString()} column-level, ${c[1].toLocaleString()} cross-system)` + (ev?.done ? ` and ${ev.rows.length.toLocaleString()} user events.` : ev?.skipped ? '. User events were skipped.' : '.') + ' Do you want to start downloading lineage for them now?'
  $('#optT2Label').textContent = `Column-level (${c[2].toLocaleString()} assets)`
  $('#optT1Label').textContent = `Cross-system (${c[1].toLocaleString()} assets)`
  // Pre-select the smaller non-empty set so the default is the cheaper download.
  const pre = c[1] && (!c[2] || c[1] <= c[2]) ? 1 : c[2] ? 2 : 0
  $('#optT1').checked = pre === 1; $('#optT2').checked = pre === 2
  $('#optT1').disabled = !c[1]; $('#optT2').disabled = !c[2]
  updateEstimate()
}
function selection() {
  const c = counts(), limit = Number($('#optLimit').value) || 0
  const types = [2, 1].filter((t) => $(`#optT${t}`).checked && c[t])
  const dirs = [1, 2].filter((d) => $(d === 1 ? '#optUp' : '#optDown').checked)
  const per = Object.fromEntries(types.map((t) => [t, limit ? Math.min(limit, c[t]) : c[t]]))
  const calls = types.reduce((s, t) => s + per[t], 0) * dirs.length
  return { types, dirs, limit, per, calls }
}
function updateEstimate() {
  const s = selection()
  $('#dlStart').disabled = !s.calls
  $('#promptEstimate').textContent = s.calls
    ? `This makes about ${s.calls.toLocaleString()} requests (one per asset per direction)${$('#optSkip').checked ? ', fewer if some already have saved lineage' : ''}, 6 at a time, and writes the results to a file as it goes.${s.calls > 5000 ? ' That is a lot, so it may take a long time. Keep this tab open. If the token expires you will be asked for your password to continue.' : ''}`
    : 'Choose at least one set of assets and one direction.'
}
document.querySelectorAll('#optT1,#optT2,#optUp,#optDown,#optLimit,#optSkip,#optAge').forEach((el) => el.addEventListener('input', updateEstimate))
$('#dlLater').addEventListener('click', () => { $('#lineagePrompt').hidden = true; $('#dlReopen').hidden = false })
$('#dlReopen').addEventListener('click', () => setTab('download'))
$('#dlReopen').addEventListener('click', () => { if (!state.dl || state.dl.status !== 'running') showPrompt() })
$('#dlCancel').addEventListener('click', () => state.dl?.abort.abort())

// ---------- Lineage download (streamed to a file on the local server) ----------
$('#dlStart').addEventListener('click', startDownload)
async function startDownload() {
  const s = selection(); if (!s.calls) return
  const jobs = []
  const skipOn = $('#optSkip').checked, maxAgeMs = Number($('#optAge').value) * 86400000
  let skipped = 0
  const have = {}
  if (skipOn) {
    $('#dlStart').disabled = true; $('#promptEstimate').textContent = 'Checking what is already saved…'
    try {
      for (const t of s.types) for (const d of s.dirs) { const r = await fetch(`/local/${state.tenant}/have?type=${t}&dir=${DIR_NAME[d]}`); have[`${t}|${d}`] = r.ok ? (await r.json()).have : {} }
    } catch { /* fall back to downloading everything */ }
    $('#dlStart').disabled = false
  }
  const isFresh = (t, d, k) => { const at = have[`${t}|${d}`]?.[k]; return !!at && (!maxAgeMs || Date.now() - at < maxAgeMs) }
  for (const t of s.types) {
    const items = activeItems(t)
    const todo = skipOn ? items.filter((it) => s.dirs.some((d) => !isFresh(t, d, it.k))) : items
    for (const it of todo.slice(0, s.limit ? s.limit : todo.length)) for (const d of s.dirs) { if (skipOn && isFresh(t, d, it.k)) skipped++; else jobs.push([t, it, d]) }
  }
  if (!jobs.length) { $('#promptEstimate').textContent = 'Everything selected already has saved lineage, so there is nothing to download. Untick "Skip assets that already have saved lineage" to download again.'; return }
  const runId = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
  const dl = state.dl = { runId, total: jobs.length, done: 0, errors: 0, truncated: 0, nodes: 0, startedAt: Date.now(), abort: new AbortController(), status: 'running', buf: [], flushing: Promise.resolve(), note: '', dirs: s.dirs, seen: new Map(), keySets: {}, skipped }
  for (const t of s.types) dl.keySets[t] = new Set(state.assets[t].items.map((x) => x.k))
  state.findings = newFindings(); lastFindSig = ''; renderOrphans()
  $('#lineagePrompt').hidden = true; $('#dlCard').hidden = false; $('#dlJson').hidden = true; $('#dlCsv').hidden = true
  $('#dlCancel').hidden = false; $('#catalogBtn').disabled = true
  renderDl()
  const timer = setInterval(renderDl, 1000)
  const flush = (force) => {
    if (!dl.buf.length || (!force && dl.buf.length < 200)) return
    const body = dl.buf.join('\n') + '\n'; dl.buf = []
    dl.flushing = dl.flushing.then(async () => { const r = await fetch(`/export/${state.tenant}/${runId}`, { method: 'POST', body }); if (!r.ok) throw new Error('write failed') }).catch(() => { dl.note = 'Warning: some results could not be written to the export file.' })
  }
  let i = 0
  const worker = async () => {
    while (i < jobs.length && !dl.abort.signal.aborted) {
      const [t, it, d] = jobs[i++]
      const line = { t, key: it.k, label: it.l, dir: DIR_NAME[d] }
      try {
        const r = await lineageRaw(it.k, t, d, dl.abort.signal)
        Object.assign(line, { truncated: r.truncated, nodes: r.nodes, edges: r.edges })
        dl.nodes += r.nodes.length; if (r.truncated) dl.truncated++
        analyzeGraph(dl, t, it, d, r)
      } catch (err) {
        if (err.name === 'AbortError' || err.auth) { dl.abort.abort(); return }
        dl.errors++; Object.assign(line, { error: err.message, nodes: [], edges: [] })
        state.findings.failedTotal++; if (state.findings.failed.length < FIND_CAP) state.findings.failed.push({ t, asset: it.l, dir: DIR_NAME[d], detail: err.message })
      }
      dl.buf.push(JSON.stringify(line)); dl.done++; flush(false)
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker))
  clearInterval(timer); flush(true); await dl.flushing
  dl.status = dl.done >= dl.total ? 'complete' : 'stopped'; dl.finishedAt = Date.now()
  $('#catalogBtn').disabled = false; $('#dlCancel').hidden = true; $('#dlReopen').hidden = false; refreshLocalStatus()
  coverage.data = {}; renderStats(); if (state.tab === 'health') renderHealth()
  if (dl.done) { $('#dlJson').href = `/export/${state.tenant}/${runId}`; $('#dlCsv').href = `/export/${state.tenant}/${runId}?format=csv`; $('#dlJson').hidden = false; $('#dlCsv').hidden = false }
  renderDl()
}
function renderDl() {
  const dl = state.dl; if (!dl) return
  const secs = ((dl.finishedAt || Date.now()) - dl.startedAt) / 1000
  const rate = dl.done / Math.max(secs, 1), left = rate ? (dl.total - dl.done) / rate : 0
  $('#dlBar').style.width = `${Math.round(dl.done / Math.max(dl.total, 1) * 100)}%`
  $('#dlState').textContent = dl.status === 'running' ? 'running' : dl.status === 'complete' ? 'complete' : 'stopped early. Partial results are saved.'
  $('#dlStats').textContent = `${dl.done.toLocaleString()} of ${dl.total.toLocaleString()} graphs · ${dl.nodes.toLocaleString()} related assets · ${rate.toFixed(1)} per second` + (dl.status === 'running' && dl.done > 20 ? ` · about ${fmtDur(left)} left` : '') + (dl.errors ? ` · ${dl.errors} failed` : '') + (dl.truncated ? ` · ${dl.truncated} possibly incomplete (hit the node limit)` : '')
  renderStatus(); refreshOrphans()
  $('#dlNote').textContent = dl.note || (dl.status === 'complete' ? `Saved on this computer in the data/exports/${state.tenant} folder as ${dl.runId}.ndjson.` : '') + (dl.skipped ? ` ${dl.skipped.toLocaleString()} requests were skipped because lineage was already saved. Orphan and broken-lineage findings below cover only what was downloaded in this run.` : '')
}

// ---------- Lineage for one asset ----------
// The endpoint has no paging and no "truncated" flag, so a graph that comes back with exactly `limit` nodes may have
// been cut off: ask again with a 4x bigger limit (up to 200,000) and flag it if it is still full.
async function lineageRaw(key, assetType, direction, signal) {
  let limit = LINEAGE_LIMIT, r
  for (let tries = 0; ; tries++) {
    r = await api('/api/v2.0/lineage', { signal, body: { assetKey: key, depth: DEPTH, direction, limit, assetType } })
    if ((r.nodes || []).length < limit || limit >= LINEAGE_MAX_LIMIT || tries >= 4) break
    limit = Math.min(limit * 4, LINEAGE_MAX_LIMIT)
  }
  const truncated = (r.nodes || []).length >= limit
  const nodes = (r.nodes || []).filter((n) => n && pick(n, '_key', 'rid', 'objectGUID') !== key && !n.isStartNode).map(summarizeNode)
  const edges = (r.edges || r.links || []).map((e) => [pick(e, '_from', 'FromRid', 'from'), pick(e, '_to', 'ToRid', 'to')])
  return { nodes, edges, truncated }
}
function summarizeNode(n) {
  const p = n.properties || {}
  const flat = normalizeAsset(n)
  return {
    key: flat.key || n.Rid || '',
    name: String(pick(n, 'objectNameFull', 'objectName', 'assetName', 'name') || p.ObjectName || ''),
    connection: flat.connection || p.ConnectionName || '',
    db: flat.db || p.DB || '', schema: flat.schema || p.Schema || '', table: flat.table || p.Table || '',
    tool: flat.tool || n.tool || p.ToolName || '', type: String(pick(n, 'toolType') || n.type || p.ToolType || ''),
    depth: Number(n.depth ?? 0),
  }
}
// Keyword-scan version: uses the 24 hour cache.
async function lineageFor(col, direction, signal, useCache) {
  const k = `${col.key}|${direction}`
  const hit = state.cache.lineage[k]
  if (useCache && hit && Date.now() - hit.at < CACHE_MAX_AGE_MS) return { nodes: hit.nodes, truncated: !!hit.truncated, cached: true }
  const r = await lineageRaw(col.key, 2, direction, signal)
  state.cache.lineage[k] = { at: Date.now(), nodes: r.nodes, truncated: r.truncated }; state.cacheDirty = true
  return { nodes: r.nodes, truncated: r.truncated, cached: false }
}

// ---------- Keyword scan ----------
$('#scanForm').addEventListener('submit', (e) => { e.preventDefault(); startScan() })
$('#cancelBtn').addEventListener('click', () => state.run?.abort.abort())

async function startScan() {
  const names = [...new Set($('#keywords').value.split(',').map((s) => s.trim()).filter(Boolean))]
  if (!names.length) return
  const mode = document.querySelector('input[name=mode]:checked').value
  const useCache = !$('#fresh').checked
  if (document.querySelector('input[name=src]:checked').value === 'local') return runLocalScan(names, mode)
  const abort = new AbortController()
  const run = state.run = { names, mode, abort, startedAt: Date.now(), columns: [], done: 0, cachedCount: 0, failed: 0, status: 'running', error: '' }
  $('#scanBtn').disabled = true; $('#cancelBtn').hidden = false
  $('#results').hidden = false; $('#groups').innerHTML = ''
  renderSummary()
  try {
    run.status = 'finding'; renderSummary()
    const raw = await findColumns(names, abort.signal, (n) => { run.status = `finding (${n.toLocaleString()} matches so far)`; renderSummary() })
    const lower = names.map((n) => n.toLowerCase())
    const seen = new Set()
    run.columns = raw.map(normalizeAsset).filter((c) => c.key && c.column && !seen.has(c.key) && seen.add(c.key))
      .filter((c) => lower.some((n) => c.column.toLowerCase().includes(n)))
      .map((c) => ({ ...c, keyword: names[lower.findIndex((n) => c.column.toLowerCase().includes(n))], nodes: null, error: '' }))
    run.columns.sort((a, b) => colPath(a).localeCompare(colPath(b)) || 0)
    run.status = 'lineage'; renderAll()
    let i = 0
    const worker = async () => {
      while (i < run.columns.length && !abort.signal.aborted) {
        const col = run.columns[i++]
        try {
          const r = await lineageFor(col, MODES[mode].direction, abort.signal, useCache)
          col.nodes = r.nodes; col.truncated = r.truncated; if (r.cached) run.cachedCount++; if (r.truncated) run.truncatedCount = (run.truncatedCount || 0) + 1
        } catch (err) {
          if (err.name === 'AbortError') return
          if (err.auth) { abort.abort(); run.error = err.message; return }
          col.error = err.message; col.nodes = []; run.failed++
        }
        run.done++
        if (run.done % 5 === 0 || run.done === run.columns.length) { renderSummary(); renderAll() }
        if (run.done % 50 === 0) saveCache()
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, worker))
    run.status = abort.signal.aborted ? (run.error ? 'error' : 'stopped') : 'complete'
  } catch (err) {
    run.status = err.name === 'AbortError' ? 'stopped' : 'error'
    if (err.name !== 'AbortError') run.error = err.message
  }
  run.finishedAt = Date.now()
  await saveCache()
  $('#scanBtn').disabled = false; $('#cancelBtn').hidden = true
  renderAll(); updateCacheNote()
}

// ---------- Keyword scan against local files ----------
// Searches the asset list saved on this computer, then reads lineage from the saved scan cache and the lineage downloads.
// Nothing is sent to Octopai.
const jpost = async (url, body) => { const r = await fetch(url, { method: 'POST', body: JSON.stringify(body) }); if (!r.ok) throw new Error(`Local read failed (${r.status})`); return r.json() }
// Saves the asset list in chunks (compact rows plus a dictionary of repeated strings), so even millions of assets save
// without building one huge string. The server compresses it and swaps it in only when every chunk has arrived.
const SAVE_CHUNK = 50000
async function saveAssetsLocal(types = [1, 2]) {
  for (const t of types) {
    const a = state.assets[t]; if (!a?.done || a.error || a.savedAt) continue
    const items = a.items
    state.saving = { t, done: 0, total: items.length }; renderStatus()
    const post = async (op, body) => { const r = await fetch(`/assets/${state.tenant}/${t}?op=${op}`, { method: 'POST', body }); if (!r.ok) throw new Error(`save ${op} failed (${r.status})`) }
    try {
      const dict = new Map()
      const di = (v) => { v = v ?? ''; let i = dict.get(v); if (i === undefined) { i = dict.size; dict.set(v, i) } return i }
      for (const x of items) { di(x.c); di(x.tool); di(x.tt); di(x.ot); di(x.ct); di(x.d); di(x.s); di(x.tb) }
      await post('begin', JSON.stringify({ meta: { savedAt: Date.now(), count: items.length, v: 3 } }) + '\n' + JSON.stringify({ dict: [...dict.keys()] }) + '\n')
      for (let i = 0; i < items.length; i += SAVE_CHUNK) {
        const body = items.slice(i, i + SAVE_CHUNK).map((x) => JSON.stringify([x.k, x.n, di(x.c), di(x.tool), di(x.tt), di(x.ot), di(x.ct), di(x.d), di(x.s), di(x.tb), x.ins ?? null, x.outs ?? null, x.fo ? 1 : 0])).join('\n') + '\n'
        await post('append', body)
        state.saving.done = Math.min(i + SAVE_CHUNK, items.length); renderStatus()
      }
      state.saving.compressing = true; renderStatus()
      await post('commit', '')
      state.saveNote = `Saved ${items.length.toLocaleString()} ${TYPE_NAME[t]} assets on this computer.`
    } catch (err) {
      state.saveNote = `Could not save the ${TYPE_NAME[t]} assets on this computer (${err.message}), so they will be downloaded again next time.`
    } finally { state.saving = null; renderStatus() }
  }
  refreshLocalStatus()
}
async function refreshLocalStatus() {
  try { const r = await fetch(`/local/${state.tenant}/status`); state.local = r.ok ? await r.json() : null } catch { state.local = null }
  renderLocalNote(); renderChip()
}
function renderLocalNote() {
  const l = state.local, el = $('#localNote'), a = l?.assets?.[2]
  const live = document.querySelector('input[name=src]:checked').value === 'live'
  $('#fresh').closest('label').hidden = !live
  if (!l) { el.textContent = ''; return }
  el.textContent = a
    ? `Local files: ${a.count.toLocaleString()} column-level assets saved ${new Date(a.savedAt).toLocaleString()}; lineage saved for ${l.lineage.up.toLocaleString()} columns upstream and ${l.lineage.down.toLocaleString()} downstream.`
    : 'No local catalog saved for this site yet. Load the catalog first, or choose Live from Octopai.'
  if (!state.srcTouched) { const want = a ? 'local' : 'live'; const el2 = document.querySelector(`input[name=src][value=${want}]`); if (!el2.checked) { el2.checked = true; renderLocalNote() } }
}
document.querySelectorAll('input[name=src]').forEach((r) => r.addEventListener('change', () => { state.srcTouched = true; renderLocalNote() }))

async function runLocalScan(names, mode) {
  const abort = new AbortController()
  const run = state.run = { names, mode, abort, startedAt: Date.now(), columns: [], done: 0, cachedCount: 0, failed: 0, status: 'finding', error: '', local: true }
  $('#scanBtn').disabled = true; $('#fetchMissing').hidden = true
  $('#results').hidden = false; $('#groups').innerHTML = ''
  renderSummary()
  const dir = MODES[mode].direction
  try {
    const r = await fetch(`/local/${state.tenant}/find?type=2&keywords=${encodeURIComponent(names.join(','))}`)
    if (r.status === 404) throw new Error('No local catalog saved yet. Load the catalog first, or choose Live from Octopai.')
    if (!r.ok) throw new Error(`Local search failed (${r.status})`)
    const f = await r.json()
    run.savedAt = f.savedAt
    const lower = names.map((n) => n.toLowerCase())
    run.columns = f.matches.map((m) => ({ key: m.k, column: m.n || m.l, label: m.l, connection: m.c, tool: m.tool, keyword: names[lower.findIndex((n) => String(m.n || '').toLowerCase().includes(n))] || names[0], nodes: null, error: '' }))
    run.columns.sort((a, b) => colPath(a).localeCompare(colPath(b)) || 0)
    run.status = 'lineage'; renderAll()
    for (let i = 0; i < run.columns.length; i += 1000) {
      const batch = run.columns.slice(i, i + 1000)
      const { found } = await jpost(`/local/${state.tenant}/lineage`, { direction: dir, keys: batch.map((c) => c.key) })
      for (const c of batch) {
        const g = found[c.key]
        if (g) { c.nodes = g.nodes; c.truncated = g.truncated; run.cachedCount++; if (g.truncated) run.truncatedCount = (run.truncatedCount || 0) + 1 }
        else { c.nodes = null; c.missing = true; run.missing = (run.missing || 0) + 1 }
        run.done++
      }
      renderSummary(); renderAll()
    }
    run.status = 'complete'
  } catch (err) { run.status = 'error'; run.error = err.message }
  run.finishedAt = Date.now()
  $('#scanBtn').disabled = false
  const m = $('#fetchMissing'); m.hidden = !run.missing
  if (run.missing) m.textContent = `Fetch lineage for the ${run.missing.toLocaleString()} missing columns from Octopai`
  renderAll()
}
$('#fetchMissing').addEventListener('click', async () => {
  const r = state.run; if (!r?.local) return
  const todo = r.columns.filter((c) => c.missing)
  const abort = r.abort = new AbortController()
  $('#fetchMissing').disabled = true; r.fetching = true; r.fetchDone = 0; r.fetchTotal = todo.length
  let i = 0
  const worker = async () => {
    while (i < todo.length && !abort.signal.aborted) {
      const col = todo[i++]
      try {
        const x = await lineageFor(col, MODES[r.mode].direction, abort.signal, false)
        col.nodes = x.nodes; col.truncated = x.truncated; col.missing = false; r.missing--
      } catch (err) {
        if (err.name === 'AbortError') return
        if (err.auth) { abort.abort(); return }
        col.error = err.message; col.nodes = []; col.missing = false; r.missing--; r.failed++
      }
      r.fetchDone++
      if (r.fetchDone % 5 === 0) { renderSummary(); renderAll() }
      if (r.fetchDone % 50 === 0) saveCache()
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker))
  r.fetching = false; await saveCache(); refreshLocalStatus()
  const m = $('#fetchMissing'); m.disabled = false; m.hidden = !r.missing
  if (r.missing) m.textContent = `Fetch lineage for the ${r.missing.toLocaleString()} missing columns from Octopai`
  renderSummary(); renderAll()
})

// ---------- Rendering: keyword results ----------
function renderSummary() {
  const r = state.run; if (!r) return
  const conns = new Set(r.columns.map((c) => c.connection)).size
  const total = r.columns.length
  $('#summaryText').textContent = total ? `${total.toLocaleString()} columns across ${conns} connection${conns === 1 ? '' : 's'}` : (r.status === 'complete' ? 'No matching columns found' : 'Searching…')
  $('#bar').style.width = r.status === 'complete' ? '100%' : total ? `${Math.round((r.done / total) * 100)}%` : '5%'
  const parts = []
  const label = { complete: 'Complete', stopped: 'Stopped early. Results are partial.', error: `Stopped by an error: ${r.error}` }[r.status]
  parts.push(label || (r.status === 'lineage' ? `Fetching lineage ${r.done.toLocaleString()} of ${total.toLocaleString()}` : `Working: ${r.status}`))
  if (r.local) parts.unshift(`From local files${r.savedAt ? ' saved ' + new Date(r.savedAt).toLocaleString() : ''}`)
  if (r.fetching) parts.push(`fetching missing lineage ${r.fetchDone} of ${r.fetchTotal}`)
  if (r.local && r.missing) parts.push(`${r.missing.toLocaleString()} without local lineage`)
  if (r.cachedCount) parts.push(`${r.cachedCount.toLocaleString()} ${r.local ? 'found in local files' : 'from cache'}`)
  if (r.failed) parts.push(`${r.failed} failed`)
  if (r.truncatedCount) parts.push(`${r.truncatedCount} graph(s) may be incomplete (hit the node limit)`)
  $('#status').textContent = parts.join(' · ')
  renderStatus()
  $('#reportHead').innerHTML = `<h1>Lineage scan report</h1>
    <div><b>Site:</b> ${esc(state.tenant)}.octopai.com &nbsp; <b>Mode:</b> ${esc(MODES[r.mode].label)}</div>
    <div><b>Keywords:</b> ${esc(r.names.join(', '))}</div>
    <div><b>Run:</b> ${new Date(r.startedAt).toLocaleString()} by ${esc(state.user)} &nbsp; <b>Status:</b> ${esc(label || r.status)}</div>
    <div><b>Data:</b> ${r.local ? 'local files' + (r.savedAt ? ' saved ' + esc(new Date(r.savedAt).toLocaleString()) : '') : 'live from Octopai'}</div>
    <div><b>Result:</b> ${esc($('#summaryText').textContent)}</div>`
}

function renderAll() {
  renderSummary()
  const r = state.run; if (!r) return
  const byConn = new Map()
  for (const c of r.columns) { if (!byConn.has(c.connection)) byConn.set(c.connection, []); byConn.get(c.connection).push(c) }
  const open = new Set([...document.querySelectorAll('#groups details[open]')].map((d) => d.dataset.k))
  let html = ''
  for (const [conn, cols] of [...byConn].sort((a, b) => b[1].length - a[1].length)) {
    html += `<div class="group"><h3><span>${esc(conn || '(unnamed connection)')}</span><span class="tag">${cols.length.toLocaleString()} column${cols.length === 1 ? '' : 's'}</span></h3>`
    for (const c of cols.slice(0, 500)) {
      const n = c.nodes
      const count = c.missing ? '<span class="muted">no local lineage</span>' : n === null ? 'waiting…' : c.error ? `<span style="color:var(--bad)">failed</span>` : `<b>${n.length.toLocaleString()}</b> ${r.mode === 'source' ? 'sources' : 'consumers'}${c.truncated ? ' (may be incomplete)' : ''}`
      html += `<details data-k="${esc(c.key)}"${open.has(c.key) ? ' open' : ''}><summary><span class="path">${esc(colPath(c))}<span class="badge">${esc(c.tool)}</span></span><span class="count">${count}</span></summary>`
      if (c.error) html += `<p class="error small">${esc(c.error)}</p>`
      else if (n && n.length) {
        html += '<table class="nodes"><tr><th>Hop</th><th>Column / object</th><th>Location</th><th>Tool</th></tr>'
        for (const x of n.slice(0, 200)) html += `<tr><td>${x.depth}</td><td>${esc(x.name)}</td><td>${esc([x.connection, x.db, x.schema, x.table].filter(Boolean).join(' › '))}</td><td>${esc(x.tool)}</td></tr>`
        html += '</table>'
        if (n.length > 200) html += `<p class="muted small">+${(n.length - 200).toLocaleString()} more. All are included in the CSV download.</p>`
      } else if (n) html += `<p class="muted small">No ${r.mode === 'source' ? 'upstream sources' : 'downstream consumers'} found.</p>`
      html += '</details>'
    }
    if (cols.length > 500) html += `<p class="muted small">Showing the first 500 of ${cols.length.toLocaleString()} in this connection. All are included in the CSV download.</p>`
    html += '</div>'
  }
  $('#groups').innerHTML = html
}

// ---------- Export ----------
function csvCell(v) { const s = String(v ?? ''); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s }
function downloadBlob(blob, name) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href)
}
$('#csvBtn').addEventListener('click', () => {
  const r = state.run; if (!r) return
  const head = ['site', 'mode', 'keyword', 'run_at', 'run_by', 'scan_status', 'match_connection', 'match_path', 'match_tool', 'lineage_possibly_incomplete', 'hop', 'related_name', 'related_connection', 'related_db', 'related_schema', 'related_table', 'related_tool']
  const meta = [`${state.tenant}.octopai.com`, MODES[r.mode].label]
  const runInfo = [new Date(r.startedAt).toISOString(), state.user, r.status]
  const rows = [head]
  for (const c of r.columns) {
    const base = [...meta, c.keyword, ...runInfo, c.connection, colPath(c), c.tool, c.truncated ? 'yes' : '']
    if (c.nodes && c.nodes.length) for (const x of c.nodes) rows.push([...base, x.depth, x.name, x.connection, x.db, x.schema, x.table, x.tool])
    else rows.push([...base, '', '', '', '', '', '', ''])
  }
  downloadBlob(new Blob(['﻿' + rows.map((row) => row.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }),
    `lineage-${state.tenant}-${r.mode}-${r.names.join('_').replace(/[^\w-]+/g, '').slice(0, 40)}-${new Date(r.startedAt).toISOString().slice(0, 10)}.csv`)
})
$('#printBtn').addEventListener('click', () => window.print())
window.addEventListener('beforeprint', () => document.querySelectorAll('#groups details').forEach((d) => { d.dataset.was = d.open ? '1' : ''; d.open = true }))
window.addEventListener('afterprint', () => document.querySelectorAll('#groups details').forEach((d) => { d.open = d.dataset.was === '1' }))

// ---------- Small UI bits ----------
function updateHelp() { $('#modeHelp').textContent = MODES[document.querySelector('input[name=mode]:checked').value].help }
document.querySelectorAll('input[name=mode]').forEach((r) => r.addEventListener('change', updateHelp))
updateHelp()
$('#chips').innerHTML = PRESETS.map((p) => `<button type="button" class="chip" data-k="${p}">${p}</button>`).join('')
$('#chips').addEventListener('click', (e) => {
  const k = e.target.dataset.k; if (!k) return
  const cur = $('#keywords').value.split(',').map((s) => s.trim()).filter(Boolean)
  if (!cur.includes(k)) cur.push(k)
  $('#keywords').value = cur.join(', ')
})

// ---------- Source filter (like the metadata source picker in Octopai's lineage dashboard) ----------
// Unchecked connections are left out of the KPIs, Overview, Orphans & Health, Catalog Health and the lineage download.
const srcFilter = { off: new Set() }
const fvMemo = new Map(), itemsMemo = new Map()
const filterKey = () => `lineage-srcoff-${state.tenant}`
function loadFilter() { try { return new Set(JSON.parse(localStorage.getItem(filterKey()) || '[]')) } catch { return new Set() } }
function saveFilter() { try { localStorage.setItem(filterKey(), JSON.stringify([...srcFilter.off])) } catch { /* storage unavailable */ } }
const normType = (tt) => { const u = String(tt || '').toUpperCase(); return u === 'DATABASE' ? 'DB' : u || 'OTHER' }
const filterSig = () => [...srcFilter.off].sort().join('\u0001')
const filterActive = () => srcFilter.off.size > 0 && !!(state.assets[1]?.done || state.assets[2]?.done)
function allSources() {
  const m = new Map()
  for (const t of [1, 2]) for (const c of state.assets[t]?.conns?.values() || []) {
    const s = m.get(c.name) || { name: c.name, tool: c.tool, tt: normType(c.tt), count: 0 }
    s.count += c.count; m.set(c.name, s)
  }
  return [...m.values()]
}
function activeItems(t) {
  const a = state.assets[t]; if (!a) return []
  if (!filterActive()) return a.items
  const key = `${filterSig()}|${a.items.length}`, hit = itemsMemo.get(t)
  if (hit?.key === key) return hit.items
  const items = a.items.filter((x) => !srcFilter.off.has(x.c))
  itemsMemo.set(t, { key, items })
  return items
}
function filteredView(t) {
  const a = state.assets[t], key = `${filterSig()}|${a.items.length}`, hit = fvMemo.get(t)
  if (hit?.key === key) return hit.v
  const tools = new Set(), dbs = new Set(), schemas = new Set(), conns = new Map(), combos = new Map(), oc = new Map(), orphans = []
  const orph = { linkCounted: 0, orphanTotal: 0, sources: 0, endpoints: 0, flagged: 0, combos: [] }
  const items = activeItems(t)
  for (const x of items) {
    if (x.tool) tools.add(x.tool)
    if (x.d) dbs.add(x.d)
    if (x.d || x.s) schemas.add(`${x.d}.${x.s}`)
    const c = conns.get(x.c) || { name: x.c, tool: x.tool, tt: x.tt, count: 0 }
    c.count++; conns.set(x.c, c)
    const ck = [x.tool, x.tt, x.ot, x.ct].join('\u0001')
    const cb = combos.get(ck) || { tool: x.tool, toolType: x.tt, objectType: x.ot, container: x.ct, count: 0 }
    cb.count++; combos.set(ck, cb)
    if (x.ins != null && x.outs != null) {
      orph.linkCounted++
      if (x.ins === 0 && x.outs === 0) {
        orph.orphanTotal++; if (orphans.length < ORPHAN_CAP) orphans.push(x)
        const o = oc.get(ck) || { tool: x.tool, toolType: x.tt, objectType: x.ot, container: x.ct, count: 0 }
        o.count++; oc.set(ck, o)
      } else if (x.ins === 0) orph.sources++
      else if (x.outs === 0) orph.endpoints++
    }
    if (x.fo) orph.flagged++
  }
  orph.combos = [...oc.values()]
  const v = { total: items.length, tools: tools.size, dbs: dbs.size, schemas: schemas.size, conns: [...conns.values()], combos: [...combos.values()], orph, orphans }
  fvMemo.set(t, { key, v })
  return v
}
function filterNote() {
  if (!filterActive()) return ''
  const all = allSources(), on = all.filter((s) => !srcFilter.off.has(s.name)).length
  return `<p class="warnbox small">Source filter is on: showing ${on} of ${all.length} sources. <button class="linkbtn" type="button" data-clearfilter>Show all sources</button></p>`
}
const TYPE_ORDER = ['ETL', 'DB', 'REPORT']
function buildSources() {
  const all = allSources(), btn = $('#srcBtn'), panel = $('#srcPanel')
  btn.disabled = !all.length
  btn.title = all.length ? '' : 'Load assets first'
  const on = all.filter((s) => !srcFilter.off.has(s.name)).length
  btn.textContent = !all.length ? 'Sources' : on === all.length ? `Sources: all ${all.length}` : `Sources: ${on} of ${all.length}`
  btn.classList.toggle('on', on < all.length && all.length > 0)
  const groups = new Map()
  for (const s of all) { if (!groups.has(s.tt)) groups.set(s.tt, []); groups.get(s.tt).push(s) }
  const order = [...groups.keys()].sort((a, b) => ((TYPE_ORDER.indexOf(a) + 1) || 99) - ((TYPE_ORDER.indexOf(b) + 1) || 99) || a.localeCompare(b))
  panel.innerHTML = `<div class="srctop"><span class="muted small">Metadata sources</span><span><button class="linkbtn" type="button" data-srcall>Check all</button> · <button class="linkbtn" type="button" data-srcnone>Uncheck all</button></span></div>` +
    order.map((g) => {
      const list = groups.get(g).sort((a, b) => b.count - a.count), n = list.filter((s) => !srcFilter.off.has(s.name)).length
      return `<div class="srcgroup"><label class="check srchead"><input type="checkbox" data-srcgroup="${esc(g)}"${n === list.length ? ' checked' : ''}${n && n < list.length ? ' data-mixed="1"' : ''}> <b>${esc(g)}</b><span class="muted small">${n} / ${list.length}</span></label>` +
        list.map((s) => `<label class="check srcrow2"><input type="checkbox" data-src="${esc(s.name)}"${srcFilter.off.has(s.name) ? '' : ' checked'}> <span class="nm">${esc(s.name || '(unnamed)')}</span><span class="badge">${esc(s.tool)}</span><span class="ct muted small">${s.count.toLocaleString()}</span></label>`).join('') + '</div>'
    }).join('')
  panel.querySelectorAll('[data-mixed]').forEach((el) => { el.indeterminate = true })
}
function onFilterChange() {
  saveFilter(); fvMemo.clear(); itemsMemo.clear(); healthMemo.clear(); xMemo.clear(); statsMemo.clear()
  buildSources(); renderOverview()
  if (state.tab === 'health') renderHealth()
  if (state.tab === 'explorer') renderExplorer()
  if (!$('#lineagePrompt').hidden) showPrompt()
}
$('#srcBtn').addEventListener('click', (e) => {
  e.stopPropagation()
  const p = $('#srcPanel'); p.hidden = !p.hidden
  if (!p.hidden) p.classList.toggle('left', $('#srcBtn').getBoundingClientRect().right < Math.min(440, window.innerWidth - 16))
})
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-clearfilter]')) { srcFilter.off.clear(); onFilterChange(); return }
  if (!$('#srcPanel').hidden && !e.target.closest('.srcpick')) $('#srcPanel').hidden = true
})
$('#srcPanel').addEventListener('click', (e) => {
  if (e.target.closest('[data-srcall]')) { srcFilter.off.clear(); onFilterChange() }
  else if (e.target.closest('[data-srcnone]')) { for (const s of allSources()) srcFilter.off.add(s.name); onFilterChange() }
})
$('#srcPanel').addEventListener('change', (e) => {
  const el = e.target
  if (el.dataset.src !== undefined) { el.checked ? srcFilter.off.delete(el.dataset.src) : srcFilter.off.add(el.dataset.src) }
  else if (el.dataset.srcgroup !== undefined) { for (const s of allSources()) if (s.tt === el.dataset.srcgroup) el.checked ? srcFilter.off.delete(s.name) : srcFilter.off.add(s.name) }
  else return
  onFilterChange()
})

// ---------- Catalog Health: schemas, cleanup candidates, same name in several schemas, report coverage ----------
const healthMemo = new Map()
const healthUi = { schemas: 15, cleanup: 25, rule: '', dupes: 25, cov: 25 }
const coverage = { data: {}, loading: {} }
const schemaOf = (x) => [x.d, x.s].filter(Boolean).join('.') || '(no schema)'
const catOf = (x) => classify({ tool: x.tool, toolType: x.tt, objectType: x.ot, container: x.ct })
const isOrphan = (x) => x.ins === 0 && x.outs === 0
const hasLinks = (x) => x.ins != null && x.outs != null
const pctTxt = (n, d) => (d ? `${(n / d * 100).toFixed(1)}%` : '–')
function csvDownload(head, rows, name) {
  downloadBlob(new Blob(['﻿' + [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }), `${name}-${state.tenant}-${new Date().toISOString().slice(0, 10)}.csv`)
}
// One entry per object (table, view, package...). Column-level assets are rolled up to their table.
function objectsFor(t) {
  const items = activeItems(t), key = `obj|${t}|${filterSig()}|${items.length}`
  if (healthMemo.has(key)) return healthMemo.get(key)
  let out
  if (t === 1) {
    out = items.map((x) => {
      const name = x.n || x.tb
      return { name, path: [x.d, x.s, x.tb && x.tb !== name ? x.tb : '', name].filter(Boolean).join('.'), schema: schemaOf(x), type: x.ot || x.ct, conn: x.c, tool: x.tool, cat: catOf(x), cols: 1, linked: hasLinks(x) ? 1 : 0, orphans: isOrphan(x) ? 1 : 0, keys: [x.k] }
    })
  } else {
    const m = new Map()
    for (const x of items) {
      if (!x.tb) continue
      const k = `${x.c}\u0001${x.d}\u0001${x.s}\u0001${x.tb}`
      let o = m.get(k)
      if (!o) { o = { name: x.tb, path: [x.d, x.s, x.tb].filter(Boolean).join('.'), schema: schemaOf(x), type: x.ct || 'TABLE', conn: x.c, tool: x.tool, cat: catOf(x), cols: 0, linked: 0, orphans: 0, keys: [] }; m.set(k, o) }
      o.cols++; if (hasLinks(x)) o.linked++; if (isOrphan(x)) o.orphans++; o.keys.push(x.k)
    }
    out = [...m.values()]
  }
  for (const o of out) { const r = CLEANUP_RULES.find((rule) => rule.test.test(o.name)); o.rule = r?.id || '' }
  healthMemo.set(key, out)
  return out
}
const lineageTxt = (o) => (!o.linked ? 'unknown' : o.orphans === o.cols ? 'no links' : 'has links')

function waitMsg(t) {
  const a = state.assets[t]
  if (a?.running) return `<p class="muted small">Still loading ${TYPE_NAME[t]} assets (${a.total.toLocaleString()} so far)…</p>`
  if (a?.error) return `<p class="error small">Could not load ${TYPE_NAME[t]} assets from Octopai: ${esc(a.error)}</p><p class="muted small">Click <b>Reload assets and events</b> to try again${state.assets[t === 1 ? 2 : 1]?.done ? `, or switch to ${TYPE_NAME[t === 1 ? 2 : 1]} at the top right` : ''}.</p>`
  return '<p class="muted small">Waiting for assets. Use Reload assets and events if nothing is loading.</p>'
}
function renderHealth() {
  if (state.tab !== 'health') return
  const t = selType(), a = state.assets[t]
  if (!a?.done) { for (const id of ['#hSchemas', '#hCleanup', '#hDupes', '#hCov']) $(id).innerHTML = waitMsg(t); $('#hNote').innerHTML = ''; return }
  $('#hNote').innerHTML = filterNote() + `<p class="muted small">Checking ${TYPE_NAME[t]} assets${t === 2 ? ', rolled up to their tables' : ''}. Switch the asset type at the top right.</p>`
  renderSchemas(t); renderCleanup(t); renderDupes(t); renderCoverage(t)
}

// #3 Breakdown by schema
function schemaRows(t) {
  const m = new Map()
  for (const x of activeItems(t)) {
    const s = schemaOf(x)
    const r = m.get(s) || { schema: s, assets: 0, linked: 0, orphans: 0, cleanup: 0, tools: new Set(), conns: new Set() }
    r.assets++; if (hasLinks(x)) r.linked++; if (isOrphan(x)) r.orphans++
    if (x.tool) r.tools.add(x.tool); if (x.c) r.conns.add(x.c)
    m.set(s, r)
  }
  for (const o of objectsFor(t)) if (o.rule) { const r = m.get(o.schema); if (r) r.cleanup++ }
  return [...m.values()].sort((a, b) => b.assets - a.assets)
}
function renderSchemas(t) {
  const rows = schemaRows(t), el = $('#hSchemas')
  if (!rows.length) { el.innerHTML = '<p class="muted small">No assets for the selected sources.</p>'; return }
  const max = rows[0].assets, total = rows.reduce((s, r) => s + r.assets, 0)
  const worst = rows.filter((r) => r.linked >= 20).sort((a, b) => b.orphans / b.linked - a.orphans / a.linked)[0]
  let html = `<div class="pairs"><span><b>${rows.length.toLocaleString()}</b> schemas</span><span><b>${total.toLocaleString()}</b> assets</span>${worst && worst.orphans ? `<span>Highest orphan rate: <b>${esc(worst.schema)}</b> (${pctTxt(worst.orphans, worst.linked)})</span>` : ''}</div>`
  html += `<div class="scroll"><table class="ev htable"><tr><th>Schema</th><th class="rt">Assets</th><th></th><th class="rt">Orphans</th><th class="rt">Cleanup candidates</th><th>Tools</th></tr>` +
    rows.slice(0, healthUi.schemas).map((r) => `<tr><td title="${esc(r.schema)}">${esc(r.schema)}</td><td class="rt">${r.assets.toLocaleString()}</td><td class="barcell"><i style="width:${Math.max(1, Math.round(r.assets / max * 100))}%"></i></td><td class="rt${r.orphans ? ' bad' : ''}">${r.linked ? `${r.orphans.toLocaleString()} <span class="muted">(${pctTxt(r.orphans, r.linked)})</span>` : '<span class="muted">n/a</span>'}</td><td class="rt${r.cleanup ? ' warn' : ''}">${r.cleanup.toLocaleString()}</td><td title="${esc([...r.tools].join(', '))}">${esc([...r.tools].join(', '))}</td></tr>`).join('') + '</table></div>'
  html += `<div class="muted small">Showing ${Math.min(healthUi.schemas, rows.length)} of ${rows.length}. ${rows.length > healthUi.schemas ? '<button class="linkbtn" type="button" data-more="schemas">Show all</button> ' : ''}<button class="linkbtn" type="button" data-csv="schemas">Download schemas as CSV</button></div>`
  el.innerHTML = html
}

// #4 Cleanup candidates
function renderCleanup(t) {
  const el = $('#hCleanup'), objs = objectsFor(t).filter((o) => o.rule)
  if (!objs.length) { el.innerHTML = '<div class="verdict fine">No recycle-bin, backup, test or dated objects found.</div><p class="muted small">The rules are in <code>health-rules.js</code>.</p>'; return }
  const byRule = new Map(CLEANUP_RULES.map((r) => [r.id, 0])); for (const o of objs) byRule.set(o.rule, byRule.get(o.rule) + 1)
  const noLinks = objs.filter((o) => lineageTxt(o) === 'no links').length
  const unit = t === 2 ? 'tables' : 'objects'
  let html = `<div class="verdict"><b>${objs.length.toLocaleString()}</b> ${unit} look like cleanup candidates.${noLinks ? ` <b>${noLinks.toLocaleString()}</b> of them have no lineage links, so start with those.` : ''}</div>`
  html += `<div class="chips">${CLEANUP_RULES.filter((r) => byRule.get(r.id)).map((r) => `<button type="button" class="chip${healthUi.rule === r.id ? ' on' : ''}" data-rule="${r.id}" title="${esc(r.help)}">${esc(r.name)} (${byRule.get(r.id).toLocaleString()})</button>`).join('')}</div>`
  const list = objs.filter((o) => !healthUi.rule || o.rule === healthUi.rule).sort((a, b) => (lineageTxt(a) === 'no links' ? 0 : 1) - (lineageTxt(b) === 'no links' ? 0 : 1) || a.path.localeCompare(b.path))
  const ruleName = (id) => CLEANUP_RULES.find((r) => r.id === id)?.name || id
  if (healthUi.rule) html += `<p class="muted small">${esc(CLEANUP_RULES.find((r) => r.id === healthUi.rule)?.help || '')}</p>`
  html += `<div class="scroll"><table class="ev htable"><tr><th>Object</th><th>Reason</th><th>Type</th><th>Connection</th><th>Lineage</th></tr>` +
    list.slice(0, healthUi.cleanup).map((o) => `<tr><td title="${esc(o.path)}">${esc(o.path)}</td><td>${esc(ruleName(o.rule))}</td><td>${esc(o.type)}</td><td>${esc(o.conn)}</td><td class="${lineageTxt(o) === 'no links' ? 'good' : lineageTxt(o) === 'has links' ? 'warn' : 'muted'}">${lineageTxt(o)}</td></tr>`).join('') + '</table></div>'
  html += `<div class="muted small">Showing ${Math.min(healthUi.cleanup, list.length).toLocaleString()} of ${list.length.toLocaleString()}. "Has links" means something still reads from or writes to it, so check before dropping. ${list.length > healthUi.cleanup ? '<button class="linkbtn" type="button" data-more="cleanup">Show 50 more</button> ' : ''}<button class="linkbtn" type="button" data-csv="cleanup">Download cleanup candidates as CSV</button></div>`
  el.innerHTML = html
}

// #5 Same name in several schemas
function dupeGroups(t) {
  const key = `dupes|${t}|${filterSig()}|${activeItems(t).length}`
  if (healthMemo.has(key)) return healthMemo.get(key)
  const m = new Map()
  for (const o of objectsFor(t)) {
    if (!o.name || o.name.length < SAME_NAME_MIN_LENGTH || o.rule === 'recycle' || SAME_NAME_IGNORE_TYPES.test(o.type || '')) continue
    const k = o.name.toUpperCase()
    if (!m.has(k)) m.set(k, new Map())
    const bySchema = m.get(k)
    if (!bySchema.has(o.schema)) bySchema.set(o.schema, o)
  }
  const out = [...m].filter(([, s]) => s.size > 1).map(([name, s]) => ({ name, objs: [...s.values()], types: [...new Set([...s.values()].map((o) => o.type).filter(Boolean))] }))
    .sort((a, b) => b.objs.length - a.objs.length || a.name.localeCompare(b.name))
  healthMemo.set(key, out)
  return out
}
function renderDupes(t) {
  const el = $('#hDupes'), groups = dupeGroups(t)
  if (!groups.length) { el.innerHTML = '<div class="verdict fine">No object name appears in more than one schema.</div>'; return }
  const copies = groups.reduce((s, g) => s + g.objs.length, 0)
  let html = `<div class="verdict"><b>${groups.length.toLocaleString()}</b> ${groups.length === 1 ? 'name appears' : 'names appear'} in more than one schema (${copies.toLocaleString()} copies in all). Copies can drift apart, so check that each one is still needed and still the same.</div>`
  html += `<div class="scroll"><table class="ev htable"><tr><th>Name</th><th>Type</th><th class="rt">Schemas</th><th>Where</th></tr>` +
    groups.slice(0, healthUi.dupes).map((g) => `<tr><td title="${esc(g.name)}">${esc(g.name)}</td><td>${esc(g.types.join(', '))}</td><td class="rt">${g.objs.length}</td><td title="${esc(g.objs.map((o) => o.schema).join(', '))}">${esc(g.objs.map((o) => o.schema).join(', '))}</td></tr>`).join('') + '</table></div>'
  html += `<div class="muted small">Showing ${Math.min(healthUi.dupes, groups.length).toLocaleString()} of ${groups.length.toLocaleString()}. ${groups.length > healthUi.dupes ? '<button class="linkbtn" type="button" data-more="dupes">Show 50 more</button> ' : ''}<button class="linkbtn" type="button" data-csv="dupes">Download as CSV</button></div>`
  el.innerHTML = html
}

// #6 Report coverage: which DB objects feed at least one report, based on downloaded downstream lineage.
async function loadCoverage(t) {
  if (coverage.data[t] || coverage.loading[t]) return
  coverage.loading[t] = true
  try {
    const r = await fetch(`/local/${state.tenant}/coverage?type=${t}`)
    coverage.data[t] = r.ok ? await r.json() : { count: 0, keys: {}, error: `Local read failed (${r.status})` }
  } catch (err) { coverage.data[t] = { count: 0, keys: {}, error: err.message } }
  coverage.loading[t] = false
  healthMemo.clear(); renderHealth(); renderStats()
}
const feedsReport = (combos) => combos.some((c) => { const [tool, type] = c.split('\u0001'); return classify({ tool, toolType: type }) === 'reports' })
function coverageRows(t) {
  const cov = coverage.data[t]
  const key = `cov|${t}|${filterSig()}|${activeItems(t).length}|${cov?.count}`
  if (healthMemo.has(key)) return healthMemo.get(key)
  const rows = objectsFor(t).filter((o) => o.cat === 'db').map((o) => {
    let seen = 0, feeds = 0, trunc = 0
    for (const k of o.keys) { const c = cov.keys[k]; if (!c) continue; seen++; if (c.tr) trunc++; if (feedsReport(c.c)) feeds++ }
    return { ...o, status: !seen ? 'no lineage' : feeds ? 'feeds a report' : 'no report', trunc }
  })
  healthMemo.set(key, rows)
  return rows
}
function renderCoverage(t) {
  const el = $('#hCov'), cov = coverage.data[t]
  if (!cov) { el.innerHTML = '<p class="muted small">Reading saved lineage…</p>'; loadCoverage(t); return }
  if (cov.error) { el.innerHTML = `<p class="error small">${esc(cov.error)}</p>`; return }
  const reports = activeItems(t).filter((x) => catOf(x) === 'reports').length
  const rows = coverageRows(t), withL = rows.filter((r) => r.status !== 'no lineage'), feeds = withL.filter((r) => r.status === 'feeds a report')
  const unit = t === 2 ? 'DB tables' : 'DB objects'
  let html = `<div class="pairs"><span><b>${reports.toLocaleString()}</b> report asset${reports === 1 ? '' : 's'} in the catalog</span><span><b>${rows.length.toLocaleString()}</b> ${unit}</span><span><b>${withL.length.toLocaleString()}</b> with downloaded downstream lineage</span></div>`
  if (!withL.length) {
    el.innerHTML = html + `<p class="muted small">No downstream lineage is saved for these ${unit} yet. Open <b>Lineage Download</b>, choose ${TYPE_NAME[t]} assets and the Downstream direction, then come back here.</p>`
    return
  }
  html = `<div class="verdict${feeds.length === withL.length ? ' fine' : ''}"><b>${pctTxt(feeds.length, withL.length)}</b> of ${unit} with downstream lineage feed at least one report (${feeds.length.toLocaleString()} of ${withL.length.toLocaleString()}). <b>${(withL.length - feeds.length).toLocaleString()}</b> feed no report.</div>` + html
  if (withL.length < rows.length) html += `<p class="muted small">${(rows.length - withL.length).toLocaleString()} ${unit} have no downloaded downstream lineage, so they are not counted. Download more lineage to include them.</p>`
  const truncN = withL.filter((r) => r.trunc).length
  if (truncN) html += `<p class="muted small">${truncN.toLocaleString()} graphs hit the node limit, so a few "no report" results may be wrong.</p>`
  const bySchema = new Map()
  for (const r of withL) { const s = bySchema.get(r.schema) || { schema: r.schema, n: 0, feeds: 0 }; s.n++; if (r.status === 'feeds a report') s.feeds++; bySchema.set(r.schema, s) }
  const sch = [...bySchema.values()].sort((a, b) => b.n - a.n).slice(0, 12)
  html += `<h4>Report coverage by schema</h4><div class="hbars">${sch.map((s) => `<div class="hbar"><span title="${esc(s.schema)}">${esc(s.schema)}</span><span class="tr"><i style="width:${s.feeds / s.n * 100}%;--c:var(--c-reports)"></i></span><span class="v">${s.feeds.toLocaleString()} of ${s.n.toLocaleString()} · ${pctTxt(s.feeds, s.n)}</span></div>`).join('')}</div>`
  const none = withL.filter((r) => r.status === 'no report').sort((a, b) => a.path.localeCompare(b.path))
  if (none.length) {
    html += `<h4>${unit} that feed no report</h4><div class="scroll"><table class="ev htable"><tr><th>Object</th><th>Type</th><th>Connection</th></tr>` +
      none.slice(0, healthUi.cov).map((r) => `<tr><td title="${esc(r.path)}">${esc(r.path)}</td><td>${esc(r.type)}</td><td>${esc(r.conn)}</td></tr>`).join('') + '</table></div>'
    html += `<div class="muted small">Showing ${Math.min(healthUi.cov, none.length).toLocaleString()} of ${none.length.toLocaleString()}. ${none.length > healthUi.cov ? '<button class="linkbtn" type="button" data-more="cov">Show 50 more</button> ' : ''}</div>`
  }
  html += '<div class="muted small"><button class="linkbtn" type="button" data-csv="cov">Download report coverage as CSV</button> · <button class="linkbtn" type="button" data-covreload>Re-read saved lineage</button></div>'
  el.innerHTML = html
}

$('#healthPanel').addEventListener('click', (e) => {
  const t = selType(), b = e.target.closest('button'); if (!b) return
  if (b.dataset.more) { healthUi[b.dataset.more] = b.dataset.more === 'schemas' ? 1e9 : healthUi[b.dataset.more] + 50; renderHealth(); return }
  if (b.dataset.rule !== undefined) { healthUi.rule = healthUi.rule === b.dataset.rule ? '' : b.dataset.rule; healthUi.cleanup = 25; renderHealth(); return }
  if (b.dataset.covreload !== undefined) { delete coverage.data[t]; renderHealth(); return }
  const kind = b.dataset.csv; if (!kind) return
  if (kind === 'schemas') csvDownload(['schema', 'assets', 'assets_with_link_counts', 'orphans', 'cleanup_candidates', 'connections', 'tools'], schemaRows(t).map((r) => [r.schema, r.assets, r.linked, r.orphans, r.cleanup, [...r.conns].join('; '), [...r.tools].join('; ')]), `schemas-${TYPE_NAME[t]}`)
  if (kind === 'cleanup') csvDownload(['object', 'name', 'schema', 'reason', 'type', 'connection', 'tool', 'lineage', 'columns'], objectsFor(t).filter((o) => o.rule).map((o) => [o.path, o.name, o.schema, CLEANUP_RULES.find((r) => r.id === o.rule)?.name, o.type, o.conn, o.tool, lineageTxt(o), o.cols]), `cleanup-candidates-${TYPE_NAME[t]}`)
  if (kind === 'dupes') csvDownload(['name', 'schema_count', 'schema', 'object', 'type', 'connection', 'lineage'], dupeGroups(t).flatMap((g) => g.objs.map((o) => [g.name, g.objs.length, o.schema, o.path, o.type, o.conn, lineageTxt(o)])), `same-name-${TYPE_NAME[t]}`)
  if (kind === 'cov') csvDownload(['object', 'schema', 'type', 'connection', 'tool', 'report_coverage', 'possibly_incomplete'], coverageRows(t).map((r) => [r.path, r.schema, r.type, r.conn, r.tool, r.status, r.trunc ? 'yes' : '']), `report-coverage-${TYPE_NAME[t]}`)
})

// ---------- Lineage Explorer: three columns like Octopai's dashboard, plus impact analysis for one asset ----------
const XCOLS = [
  { id: 'src', name: 'ETLs, Stored Procedures & SQL Files', cats: ['etl', 'sp'], color: 'sp' },
  { id: 'db', name: 'DB Objects, Files & Analysis Services', cats: ['db', 'files', 'other'], color: 'db' },
  { id: 'rep', name: 'Reports, Analytics & Information Consumers', cats: ['reports'], color: 'reports' },
]
const X_SHOW = 200
const xUi = { q: '', imp: null, impShow: 100 }
const xMemo = new Map()
const catName = (id) => CATEGORY_ORDER.find((c) => c.id === id)?.name || id
const nodeCat = (n) => classify({ tool: n.tool, toolType: n.type })
function xEntries(t) {
  const items = activeItems(t), key = `${filterSig()}|${items.length}`, hit = xMemo.get(t)
  if (hit?.key === key) return hit.v
  const list = items.map((x) => {
    const cat = catOf(x)
    return { x, cat, col: (XCOLS.find((c) => c.cats.includes(cat)) || XCOLS[1]).id, name: t === 1 ? (x.n || x.tb || x.l) : [x.tb, x.n].filter(Boolean).join('.') || x.l, sub: schemaOf(x) }
  })
  for (const e of list) e.lower = `${e.name} ${e.sub} ${e.x.c} ${e.x.tool}`.toLowerCase()
  list.sort((a, b) => a.name.localeCompare(b.name))
  const v = { list, byKey: new Map(list.map((e) => [e.x.k, e])) }
  xMemo.set(t, { key, v })
  return v
}

function renderExplorer() {
  if (state.tab !== 'explorer') return
  const t = selType(), a = state.assets[t]
  if (!a?.done) { $('#xCols').innerHTML = waitMsg(t); $('#xNote').innerHTML = ''; renderImpact(); return }
  if (xUi.imp && xUi.imp.t !== t) xUi.imp = null
  const { list } = xEntries(t)
  const terms = xUi.q.toLowerCase().split(/\s+/).filter(Boolean)
  const hits = terms.length ? list.filter((e) => terms.every((w) => e.lower.includes(w))) : list
  $('#xNote').innerHTML = filterNote() + `<p class="muted small">${terms.length ? `${hits.length.toLocaleString()} of ${list.length.toLocaleString()}` : list.length.toLocaleString()} ${TYPE_NAME[t]} assets${t === 2 ? ' (columns)' : ''}. Switch the asset type at the top right.</p>`
  const selK = xUi.imp?.it.k
  $('#xCols').innerHTML = XCOLS.map((c) => {
    const arr = hits.filter((e) => e.col === c.id)
    return `<div class="xcol" style="--c:var(--c-${c.color})"><div class="xhead"><span>${esc(c.name)}</span><span class="ct">${arr.length.toLocaleString()}</span></div><div class="xlist">` +
      (arr.length ? arr.slice(0, X_SHOW).map((e) => `<button type="button" class="xitem${e.x.k === selK ? ' on' : ''}" data-xk="${esc(e.x.k)}" title="${esc(e.x.l)}"><span class="xn">${esc(e.name)}</span><span class="xs">${esc(e.sub)}${c.id === 'db' && (e.x.ot || e.x.ct) ? `<span class="badge">${esc(e.x.ot || e.x.ct)}</span>` : ''}</span></button>`).join('') : '<p class="muted small xempty">Nothing here.</p>') +
      `</div>${arr.length > X_SHOW ? `<div class="muted small xmore">Showing ${X_SHOW} of ${arr.length.toLocaleString()}. Search to narrow it down.</div>` : ''}</div>`
  }).join('')
  renderImpact()
}
let xTimer = 0
$('#xSearch').addEventListener('input', (e) => { clearTimeout(xTimer); xTimer = setTimeout(() => { xUi.q = e.target.value; renderExplorer() }, 150) })
$('#xCols').addEventListener('click', (e) => { const b = e.target.closest('[data-xk]'); if (b) selectAsset(b.dataset.xk) })

function selectAsset(k, scroll = true) {
  const t = selType(), e = xEntries(t).byKey.get(k); if (!e) return
  xUi.impShow = 100
  loadImpact(t, e.x, false)
  document.querySelectorAll('#xCols .xitem').forEach((b) => b.classList.toggle('on', b.dataset.xk === k))
  if (scroll) $('#xImpact').scrollIntoView({ behavior: 'smooth', block: 'start' })
}

// Reads saved lineage for the asset (lineage downloads, and the keyword-scan cache for columns). Anything missing is
// fetched live from Octopai and appended to data/exports/<site>/explorer-<date>.ndjson so it is saved for next time.
async function loadImpact(t, it, force) {
  const imp = xUi.imp = { t, it, up: null, down: null, source: {}, status: 'loading', error: '' }
  renderImpact()
  try {
    if (!force) for (const d of [1, 2]) {
      const { found } = await jpost(`/local/${state.tenant}/lineage`, { type: t, direction: d, keys: [it.k] })
      const g = found[it.k]
      if (g) { imp[d === 1 ? 'up' : 'down'] = { nodes: g.nodes || [], truncated: !!g.truncated }; imp.source[d] = g.source === 'saved scan' ? 'saved keyword scan' : 'saved lineage' }
    }
    const lines = []
    for (const d of [1, 2]) {
      const side = d === 1 ? 'up' : 'down'
      if (imp[side]) continue
      if (!state.token) throw new Error('Not connected to Octopai, and no saved lineage was found for this asset.')
      imp.status = 'fetching'; if (xUi.imp === imp) renderImpact()
      const r = await lineageRaw(it.k, t, d)
      imp[side] = { nodes: r.nodes, truncated: r.truncated }; imp.source[d] = 'live from Octopai'
      lines.push(JSON.stringify({ t, key: it.k, label: it.l, dir: DIR_NAME[d], truncated: r.truncated, nodes: r.nodes, edges: r.edges }))
    }
    if (lines.length) {
      try { await fetch(`/export/${state.tenant}/explorer-${new Date().toISOString().slice(0, 10)}`, { method: 'POST', body: lines.join('\n') + '\n' }) } catch { /* saving is best effort */ }
      coverage.data = {}; refreshLocalStatus()
    }
    imp.status = 'done'
  } catch (err) { imp.status = 'error'; imp.error = err.message }
  if (xUi.imp === imp) renderImpact()
}

function laneHtml(nodes, byKey) {
  if (!nodes.length) return '<p class="muted small">None found.</p>'
  const groups = new Map()
  for (const n of nodes) { const c = nodeCat(n); if (!groups.has(c)) groups.set(c, []); groups.get(c).push(n) }
  return CATEGORY_ORDER.filter((c) => groups.has(c.id)).map((c) => {
    const list = groups.get(c.id).sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name))
    return `<div class="lgroup" style="--c:var(--c-${c.id})"><div class="lgh"><span>${esc(c.name)}</span><b>${list.length.toLocaleString()}</b></div>` +
      list.slice(0, 8).map((n) => { const go = byKey.has(n.key); return `<div class="lnode${go ? ' go' : ''}"${go ? ` data-xk="${esc(n.key)}" role="button" tabindex="0"` : ''} title="${esc([n.connection, n.db, n.schema, n.table, n.name].filter(Boolean).join(' › '))}"><span>${esc(n.name || n.table || n.key)}</span><span class="muted small">hop ${n.depth}</span></div>` }).join('') +
      (list.length > 8 ? `<div class="muted small">+${(list.length - 8).toLocaleString()} more in the table below</div>` : '') + '</div>'
  }).join('')
}
const countPhrase = (nodes) => {
  const m = new Map(); for (const n of nodes) { const c = nodeCat(n); m.set(c, (m.get(c) || 0) + 1) }
  const short = { etl: ['ETL', 'ETLs'], sp: ['stored procedure or SQL file', 'stored procedures or SQL files'], db: ['DB object', 'DB objects'], files: ['file or analysis service', 'files or analysis services'], reports: ['report', 'reports'], other: ['unclassified asset', 'unclassified assets'] }
  return CATEGORY_ORDER.filter((c) => m.has(c.id)).map((c) => { const n = m.get(c.id); return `${n.toLocaleString()} ${short[c.id][n === 1 ? 0 : 1]}` }).join(', ')
}
function impactRows(imp) {
  return [...imp.up.nodes.map((n) => ['Upstream', n]), ...imp.down.nodes.map((n) => ['Downstream', n])]
    .sort((a, b) => a[0].localeCompare(b[0]) * -1 || a[1].depth - b[1].depth || String(a[1].name).localeCompare(String(b[1].name)))
}
function renderImpact() {
  const el = $('#xImpact'), imp = xUi.imp
  if (!imp) { el.innerHTML = '<h2>Impact analysis</h2><p class="muted">Click any asset above to see what it depends on (upstream) and what would be affected if it changed (downstream), including which reports.</p>'; return }
  const t = imp.t, e = xEntries(t).byKey.get(imp.it.k), byKey = xEntries(t).byKey
  const name = e?.name || imp.it.l
  let html = `<div class="ovhead"><h2>Impact analysis</h2><span class="noprint">${imp.status === 'done' ? '<button class="linkbtn" type="button" data-ximp="csv">Download CSV</button> · ' : ''}<button class="linkbtn" type="button" data-ximp="refresh"${['loading', 'fetching'].includes(imp.status) ? ' disabled' : ''}>Refresh from Octopai</button></span></div>`
  html += `<div class="xsel" style="--c:var(--c-${e?.cat || 'other'})"><b>${esc(name)}</b><span class="muted small">${esc(imp.it.l)}</span><span class="badge">${esc(imp.it.tool)}</span><span class="badge">${esc(catName(e?.cat || 'other'))}</span></div>`
  if (imp.status === 'loading') { el.innerHTML = html + '<p class="muted small">Reading saved lineage…</p>'; return }
  if (imp.status === 'fetching') { el.innerHTML = html + '<p class="muted small">Fetching lineage from Octopai… It is saved on this computer for next time.</p>'; return }
  if (imp.status === 'error') { el.innerHTML = html + `<p class="error small">${esc(imp.error)}</p>`; return }
  const up = imp.up.nodes, down = imp.down.nodes
  const reports = down.filter((n) => nodeCat(n) === 'reports').length
  html += `<div class="verdict${down.length ? '' : ' fine'}">` + (down.length
    ? `Changing <b>${esc(name)}</b> could affect <b>${down.length.toLocaleString()}</b> downstream asset${down.length === 1 ? '' : 's'}${reports ? `, including <b>${reports.toLocaleString()} report${reports === 1 ? '' : 's'}</b>` : ''}${new Set(down.map(nodeCat)).size > 1 ? `: ${esc(countPhrase(down))}` : ''}.`
    : `Nothing downstream uses <b>${esc(name)}</b>.`) +
    ` ${up.length ? `It gets data from <b>${up.length.toLocaleString()}</b> upstream asset${up.length === 1 ? '' : 's'}.` : 'It has no upstream sources.'}</div>`
  html += `<div class="lanes"><div class="lane"><h4>Upstream (sources)</h4>${laneHtml(up, byKey)}</div><div class="lane mid"><div class="xnode" style="--c:var(--c-${e?.cat || 'other'})">${esc(name)}</div></div><div class="lane"><h4>Downstream (consumers)</h4>${laneHtml(down, byKey)}</div></div>`
  const rows = impactRows(imp)
  if (rows.length) {
    html += `<h4>All related assets</h4><div class="scroll"><table class="ev htable"><tr><th>Direction</th><th class="rt">Hop</th><th>Name</th><th>Category</th><th>Location</th><th>Tool</th></tr>` +
      rows.slice(0, xUi.impShow).map(([dir, n]) => `<tr><td>${dir}</td><td class="rt">${n.depth}</td><td title="${esc(n.name)}">${byKey.has(n.key) ? `<button type="button" class="linkbtn tlink" data-xk="${esc(n.key)}">${esc(n.name)}</button>` : esc(n.name)}</td><td>${esc(catName(nodeCat(n)))}</td><td title="${esc([n.connection, n.db, n.schema, n.table].filter(Boolean).join(' › '))}">${esc([n.connection, n.db, n.schema, n.table].filter(Boolean).join(' › '))}</td><td>${esc(n.tool)}</td></tr>`).join('') + '</table></div>'
    html += `<div class="muted small">Showing ${Math.min(xUi.impShow, rows.length).toLocaleString()} of ${rows.length.toLocaleString()}. ${rows.length > xUi.impShow ? '<button class="linkbtn" type="button" data-ximp="more">Show 100 more</button>' : ''}</div>`
  }
  const notes = [`Upstream: ${imp.source[1]}`, `downstream: ${imp.source[2]}`, `up to ${DEPTH} hops`]
  if (imp.up.truncated || imp.down.truncated) notes.push('a graph hit the node limit, so the lists may be incomplete')
  html += `<p class="muted small">${esc(notes.join(' · '))}. Names you can click are in the current asset list and open their own impact analysis.</p>`
  el.innerHTML = html
}
$('#xImpact').addEventListener('click', (e) => {
  const go = e.target.closest('[data-xk]'); if (go) { selectAsset(go.dataset.xk); return }
  const b = e.target.closest('[data-ximp]'); if (!b || !xUi.imp) return
  const imp = xUi.imp
  if (b.dataset.ximp === 'refresh') loadImpact(imp.t, imp.it, true)
  if (b.dataset.ximp === 'more') { xUi.impShow += 100; renderImpact() }
  if (b.dataset.ximp === 'csv') {
    const name = xEntries(imp.t).byKey.get(imp.it.k)?.name || imp.it.l
    csvDownload(['selected_asset', 'selected_path', 'direction', 'hop', 'related_name', 'category', 'connection', 'db', 'schema', 'table', 'tool', 'tool_type', 'related_key'],
      impactRows(imp).map(([dir, n]) => [name, imp.it.l, dir, n.depth, n.name, catName(nodeCat(n)), n.connection, n.db, n.schema, n.table, n.tool, n.type, n.key]),
      `impact-${String(name).replace(/[^\w-]+/g, '_').slice(0, 40)}`)
  }
})
$('#xImpact').addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.matches('.lnode.go')) selectAsset(e.target.dataset.xk) })

// ---------- Overview stat cards ----------
// Degree = lineage links in + links out, from the link counts Octopai returns with each asset (all assets, not a sample).
const HIGH_IMPACT_DEGREE = 4
const statsMemo = new Map()
function linkStats(t) {
  const items = activeItems(t), key = `${filterSig()}|${items.length}`, hit = statsMemo.get(t)
  if (hit?.key === key) return hit.v
  let counted = 0, linked = 0, orphans = 0, high = 0, top = null
  for (const x of items) {
    if (x.ins == null || x.outs == null) continue
    counted++
    const d = x.ins + x.outs
    if (d > 0) linked++; else orphans++
    if (d >= HIGH_IMPACT_DEGREE) high++
    if (!top || d > top.ins + top.outs) top = x
  }
  const v = { counted, linked, orphans, high, top, total: items.length }
  statsMemo.set(t, { key, v })
  return v
}
function depthStats(t) {
  const cov = coverage.data[t]; if (!cov) return null
  const buckets = new Map(); let chains = 0, sum = 0
  for (const x of activeItems(t)) { const c = cov.keys[x.k]; if (!c) continue; const md = c.md || 0; chains++; sum += md; buckets.set(md, (buckets.get(md) || 0) + 1) }
  return { chains, avg: chains ? sum / chains : 0, buckets }
}
function renderStats() {
  const el = $('#stats'); if (!el) return
  const t = selType(), a = state.assets[t], a1 = state.assets[1]
  const card = (cls, title, value, sub, tip, extra = '') => `<div class="stat ${cls}" title="${esc(tip)}"${extra}><div class="st">${esc(title)}</div><div class="sv">${value}</div><div class="ss">${sub}</div></div>`
  const typeNote = t === 2 ? ' (column-level)' : ''
  if (!a?.done && !a1?.done) { el.innerHTML = ''; return }
  const cards = []
  if (a?.done) {
    const s = linkStats(t)
    const noCounts = !s.counted
    cards.push(card('s-impact', `High Impact Objects${typeNote}`, noCounts ? '–' : s.high.toLocaleString(), noCounts ? 'no link counts in this asset list' : `Objects with lineage in + out ≥ ${HIGH_IMPACT_DEGREE} · ${pctTxt(s.high, s.counted)} of assets`, 'Assets with at least 4 lineage links (in plus out), counted over every asset, not a sample.'))
    if (s.top && s.top.ins + s.top.outs > 0) {
      const x = s.top, name = t === 1 ? (x.n || x.tb || x.l) : [x.tb, x.n].filter(Boolean).join('.')
      cards.push(card('s-top', `Most Connected Object${typeNote}`, `<span class="sname">${esc(name)}</span>`, `${esc(x.c || x.tool)} · degree ${(x.ins + x.outs).toLocaleString()} (${x.ins.toLocaleString()} in, ${x.outs.toLocaleString()} out)`, 'The asset with the most lineage links. Click to open it in the Lineage Explorer.', ` data-statgo="${esc(x.k)}" role="button" tabindex="0"`))
    } else cards.push(card('s-top', `Most Connected Object${typeNote}`, '–', noCounts ? 'no link counts in this asset list' : 'no asset has lineage links', ''))
  } else cards.push(card('s-impact', 'High Impact Objects', '–', 'still loading…', ''), card('s-top', 'Most Connected Object', '–', 'still loading…', ''))
  if (a1?.done) {
    const by = new Map(); for (const x of activeItems(1)) { const k = normType(x.tt); by.set(k, (by.get(k) || 0) + 1) }
    const label = { ETL: 'ETL', DB: 'DB', REPORT: 'Reports' }
    const order = [...by.keys()].sort((p, q) => ((TYPE_ORDER.indexOf(p) + 1) || 99) - ((TYPE_ORDER.indexOf(q) + 1) || 99))
    cards.push(card('s-cross', 'Cross-System Objects', activeItems(1).length.toLocaleString(), order.map((k) => `${esc(label[k] || k)}: ${by.get(k).toLocaleString()}`).join(' · '), 'Cross-system assets by tool type.'))
  } else cards.push(card('s-cross', 'Cross-System Objects', '–', 'still loading…', ''))
  if (a?.done) {
    const d = depthStats(t)
    if (!d) { cards.push(card('s-depth', `Pipeline Depth${typeNote}`, '–', 'reading saved lineage…', '')); loadCoverage(t) }
    else if (!d.chains) cards.push(card('s-depth', `Pipeline Depth${typeNote}`, '–', 'Download downstream lineage (Lineage Download tab) to measure this', ''))
    else {
      const ks = [...d.buckets.keys()].sort((p, q) => p - q)
      const shown = ks.slice(0, 3).map((k) => `${k} hop${k === 1 ? '' : 's'}: ${d.buckets.get(k).toLocaleString()}`)
      const rest = ks.slice(3).reduce((s2, k) => s2 + d.buckets.get(k), 0)
      if (rest) shown.push(`${ks[3]}+ hops: ${rest.toLocaleString()}`)
      cards.push(card('s-depth', `Pipeline Depth${typeNote}`, `${d.chains.toLocaleString()} chains`, `avg ${d.avg.toFixed(1)} hops · ${shown.join(', ')}`, 'For every asset with downloaded downstream lineage: how many hops its longest downstream chain has.'))
    }
    const s = linkStats(t)
    cards.push(card('s-health', `Lineage Health${typeNote}`, s.counted ? pctTxt(s.linked, s.counted).replace('.0%', '%') : '–', s.counted ? `${s.linked.toLocaleString()} of ${s.counted.toLocaleString()} assets have lineage · ${s.orphans.toLocaleString()} orphan${s.orphans === 1 ? '' : 's'}` : 'no link counts in this asset list', 'Share of assets with at least one lineage link, counted over every asset.'))
  } else cards.push(card('s-depth', 'Pipeline Depth', '–', 'still loading…', ''), card('s-health', 'Lineage Health', '–', 'still loading…', ''))
  el.innerHTML = cards.join('')
}
$('#stats').addEventListener('click', (e) => { const c = e.target.closest('[data-statgo]'); if (!c) return; setTab('explorer'); selectAsset(c.dataset.statgo) })
$('#stats').addEventListener('keydown', (e) => { const c = e.target.closest('[data-statgo]'); if (c && e.key === 'Enter') { setTab('explorer'); selectAsset(c.dataset.statgo) } })
