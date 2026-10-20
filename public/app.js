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
const MAX_EVENT_PAGES = 400
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000
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
    try {
      res = await fetch(`/octopai${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined, signal })
    } catch (e) {
      if (e.name === 'AbortError') throw e
      why = 'Could not reach the local server or the Octopai site.'
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
    return res.json()
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
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(tenant)) { $('#loginError').textContent = 'Enter just the site name, like "iqvia" or "demo.eu".'; return }
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
window.addEventListener('beforeunload', (e) => { if (state.dl?.status === 'running') { e.preventDefault(); e.returnValue = '' } })

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

async function startLoad() {
  if (!state.token || state.loading) return
  state.loading = true
  state.loadAbort?.abort()
  const ac = state.loadAbort = new AbortController()
  state.loadStartedAt = Date.now(); state.loadFinishedAt = 0
  state.assets = { 1: newAssets(1), 2: newAssets(2) }; state.events = newEvents()
  $('#catalogBtn').disabled = true; $('#catalogBtn').textContent = 'Loading…'
  $('#lineagePrompt').hidden = true; $('#dlReopen').hidden = true
  renderOverview(); renderEvents()
  const timer = setInterval(renderOverview, 1000)
  try {
    await Promise.all([loadAssets(1, ac.signal), loadAssets(2, ac.signal), loadEvents(ac.signal)])
  } finally { clearInterval(timer) }
  if (ac.signal.aborted) { state.loading = false; return }
  state.loadFinishedAt = Date.now(); state.loading = false
  const types = {}
  for (const t of [1, 2]) { const a = state.assets[t]; if (a.done) types[t] = { total: a.total, tools: a.tools.size, dbs: a.dbs.size, schemas: a.schemas.size, conns: [...a.conns.values()], combos: [...a.combos.values()], orph: orphSummary(a) } }
  const old = state.cache.catalog
  const prev = old?.types ? { savedAt: old.savedAt, totals: { 1: old.types[1]?.total, 2: old.types[2]?.total } } : old?.prev
  state.cache.catalog = { savedAt: Date.now(), prev, types: { ...(state.cache.catalog?.types || {}), ...types }, events: state.events.done ? { total: state.events.rows.length } : state.cache.catalog?.events }
  state.cacheDirty = true; saveCache()
  saveAssetsLocal()
  $('#catalogBtn').disabled = false; $('#catalogBtn').textContent = 'Reload assets and events'
  renderOverview(); renderEvents()
  showPrompt()
}
$('#catalogBtn').addEventListener('click', startLoad)

async function loadAssets(t, signal) {
  const a = state.assets[t]
  try {
    const pg = await pageAssets({ assetType: t }, signal, (items) => {
      for (const raw of items) {
        a.total++
        const x = normalizeAsset(raw)
        if (x.tool) a.tools.add(x.tool)
        if (x.db) a.dbs.add(x.db)
        if (x.db || x.schema) a.schemas.add(`${x.db}.${x.schema}`)
        const c = a.conns.get(x.connection) || { name: x.connection, tool: x.tool, count: 0 }
        c.count++; a.conns.set(x.connection, c)
        const ck = [x.tool, x.toolType, x.objectType, x.container].join('\u0001')
        const cb = a.combos.get(ck) || { tool: x.tool, toolType: x.toolType, objectType: x.objectType, container: x.container, count: 0 }
        cb.count++; a.combos.set(ck, cb)
        const ins = numOrNull(pick(raw, 'ins', 'inCount')), outs = numOrNull(pick(raw, 'outs', 'outCount'))
        const item = { k: x.key, l: colPath(x) || String(x.key), n: x.column, c: x.connection, tool: x.tool, tt: x.toolType, ot: x.objectType, ct: x.container, ins, outs }
        if (x.key) a.items.push(item)
        if (ins !== null && outs !== null) {
          a.linkCounted++
          if (ins === 0 && outs === 0) {
            a.orphanTotal++; if (a.orphans.length < ORPHAN_CAP) a.orphans.push(item)
            const oc = a.orphanCombos.get(ck) || { tool: x.tool, toolType: x.toolType, objectType: x.objectType, container: x.container, count: 0 }
            oc.count++; a.orphanCombos.set(ck, oc)
          } else if (ins === 0) a.sources++
          else if (outs === 0) a.endpoints++
        }
        if (pick(raw, 'isSrcColumnOrphan') === true) { a.flagged++; if (a.flaggedList.length < ORPHAN_CAP) a.flaggedList.push(item) }
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
        pagesRows[p] = list
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
    if (!finished || p == null || cur == null) return ['', '']
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
  else if (cat) parts.push(`Catalog ${new Date(cat).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}`)
  const l = state.local?.lineage
  if (l && (l.up || l.down)) parts.push(`lineage saved: ${l.up.toLocaleString()} up · ${l.down.toLocaleString()} down`)
  $('#fresh2').textContent = parts.join(' · ')
}
function setTab(name) {
  state.tab = name
  document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('on', b.dataset.tab === name))
  document.querySelectorAll('.panel').forEach((p) => { p.hidden = p.dataset.panel !== name })
  $('#typeSeg').style.visibility = ['overview', 'orphans'].includes(name) ? 'visible' : 'hidden'
  try { localStorage.setItem('lineage-tab', name) } catch { /* storage unavailable */ }
}
document.querySelector('.tabs').addEventListener('click', (e) => { const b = e.target.closest('.tab'); if (b) setTab(b.dataset.tab) })
$('#dlOpen').addEventListener('click', () => { if (counts()[1] || counts()[2]) showPrompt(); else $('#dlEmpty p').textContent = 'Load the catalog first (use Reload assets and events), then choose what to download.' })
document.querySelectorAll('input[name=bdtype]').forEach((r) => r.addEventListener('change', renderKpis))
function renderOverview() {
  const n = (v) => (v ?? 0).toLocaleString()
  renderKpis()
  const loading = state.loading
  const live = state.assets[1] || state.assets[2]
  const cachedOnly = !live?.total && state.cache.catalog
  $('#catState').textContent = loading ? (cachedOnly ? `showing saved numbers from ${new Date(state.cache.catalog.savedAt).toLocaleString()}, refreshing…` : 'still fetching…')
    : state.loadFinishedAt ? `up to date · ${new Date(state.loadFinishedAt).toLocaleTimeString()}` : cachedOnly ? `saved ${new Date(state.cache.catalog.savedAt).toLocaleString()}` : ''

  const warns = []
  for (const t of [1, 2]) {
    const a = state.assets[t]
    if (a?.hitCap) warns.push(`The ${TYPE_NAME[t]} list stopped at the ${MAX_PAGES}-page safety cap, so it may be larger than shown.`)
    else if (a?.done && a.total > 0 && a.total % PAGE === 0) warns.push(`The ${TYPE_NAME[t]} total is an exact multiple of 10,000, so the API may have stopped early. Treat it as a minimum.`)
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
    text = `Loading: ${a2.total.toLocaleString()} column-level, ${a1.total.toLocaleString()} cross-system assets, ${ev.rows.length.toLocaleString()} events…`
    time = `${Math.round((Date.now() - state.loadStartedAt) / 1000)}s`; pct = null
  } else if (run && ['finding', 'lineage', 'running'].some((s) => String(run.status).startsWith(s))) {
    text = `Keyword scan: ${run.status === 'lineage' ? `lineage ${run.done.toLocaleString()} of ${run.columns.length.toLocaleString()}` : run.status}`
    time = fmtDur((Date.now() - run.startedAt) / 1000); pct = run.columns.length ? run.done / run.columns.length * 100 : null
  } else if (state.loadFinishedAt) {
    const a1 = state.assets[1], a2 = state.assets[2]
    text = `Loaded ${a2.total.toLocaleString()} column-level and ${a1.total.toLocaleString()} cross-system assets` + (state.dl ? ` · lineage download ${state.dl.status}` : '')
    time = `${Math.round((state.loadFinishedAt - state.loadStartedAt) / 1000)}s`; pct = 100
  }
  bar.hidden = !text || $('#appView').hidden
  $('#catText').textContent = text; $('#catTime').textContent = time
  $('#catBar').parentElement.classList.toggle('indet', pct === null)
  $('#catBar').style.width = pct === null ? '' : `${Math.round(pct)}%`
}
setInterval(() => { if (state.dl?.status === 'running' || state.loading || state.run?.status === 'lineage') renderStatus() }, 1000)

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
  el.innerHTML = stack + shown.map((c) => {
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
  let html = ''
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
    const list = a?.orphans || []
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
    const rows = (state.assets[t]?.orphans || []).map((x) => [t, x.k, x.l, x.c, x.tool, x.tt, x.ot, CATEGORY_ORDER.find((c) => c.id === classify({ tool: x.tool, toolType: x.tt, objectType: x.ot, container: x.ct }))?.name])
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
function counts() { return { 1: state.assets[1]?.items.length || 0, 2: state.assets[2]?.items.length || 0 } }
function showPrompt() {
  const c = counts()
  $('#lineagePrompt').hidden = false; $('#dlReopen').hidden = true; $('#dlEmpty p').textContent = 'Download the lineage graphs for your assets to find confirmed orphans and broken links. Results are saved on this computer and also feed the local keyword scan.'
  const ev = state.events
  $('#promptSummary').textContent = `Assets are loaded (${c[2].toLocaleString()} column-level, ${c[1].toLocaleString()} cross-system)` + (ev?.done ? ` and ${ev.rows.length.toLocaleString()} user events.` : ev?.skipped ? '. User events were skipped.' : '.') + ' Do you want to start downloading lineage for them now?'
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
    ? `This makes about ${s.calls.toLocaleString()} requests (one per asset per direction), 6 at a time, and writes the results to a file as it goes.${s.calls > 5000 ? ' That is a lot, so it may take a long time. Keep this tab open. If the token expires you will be asked for your password to continue.' : ''}`
    : 'Choose at least one set of assets and one direction.'
}
document.querySelectorAll('#optT1,#optT2,#optUp,#optDown,#optLimit').forEach((el) => el.addEventListener('input', updateEstimate))
$('#dlLater').addEventListener('click', () => { $('#lineagePrompt').hidden = true; $('#dlReopen').hidden = false })
$('#dlReopen').addEventListener('click', () => setTab('download'))
$('#dlReopen').addEventListener('click', () => { if (!state.dl || state.dl.status !== 'running') showPrompt() })
$('#dlCancel').addEventListener('click', () => state.dl?.abort.abort())

// ---------- Lineage download (streamed to a file on the local server) ----------
$('#dlStart').addEventListener('click', startDownload)
async function startDownload() {
  const s = selection(); if (!s.calls) return
  const jobs = []
  for (const t of s.types) for (const it of state.assets[t].items.slice(0, s.per[t])) for (const d of s.dirs) jobs.push([t, it, d])
  const runId = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
  const dl = state.dl = { runId, total: jobs.length, done: 0, errors: 0, truncated: 0, nodes: 0, startedAt: Date.now(), abort: new AbortController(), status: 'running', buf: [], flushing: Promise.resolve(), note: '', dirs: s.dirs, seen: new Map(), keySets: {} }
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
  $('#dlNote').textContent = dl.note || (dl.status === 'complete' ? `Saved on this computer in the data/exports/${state.tenant} folder as ${dl.runId}.ndjson.` : '')
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
async function saveAssetsLocal() {
  for (const t of [1, 2]) {
    const a = state.assets[t]; if (!a?.done || !a.items.length) continue
    const body = a.items.map((i) => JSON.stringify({ k: i.k, l: i.l, n: i.n, c: i.c, tool: i.tool, tt: i.tt, ot: i.ot, ct: i.ct, ins: i.ins, outs: i.outs })).join('\n')
    try { await fetch(`/assets/${state.tenant}/${t}`, { method: 'PUT', body }) } catch { /* local save is best effort */ }
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
