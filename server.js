// api_webpage: local server. Serves /public, proxies Octopai API calls, stores per-tenant cache files.
import http from 'node:http'
import https from 'node:https'
import fs from 'node:fs'
import path from 'node:path'
import readline from 'node:readline'
import { fileURLToPath } from 'node:url'

const ROOT = path.dirname(fileURLToPath(import.meta.url))
const PUBLIC = path.join(ROOT, 'public')
const DATA = path.join(ROOT, 'data')
const PORT = Number(process.env.PORT || 5190)   // Fathom (vite) uses 5173; this project uses 5190
const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.octopai\.com$/i   // only ever proxy to Octopai tenants
const TENANT_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/i   // dots allowed for regional sites like demo.eu

// Reuse TLS connections to the tenant instead of opening a new one per request (a big saving when
// many requests run at once). Responses are passed through still-compressed.
const agent = new https.Agent({ keepAlive: true, maxSockets: 64 })
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' }
const send = (res, code, body, type = 'application/json') => {
  res.writeHead(code, { 'Content-Type': type })
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body))
}

function readBody(req, limit = 200 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0
    req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('Body too large')); req.destroy() } else chunks.push(c) })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

// /octopai/<path> -> https://<X-Octopai-Host>/<path>
function proxy(req, res) {
  const host = String(req.headers['x-octopai-host'] || '')
  if (!HOST_RE.test(host)) return send(res, 400, { error: 'X-Octopai-Host must be <tenant>.octopai.com' })
  const upstreamPath = req.url.replace(/^\/octopai/, '') || '/'
  const headers = { 'Content-Type': req.headers['content-type'] || 'application/json', Accept: 'application/json', 'Accept-Encoding': 'gzip', 'Company-Host': host }
  if (req.headers.authorization) headers.Authorization = req.headers.authorization
  // OCTOPAI_UPSTREAM (e.g. http://127.0.0.1:5999) is for local testing against a mock only.
  const dev = process.env.OCTOPAI_UPSTREAM ? new URL(process.env.OCTOPAI_UPSTREAM) : null
  const lib = dev ? http : https
  const target = dev ? { host: dev.hostname, port: dev.port, path: upstreamPath, method: req.method, headers } : { host, path: upstreamPath, method: req.method, headers, agent }
  const up = lib.request(target, (ur) => {
    const out = { 'Content-Type': ur.headers['content-type'] || 'application/json' }
    if (ur.headers['content-encoding']) out['Content-Encoding'] = ur.headers['content-encoding']
    res.writeHead(ur.statusCode || 502, out)
    ur.pipe(res)
  })
  up.on('error', (e) => send(res, 502, { error: `Upstream error: ${e.message}` }))
  req.pipe(up)
}

// /cache/<tenant>: GET = read, PUT = write, DELETE = clear. Tokens are never stored here.
async function cache(req, res) {
  const tenant = decodeURIComponent(req.url.split('?')[0].split('/')[2] || '')
  if (!TENANT_RE.test(tenant)) return send(res, 400, { error: 'Bad tenant name' })
  fs.mkdirSync(DATA, { recursive: true })
  const file = path.join(DATA, `${tenant}.catalog.json`)
  if (req.method === 'GET') return fs.existsSync(file) ? send(res, 200, fs.readFileSync(file)) : send(res, 404, { error: 'No cache yet' })
  if (req.method === 'PUT') { const body = await readBody(req); JSON.parse(body.toString()); fs.writeFileSync(file, body); return send(res, 200, { ok: true, bytes: body.length }) }
  if (req.method === 'DELETE') { fs.rmSync(file, { force: true }); return send(res, 200, { ok: true }) }
  send(res, 405, { error: 'Method not allowed' })
}

// /export/<tenant>/<runId>: POST appends NDJSON lines (the page streams lineage results here so memory stays small),
// GET downloads the file, GET ?format=csv converts it to CSV on the fly.
const csvCell = (v) => { const t = String(v ?? ''); return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t }
async function exportRoute(req, res) {
  const url = new URL(req.url, 'http://x')
  const [, , tenant, run] = url.pathname.split('/')
  if (!TENANT_RE.test(tenant || '') || !/^[A-Za-z0-9_-]+$/.test(run || '')) return send(res, 400, { error: 'Bad export name' })
  const dir = path.join(DATA, 'exports', tenant)
  const file = path.join(dir, `${run}.ndjson`)
  if (req.method === 'POST') { const body = await readBody(req); fs.mkdirSync(dir, { recursive: true }); fs.appendFileSync(file, body); return send(res, 200, { ok: true }) }
  if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' })
  if (!fs.existsSync(file)) return send(res, 404, { error: 'No such export' })
  if (url.searchParams.get('format') !== 'csv') {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Content-Disposition': `attachment; filename="lineage-${tenant}-${run}.ndjson"` })
    return fs.createReadStream(file).pipe(res)
  }
  res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="lineage-${tenant}-${run}.csv"` })
  res.write('\ufeff' + ['asset_type', 'asset_key', 'asset', 'direction', 'possibly_incomplete', 'error', 'hop', 'related_key', 'related_name', 'connection', 'db', 'schema', 'table', 'tool'].join(',') + '\r\n')
  for await (const line of readline.createInterface({ input: fs.createReadStream(file) })) {
    if (!line.trim()) continue
    let g; try { g = JSON.parse(line) } catch { continue }
    const base = [g.t, g.key, g.label, g.dir, g.truncated ? 'yes' : '', g.error || '']
    const nodes = g.nodes && g.nodes.length ? g.nodes : [null]
    for (const n of nodes) res.write([...base, ...(n ? [n.depth, n.key, n.name, n.connection, n.db, n.schema, n.table, n.tool] : ['', '', '', '', '', '', '', ''])].map(csvCell).join(',') + '\r\n')
  }
  res.end()
}

// ---- local files: saved assets and saved lineage, used by the keyword scan ----
const assetsFile = (tenant, t) => path.join(DATA, `${tenant}.assets${t}.ndjson`)
const assetMem = new Map()
function loadAssets(tenant, t) {
  const f = assetsFile(tenant, t)
  if (!fs.existsSync(f)) return null
  const st = fs.statSync(f), hit = assetMem.get(f)
  if (hit && hit.mtime === st.mtimeMs) return hit
  const lines = fs.readFileSync(f, 'utf8').split('\n')
  const meta = JSON.parse(lines[0]).meta
  const items = []
  for (let i = 1; i < lines.length; i++) if (lines[i]) { try { items.push(JSON.parse(lines[i])) } catch { /* skip bad line */ } }
  const entry = { mtime: st.mtimeMs, meta, items, lower: items.map((x) => String(x.n || '').toLowerCase()) }
  assetMem.set(f, entry)
  return entry
}
// PUT /assets/<tenant>/<type>: replace the saved asset list (NDJSON, one asset per line)
async function assetsRoute(req, res) {
  const [, , tenant, t] = req.url.split('?')[0].split('/')
  if (!TENANT_RE.test(tenant || '') || !/^[12]$/.test(t || '')) return send(res, 400, { error: 'Bad name' })
  if (req.method !== 'PUT') return send(res, 405, { error: 'Method not allowed' })
  const body = (await readBody(req)).toString().trim()
  const count = body ? body.split('\n').length : 0
  fs.mkdirSync(DATA, { recursive: true })
  const file = assetsFile(tenant, t), tmp = `${file}.tmp`
  fs.writeFileSync(tmp, JSON.stringify({ meta: { savedAt: Date.now(), count } }) + '\n' + body + '\n')
  fs.renameSync(tmp, file)
  send(res, 200, { ok: true, count })
}

// Index of every saved lineage graph in data/exports/<tenant>/*.ndjson: key -> byte range, so graphs are read on demand.
function indexFile(file) {
  return new Promise((resolve, reject) => {
    const map = new Map()
    let carry = Buffer.alloc(0), abs = 0
    const handle = (lineBuf, start) => {
      if (!lineBuf.length) return
      try { const g = JSON.parse(lineBuf.toString('utf8')); if (g.key && g.dir) map.set(`${g.t}|${g.key}|${g.dir}`, { start, len: lineBuf.length }) } catch { /* skip bad line */ }
    }
    const rs = fs.createReadStream(file)
    rs.on('data', (chunk) => {
      const buf = carry.length ? Buffer.concat([carry, chunk]) : chunk
      let from = 0
      for (;;) { const nl = buf.indexOf(10, from); if (nl === -1) break; handle(buf.subarray(from, nl), abs + from); from = nl + 1 }
      carry = buf.subarray(from); abs += from
    })
    rs.on('end', () => { if (carry.length) handle(carry, abs); resolve(map) })
    rs.on('error', reject)
  })
}
const fileIdx = new Map(), combinedIdx = new Map()
async function exportIndex(tenant) {
  const dir = path.join(DATA, 'exports', tenant)
  if (!fs.existsSync(dir)) return new Map()
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.ndjson')).sort()   // names are timestamps, so oldest first
  const sigs = files.map((n) => { const st = fs.statSync(path.join(dir, n)); return `${n}|${st.size}|${st.mtimeMs}` }).join(';')
  const memo = combinedIdx.get(tenant)
  if (memo && memo.sigs === sigs) return memo.out
  const out = new Map()
  for (const name of files) {
    const file = path.join(dir, name), st = fs.statSync(file), sig = `${st.size}|${st.mtimeMs}`
    let hit = fileIdx.get(file)
    if (!hit || hit.sig !== sig) { hit = { sig, map: await indexFile(file) }; fileIdx.set(file, hit) }
    for (const [k, v] of hit.map) out.set(k, { file, ...v })
  }
  combinedIdx.set(tenant, { sigs, out })
  return out
}
const cacheMem = new Map()
function cacheLineage(tenant) {
  const f = path.join(DATA, `${tenant}.catalog.json`)
  if (!fs.existsSync(f)) return {}
  const st = fs.statSync(f), hit = cacheMem.get(f)
  if (hit && hit.mtime === st.mtimeMs) return hit.lineage
  let lineage = {}
  try { lineage = JSON.parse(fs.readFileSync(f, 'utf8')).lineage || {} } catch { /* unreadable cache */ }
  cacheMem.set(f, { mtime: st.mtimeMs, lineage })
  return lineage
}
function readGraph(entry) {
  const fd = fs.openSync(entry.file, 'r')
  try { const buf = Buffer.alloc(entry.len); fs.readSync(fd, buf, 0, entry.len, entry.start); return JSON.parse(buf.toString('utf8')) } finally { fs.closeSync(fd) }
}

async function localRoute(req, res) {
  const url = new URL(req.url, 'http://x')
  const [, , tenant, action] = url.pathname.split('/')
  if (!TENANT_RE.test(tenant || '')) return send(res, 400, { error: 'Bad tenant name' })
  if (action === 'status' && req.method === 'GET') {
    const assets = {}
    for (const t of [1, 2]) { const e = loadAssets(tenant, t); if (e) assets[t] = { count: e.items.length, savedAt: e.meta.savedAt } }
    const up = new Set(), down = new Set()
    for (const k of (await exportIndex(tenant)).keys()) { const [t, key, dir] = k.split('|'); if (t === '2') (dir === 'upstream' ? up : down).add(key) }
    for (const k of Object.keys(cacheLineage(tenant))) { const i = k.lastIndexOf('|'); (k.slice(i + 1) === '1' ? up : down).add(k.slice(0, i)) }
    return send(res, 200, { assets, lineage: { up: up.size, down: down.size } })
  }
  if (action === 'find' && req.method === 'GET') {
    const t = url.searchParams.get('type') === '1' ? 1 : 2
    const e = loadAssets(tenant, t)
    if (!e) return send(res, 404, { error: 'No local catalog yet' })
    const kws = String(url.searchParams.get('keywords') || '').toLowerCase().split(',').map((x) => x.trim()).filter(Boolean).slice(0, 50)
    const matches = []
    for (let i = 0; i < e.items.length && matches.length < 50000; i++) if (kws.some((k) => e.lower[i].includes(k))) matches.push(e.items[i])
    return send(res, 200, { matches, savedAt: e.meta.savedAt, total: e.items.length, truncated: matches.length >= 50000 })
  }
  if (action === 'lineage' && req.method === 'POST') {
    const { direction, keys } = JSON.parse((await readBody(req)).toString())
    if (![1, 2].includes(direction) || !Array.isArray(keys)) return send(res, 400, { error: 'Bad request' })
    const dirName = direction === 1 ? 'upstream' : 'downstream'
    const lin = cacheLineage(tenant), idx = await exportIndex(tenant)
    const found = {}
    for (const key of keys.slice(0, 5000)) {
      const c = lin[`${key}|${direction}`]
      if (c) { found[key] = { nodes: c.nodes || [], truncated: !!c.truncated, source: 'saved scan' }; continue }
      const e = idx.get(`2|${key}|${dirName}`)
      if (e) { try { const g = readGraph(e); found[key] = { nodes: g.nodes || [], truncated: !!g.truncated, source: 'lineage download' } } catch { /* unreadable line */ } }
    }
    return send(res, 200, { found })
  }
  send(res, 404, { error: 'Unknown local action' })
}

function serveStatic(req, res) {
  const rel = req.url.split('?')[0]
  const file = path.normalize(path.join(PUBLIC, rel === '/' ? 'index.html' : rel))
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Not found', 'text/plain')
  send(res, 200, fs.readFileSync(file), MIME[path.extname(file)] || 'application/octet-stream')
}

http.createServer(async (req, res) => {
  try {
    if (req.url.startsWith('/octopai/')) return proxy(req, res)
    if (req.url.startsWith('/cache/')) return await cache(req, res)
    if (req.url.startsWith('/export/')) return await exportRoute(req, res)
    if (req.url.startsWith('/assets/')) return await assetsRoute(req, res)
    if (req.url.startsWith('/local/')) return await localRoute(req, res)
    return serveStatic(req, res)
  } catch (e) { send(res, 500, { error: e.message }) }
}).listen(PORT, '127.0.0.1', () => console.log(`api_webpage running at http://localhost:${PORT}`))
