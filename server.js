// api_webpage: local server. Serves /public, proxies Octopai API calls, stores per-tenant cache files.
import http from 'node:http'
import https from 'node:https'
import fs from 'node:fs'
import path from 'node:path'
import readline from 'node:readline'
import zlib from 'node:zlib'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'

const ROOT = path.dirname(fileURLToPath(import.meta.url))
const PUBLIC = path.join(ROOT, 'public')
const DATA = path.join(ROOT, 'data')
const PORT = Number(process.env.PORT || 5191)   // Fathom (vite) uses 5173; this project uses 5191
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
  // Give up on Octopai if it sends nothing for 4 minutes, and stop the request if the page stops waiting for it.
  up.setTimeout(4 * 60 * 1000, () => up.destroy(new Error('Octopai did not answer within 4 minutes')))
  res.on('close', () => { if (!res.writableFinished) up.destroy() })
  up.on('error', (e) => { if (!res.headersSent) send(res, 504, { error: `Upstream error: ${e.message}` }); else res.destroy() })
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
// Saved asset lists are gzipped NDJSON so catalogs with millions of assets stay small on disk and are never held in
// memory as one big string. Format v3:
//   line 1: {"meta":{"savedAt","count","v":3}}
//   line 2: {"dict":[...]}   repeated strings (connection, tool, types, db, schema, table) stored once
//   then one JSON array per asset: [key, name, conn, tool, toolType, objectType, container, db, schema, table, ins, outs, flagged]
//   where conn..table are positions in dict.
// Older versions wrote plain <site>.assets<type>.ndjson with one JSON object per asset; those are still read.
const assetsFile = (tenant, t) => path.join(DATA, `${tenant}.assets${t}.ndjson.gz`)
const legacyAssetsFile = (tenant, t) => path.join(DATA, `${tenant}.assets${t}.ndjson`)
const savedAssetsFile = (tenant, t) => [assetsFile(tenant, t), legacyAssetsFile(tenant, t)].find((f) => fs.existsSync(f)) || null
const lineStream = (file) => readline.createInterface({ input: file.endsWith('.gz') ? fs.createReadStream(file).pipe(zlib.createGunzip()) : fs.createReadStream(file), crlfDelay: Infinity })
async function readAssetsMeta(tenant, t) {
  const f = savedAssetsFile(tenant, t); if (!f) return null
  const rl = lineStream(f)
  try { for await (const line of rl) { return JSON.parse(line).meta || null } } catch { return null } finally { rl.close() }
  return null
}
// Turns one saved row (v3 array or legacy object) into the shape the keyword scan uses.
function rowToItem(row, dict) {
  if (!Array.isArray(row)) return row
  const [k, n, c, tool, , , , d, sc, tb] = row
  const D = (i) => dict[i] ?? ''
  return { k, n, c: D(c), tool: D(tool), l: [D(d), D(sc), D(tb), n].filter(Boolean).join('.') || String(k) }
}
const assetMem = new Map()
// For the keyword scan: keeps the lowercase names and the raw rows in memory, and only builds full items for matches.
async function loadAssets(tenant, t) {
  const f = savedAssetsFile(tenant, t)
  if (!f) return null
  const st = fs.statSync(f), hit = assetMem.get(`${tenant}|${t}`)
  if (hit && hit.file === f && hit.mtime === st.mtimeMs) return hit
  let meta = null, dict = [], i = 0
  const lower = [], rows = []
  for await (const line of lineStream(f)) {
    if (!line) continue
    if (i++ === 0) { meta = JSON.parse(line).meta; continue }
    if (meta?.v >= 3 && i === 2) { dict = JSON.parse(line).dict || []; continue }
    try {
      const row = JSON.parse(line)
      lower.push(String((Array.isArray(row) ? row[1] : row.n) || '').toLowerCase()); rows.push(line)
    } catch { /* skip bad line */ }
  }
  const entry = { file: f, mtime: st.mtimeMs, meta, dict, lower, rows, count: rows.length }
  assetMem.set(`${tenant}|${t}`, entry)
  return entry
}
// /assets/<tenant>/<type>
//   GET               the saved list (gzipped; the browser unzips it on the fly)
//   POST ?op=begin    start a new list: body = the meta and dict lines
//   POST ?op=append   add rows (sent in chunks so no request is huge)
//   POST ?op=commit   compress and replace the saved list in one step, so a half-written list is never used
const uploading = new Map()
async function assetsRoute(req, res) {
  const url = new URL(req.url, 'http://x')
  const [, , tenant, t] = url.pathname.split('/')
  if (!TENANT_RE.test(tenant || '') || !/^[12]$/.test(t || '')) return send(res, 400, { error: 'Bad name' })
  if (req.method === 'GET') {
    const gz = assetsFile(tenant, t), legacy = legacyAssetsFile(tenant, t)
    if (fs.existsSync(gz)) { res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Content-Encoding': 'gzip' }); return fs.createReadStream(gz).pipe(res) }
    if (fs.existsSync(legacy)) { res.writeHead(200, { 'Content-Type': 'application/x-ndjson' }); return fs.createReadStream(legacy).pipe(res) }
    return send(res, 404, { error: 'No saved assets' })
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' })
  fs.mkdirSync(DATA, { recursive: true })
  const op = url.searchParams.get('op'), key = `${tenant}|${t}`, tmp = `${assetsFile(tenant, t)}.part`
  const body = await readBody(req)
  if (op === 'begin') { fs.writeFileSync(tmp, body); uploading.set(key, { rows: 0 }); return send(res, 200, { ok: true }) }
  const up = uploading.get(key)
  if (!up || !fs.existsSync(tmp)) return send(res, 409, { error: 'No upload in progress' })
  if (op === 'append') { fs.appendFileSync(tmp, body); return send(res, 200, { ok: true }) }
  if (op === 'commit') {
    const out = assetsFile(tenant, t), gzTmp = `${out}.tmp`
    await pipeline(fs.createReadStream(tmp), zlib.createGzip({ level: 6 }), fs.createWriteStream(gzTmp))
    fs.renameSync(gzTmp, out); fs.rmSync(tmp, { force: true }); fs.rmSync(legacyAssetsFile(tenant, t), { force: true })
    uploading.delete(key); assetMem.delete(key)
    return send(res, 200, { ok: true, bytes: fs.statSync(out).size })
  }
  send(res, 400, { error: 'Unknown op' })
}

// /events/<tenant>: GET = read the saved user events, PUT = replace them (JSON { savedAt, rows }).
async function eventsRoute(req, res) {
  const tenant = decodeURIComponent(req.url.split('?')[0].split('/')[2] || '')
  if (!TENANT_RE.test(tenant)) return send(res, 400, { error: 'Bad tenant name' })
  const file = path.join(DATA, `${tenant}.events.json`)
  if (req.method === 'GET') return fs.existsSync(file) ? send(res, 200, fs.readFileSync(file)) : send(res, 404, { error: 'No saved events' })
  if (req.method === 'PUT') {
    const body = await readBody(req); JSON.parse(body.toString())
    fs.mkdirSync(DATA, { recursive: true }); fs.writeFileSync(`${file}.tmp`, body); fs.renameSync(`${file}.tmp`, file)
    return send(res, 200, { ok: true })
  }
  send(res, 405, { error: 'Method not allowed' })
}

// Index of every saved lineage graph in data/exports/<tenant>/*.ndjson: key -> byte range, so graphs are read on demand.
function indexFile(file) {
  return new Promise((resolve, reject) => {
    const map = new Map()
    let carry = Buffer.alloc(0), abs = 0
    const handle = (lineBuf, start) => {
      if (!lineBuf.length) return
      try { const g = JSON.parse(lineBuf.toString('utf8')); if (g.key && g.dir && !g.error) map.set(`${g.t}|${g.key}|${g.dir}`, { start, len: lineBuf.length }) } catch { /* skip bad line */ }
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
    for (const t of [1, 2]) { const m = await readAssetsMeta(tenant, t); if (m) assets[t] = { count: m.count, savedAt: m.savedAt } }
    const up = new Set(), down = new Set()
    for (const k of (await exportIndex(tenant)).keys()) { const [t, key, dir] = k.split('|'); if (t === '2') (dir === 'upstream' ? up : down).add(key) }
    for (const k of Object.keys(cacheLineage(tenant))) { const i = k.lastIndexOf('|'); (k.slice(i + 1) === '1' ? up : down).add(k.slice(0, i)) }
    return send(res, 200, { assets, lineage: { up: up.size, down: down.size } })
  }
  if (action === 'have' && req.method === 'GET') {
    // Which assets already have saved lineage for one asset type and direction, and when it was saved
    const t = url.searchParams.get('type') === '1' ? '1' : '2'
    const dirName = url.searchParams.get('dir') === 'downstream' ? 'downstream' : 'upstream'
    const have = {}
    const idx = await exportIndex(tenant), mt = new Map()
    for (const [k, e] of idx) {
      const [kt, key, kd] = k.split('|')
      if (kt !== t || kd !== dirName) continue
      if (!mt.has(e.file)) mt.set(e.file, fs.statSync(e.file).mtimeMs)
      have[key] = mt.get(e.file)
    }
    if (t === '2') for (const [k, v] of Object.entries(cacheLineage(tenant))) {
      const i = k.lastIndexOf('|')
      if (k.slice(i + 1) === (dirName === 'upstream' ? '1' : '2')) { const key = k.slice(0, i); have[key] = Math.max(have[key] || 0, v.at || 0) }
    }
    return send(res, 200, { have })
  }
  if (action === 'find' && req.method === 'GET') {
    const t = url.searchParams.get('type') === '1' ? 1 : 2
    const e = await loadAssets(tenant, t)
    if (!e) return send(res, 404, { error: 'No local catalog yet' })
    const kws = String(url.searchParams.get('keywords') || '').toLowerCase().split(',').map((x) => x.trim()).filter(Boolean).slice(0, 50)
    const matches = []
    for (let i = 0; i < e.count && matches.length < 50000; i++) if (kws.some((k) => e.lower[i].includes(k))) matches.push(rowToItem(JSON.parse(e.rows[i]), e.dict))
    return send(res, 200, { matches, savedAt: e.meta?.savedAt, total: e.count, truncated: matches.length >= 50000 })
  }
  if (action === 'lineage' && req.method === 'POST') {
    const { direction, keys, type } = JSON.parse((await readBody(req)).toString())
    if (![1, 2].includes(direction) || !Array.isArray(keys)) return send(res, 400, { error: 'Bad request' })
    const t = type === 1 ? 1 : 2   // older pages send no type: column-level
    const dirName = direction === 1 ? 'upstream' : 'downstream'
    const lin = cacheLineage(tenant), idx = await exportIndex(tenant)
    const found = {}
    for (const key of keys.slice(0, 5000)) {
      const c = t === 2 && lin[`${key}|${direction}`]
      if (c) { found[key] = { nodes: c.nodes || [], truncated: !!c.truncated, source: 'saved scan' }; continue }
      const e = idx.get(`${t}|${key}|${dirName}`)
      if (e) { try { const g = readGraph(e); found[key] = { nodes: g.nodes || [], truncated: !!g.truncated, source: 'lineage download' } } catch { /* unreadable line */ } }
    }
    return send(res, 200, { found })
  }
  if (action === 'coverage' && req.method === 'GET') {
    const t = url.searchParams.get('type') === '2' ? 2 : 1
    return send(res, 200, await coverageFor(tenant, t))
  }
  send(res, 404, { error: 'Unknown local action' })
}

// Report coverage: for every asset with saved downstream lineage, the distinct tool/tool-type pairs it reaches.
// The page decides which of those count as reports (using categories.js). Later downloads override earlier ones.
const covMemo = new Map()
async function coverageFor(tenant, t) {
  const dir = path.join(DATA, 'exports', tenant)
  const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.ndjson')).sort() : []
  const cf = path.join(DATA, `${tenant}.catalog.json`)
  const sig = files.map((n) => { const st = fs.statSync(path.join(dir, n)); return `${n}|${st.size}|${st.mtimeMs}` }).join(';') + `#${fs.existsSync(cf) ? fs.statSync(cf).mtimeMs : ''}`
  const memoKey = `${tenant}|${t}`, memo = covMemo.get(memoKey)
  if (memo && memo.sig === sig) return memo.out
  const keys = {}
  const add = (key, nodes, truncated) => {
    const s = new Set(); let md = 0
    for (const n of nodes || []) { s.add(`${n.tool || ''}\u0001${n.type || ''}`); if (Number(n.depth) > md) md = Number(n.depth) }
    keys[key] = { c: [...s], tr: truncated ? 1 : 0, md }
  }
  if (t === 2) for (const [k, v] of Object.entries(cacheLineage(tenant))) { const i = k.lastIndexOf('|'); if (k.slice(i + 1) === '2') add(k.slice(0, i), v.nodes, v.truncated) }
  for (const name of files) {
    for await (const line of readline.createInterface({ input: fs.createReadStream(path.join(dir, name)) })) {
      if (!line.trim()) continue
      let g; try { g = JSON.parse(line) } catch { continue }
      if (Number(g.t) === t && g.dir === 'downstream' && !g.error && g.key) add(g.key, g.nodes, g.truncated)
    }
  }
  const out = { count: Object.keys(keys).length, keys }
  covMemo.set(memoKey, { sig, out })
  return out
}

function serveStatic(req, res) {
  const rel = req.url.split('?')[0]
  const file = path.normalize(path.join(PUBLIC, rel === '/' ? 'index.html' : rel))
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Not found', 'text/plain')
  // no-cache: the browser always checks for a newer copy, so after an update a normal reload picks up the new page.
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' })
  res.end(fs.readFileSync(file))
}

http.createServer(async (req, res) => {
  try {
    if (req.url.startsWith('/octopai/')) return proxy(req, res)
    if (req.url.startsWith('/cache/')) return await cache(req, res)
    if (req.url.startsWith('/export/')) return await exportRoute(req, res)
    if (req.url.startsWith('/assets/')) return await assetsRoute(req, res)
    if (req.url.startsWith('/local/')) return await localRoute(req, res)
    if (req.url.startsWith('/events/')) return await eventsRoute(req, res)
    return serveStatic(req, res)
  } catch (e) { send(res, 500, { error: e.message }) }
}).listen(PORT, '127.0.0.1', () => console.log(`api_webpage running at http://localhost:${PORT}`))
