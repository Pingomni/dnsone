// The demo's API: answers the console's /api calls in the browser, from data recorded from the real
// backend (backend/tools/demo_fixtures.py → fixtures.json). Lists are filtered and paged here; creating,
// changing and deleting work on an in-memory copy kept for the browser tab (sessionStorage), so a visitor
// can try everything and nothing leaves the browser.
import recorded from './fixtures.json';

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;
type Store = { fixtures: Record<string, Json>; texts: Record<string, string>; nextId: number };

export class DemoError extends Error {
    status: number;
    errors: Record<string, string>;
    constructor(status: number, message: string, errors: Record<string, string> = {}) {
        super(message);
        this.status = status;
        this.errors = errors;
    }
}

const KEY = 'dnsone-demo-v1';
const samples = (recorded as Json).samples as Record<string, Json>;
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v));

function fresh(): Store {
    return { fixtures: clone((recorded as Json).fixtures), texts: clone((recorded as Json).texts), nextId: 100000 };
}

let store: Store = (() => {
    try {
        const saved = sessionStorage.getItem(KEY);
        if (saved) return JSON.parse(saved) as Store;
    } catch {
        /* private mode or blocked storage: start fresh */
    }
    return fresh();
})();

function save(): void {
    try {
        sessionStorage.setItem(KEY, JSON.stringify(store));
    } catch {
        /* the demo still works for this page */
    }
}

export function resetDemo(): void {
    store = fresh();
    try {
        sessionStorage.removeItem(KEY);
    } catch {
        /* nothing saved */
    }
}

const now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');
const notInDemo = () => new DemoError(403, 'This is a demo: this action is not available here. Everything else can be tried.');

/** The recorded list behind a path: the same path recorded with a large page. */
function listKey(path: string): string | null {
    for (const key of [`${path}?size=500`, `${path}?limit=500`, path]) {
        const v = store.fixtures[key];
        if (v && Array.isArray(v.rows)) return key;
    }
    return null;
}

const PAGING = new Set(['page', 'size', 'sort', 'tab', 'before', 'limit', 'v', 'from', 'to', 'hours', 'days']);
const FIELD: Record<string, string> = { state: 'publish_state', group: 'group_id' };

function filterRows(rows: Json[], params: URLSearchParams): Json[] {
    let out = rows;
    for (const [key, raw] of params) {
        const value = raw.trim();
        if (!value || PAGING.has(key)) continue;
        if (key === 'q' || key === 'domain') {
            const needle = value.toLowerCase();
            out = out.filter((r) => JSON.stringify(r).toLowerCase().includes(needle));
            continue;
        }
        if (key === 'action') {
            out = out.filter((r) => String(r.action ?? '').startsWith(value));
            continue;
        }
        const field = FIELD[key] ?? key;
        out = out.filter((r) => !(field in r) || String(r[field] ?? '') === value);
    }
    return out;
}

function paged(fixture: Json, params: URLSearchParams): Json {
    const rows = filterRows(fixture.rows as Json[], params);
    const size = Number(params.get('size')) || 50;
    const pages = Math.max(1, Math.ceil(rows.length / size));
    const page = Math.min(Math.max(1, Number(params.get('page')) || 1), pages);
    return { ...fixture, rows: rows.slice((page - 1) * size, page * size), total: rows.length, page, pages, size };
}

function queryLog(params: URLSearchParams): Json {
    const base = store.fixtures['/api/queries?limit=500'];
    let rows = filterRows(base.rows, params) as Json[];
    if (params.get('qname')) rows = rows.filter((r) => r.qname === params.get('qname'));
    const before = Number(params.get('before')) || 0;
    if (before) rows = rows.filter((r) => r.id < before);
    const limit = Number(params.get('limit')) || 100;
    const page = rows.slice(0, limit);
    return { ...base, rows: page, next_before: rows.length > limit ? page[page.length - 1].id : null };
}

function newZoneDetail(zone: Json): Json {
    return { ...zone, type_counts: { NS: 2 } };
}

/** GET: the recording, else a list answer built from the recording, else a sensible empty one. */
function get(path: string, params: URLSearchParams, raw: string): Json {
    if (store.fixtures[raw] !== undefined) return clone(store.fixtures[raw]);
    if (path === '/api/queries') return queryLog(params);
    if (path === '/api/groups/lookup') {
        const client = params.get('client') ?? '';
        const family = /^10\.20\.(8|9)\./.test(client);
        const key = Object.keys(store.fixtures).find((k) => k.startsWith('/api/groups/lookup') && (k.includes('10.20.8.') === family));
        return { ...clone(store.fixtures[key!]), client };
    }
    if (path === '/api/rpz/lookup') {
        const domain = (params.get('domain') ?? '').toLowerCase();
        const blocked = /(doubleclick|adserver|ads?\d*\.|tracking|casino|app-measurement)/.test(domain);
        const sample = clone(store.fixtures[blocked ? '/api/rpz/lookup?domain=doubleclick.net' : '/api/rpz/lookup?domain=wikipedia.org']);
        return JSON.parse(JSON.stringify(sample).replaceAll(blocked ? 'doubleclick.net' : 'wikipedia.org', domain));
    }
    const list = listKey(path);
    if (list) return paged(store.fixtures[list], params);
    const zone = path.match(/^\/api\/zones\/(\d+)(\/.*)?$/);
    if (zone) {
        const row = store.fixtures['/api/zones?size=500'].rows.find((z: Json) => z.id === Number(zone[1]));
        if (!row) throw new DemoError(404, 'Zone not found.');
        if (!zone[2]) return newZoneDetail(row);
        if (zone[2] === '/records') return { rows: [], total: 0, page: 1, pages: 1, size: 100 };
        if (zone[2] === '/preview') return { serial: row.serial, text: `; zone ${row.name} (demo)\n$ORIGIN ${row.name}.\n` };
        if (zone[2] === '/dnssec') return { state: row.dnssec ?? 'off', summary: 'not signed', keys: [], ds: [], parent_ds: null, secure: false, bind_status: '' };
    }
    if (/^\/api\/users\/\d+\/tokens$/.test(path)) return { rows: [] };
    if (path.startsWith('/api/queries/')) {
        // A period the recording does not have: the nearest one.
        const near = Object.keys(store.fixtures).find((k) => k.startsWith(`${path}?`) && k.includes(params.get('dimension') ?? ''));
        if (near) return clone(store.fixtures[near]);
    }
    throw new DemoError(404, 'Not available in the demo.');
}

function nextId(): number {
    store.nextId += 1;
    return store.nextId;
}

/** The list a new item goes to, and where an item lives: /api/zones/3/records/12 → records of zone 3. */
function parentOf(path: string): { list: string | null; id: number | null } {
    const m = path.match(/^(.*)\/(\d+)$/);
    if (!m) return { list: listKey(path), id: null };
    return { list: listKey(m[1]), id: Number(m[2]) };
}

function touchZone(path: string): void {
    const m = path.match(/^\/api\/zones\/(\d+)\//);
    if (!m) return;
    const zid = Number(m[1]);
    const zones = store.fixtures['/api/zones?size=500'].rows as Json[];
    const zone = zones.find((z) => z.id === zid);
    if (zone) {
        zone.serial += 1;
        zone.published_serial = zone.serial;
        zone.updated_at = now();
        const records = store.fixtures[`/api/zones/${zid}/records?size=500`];
        if (records) zone.record_count = records.rows.length;
        const detail = store.fixtures[`/api/zones/${zid}`];
        if (detail) Object.assign(detail, zone);
    }
}

function create(path: string, body: Json): Json {
    const list = listKey(path);
    if (!list) throw notInDemo();
    const id = nextId();
    let row: Json = { id, ...body, created_at: now(), updated_at: now() };
    if (path === '/api/zones') {
        const name = String(body.name ?? '').toLowerCase().replace(/\.$/, '');
        if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(name)) throw new DemoError(422, 'Enter a full domain such as example.com.', { name: 'Enter a full domain such as example.com.' });
        row = { id, name, description: body.description ?? '', serial: 2026102401, published_serial: 2026102401, default_ttl: body.default_ttl ?? 3600,
                soa_mname: `${body.nameservers?.[0]?.host ?? 'ns1.demo-isp.net'}.`, soa_rname: 'hostmaster.demo-isp.net.', soa_refresh: 7200,
                soa_retry: 1800, soa_expire: 1209600, soa_minimum: 300, status: 'active', dnssec: 'off', publish_state: 'published',
                pending: false, published_at: now(), last_error: null, record_count: 2, created_at: now(), updated_at: now() };
        store.fixtures[`/api/zones/${id}/records?size=500`] = { rows: (body.nameservers ?? []).map((ns: Json) => ({
            id: nextId(), name: '@', fqdn: `${name}.`, type: 'NS', value: `${String(ns.host).replace(/\.$/, '')}.`, ttl: null, priority: null, disabled: false, comment: '' })),
            total: 0, page: 1, pages: 1, size: 500 };
    }
    const records = path.match(/^\/api\/zones\/(\d+)\/records$/);
    if (records) {
        const zone = store.fixtures['/api/zones?size=500'].rows.find((z: Json) => z.id === Number(records[1]));
        const name = String(body.name || '@');
        if (!body.value) throw new DemoError(422, 'Enter a value.', { value: 'Enter a value.' });
        row = { id, name, fqdn: name === '@' ? `${zone.name}.` : `${name}.${zone.name}.`, type: body.type, value: body.value,
                ttl: body.ttl ?? null, priority: body.priority ?? null, disabled: Boolean(body.disabled), comment: body.comment ?? '', updated_at: now() };
    }
    if (path === '/api/rpz/rules') row = { enabled: true, source: 'manual', created_by: 'demo', group_name: null, ...row };
    if (path === '/api/rpz/blocklists') row = { last_status: 'ok', domain_count: 12500, last_updated: now(), kind: 'block', enabled: true, ...row };
    if (path === '/api/users') row = { role: 'operator', enabled: true, auth_source: 'local', last_login_at: null, locked: false, self: false, two_factor_enabled: false, ...row };
    if (path === '/api/groups') row = { networks: [], blocklists: [], built_in: false, blocking: true, network_count: 0, ...row };
    store.fixtures[list].rows.unshift(row);
    store.fixtures[list].total = store.fixtures[list].rows.length;
    touchZone(path);
    return row;
}

function update(path: string, body: Json): Json {
    if (store.fixtures[path] && !Array.isArray(store.fixtures[path].rows)) {
        Object.assign(store.fixtures[path], body);
    }
    const { list, id } = parentOf(path);
    let row: Json = store.fixtures[path];
    if (list && id !== null) {
        row = (store.fixtures[list].rows as Json[]).find((r) => r.id === id);
        if (!row) throw new DemoError(404, 'Not found.');
        Object.assign(row, body, { updated_at: now() });
        if (body.dnssec === true) row.dnssec = 'on';
        if (body.dnssec === false && row.dnssec === 'on') row.dnssec = 'insecure';
        if (store.fixtures[path]) Object.assign(store.fixtures[path], row);
    }
    if (!row) throw notInDemo();
    touchZone(path);
    return clone(row);
}

function remove(path: string): Json {
    const { list, id } = parentOf(path);
    if (!list || id === null) throw notInDemo();
    const rows = store.fixtures[list].rows as Json[];
    const index = rows.findIndex((r) => r.id === id);
    if (index < 0) throw new DemoError(404, 'Not found.');
    rows.splice(index, 1);
    store.fixtures[list].total = rows.length;
    touchZone(path);
    return { ok: true };
}

/** Answers one API call: (status, JSON body). */
export function demoRequest(method: string, url: string, body: Json): Json {
    const parsed = new URL(url, window.location.origin);
    const path = parsed.pathname.replace(/\/$/, '');
    const raw = path + parsed.search;
    const params = parsed.searchParams;
    const me = store.fixtures['/api/auth/me'];
    if (method === 'GET') return get(path, params, raw);

    // Sign-in and account security: the demo is already signed in.
    if (path === '/api/auth/login' || path === '/api/auth/login/verify') return clone(me);
    if (path === '/api/auth/logout') {
        resetDemo();
        return { ok: true, redirect: null };
    }
    if (path.startsWith('/api/auth/2fa') || path === '/api/auth/password' || path === '/api/settings/restore') throw notInDemo();
    if (path === '/api/auth/tokens' && method === 'POST') {
        const token = { id: nextId(), name: body?.name ?? 'demo', prefix: 'dno_demo', read_only: body?.read_only ?? true, created_at: now(), last_used_at: null, expires_at: null, expired: false };
        store.fixtures['/api/auth/tokens'].rows.unshift(token);
        save();
        return { ...token, token: 'dno_demo_this_is_not_a_real_app_password' };
    }

    // Actions with a recorded sample answer.
    let m = path.match(/^\/api\/zones\/(\d+)\/publish$/);
    if (m) return { ...update(`/api/zones/${m[1]}`, {}), message: samples.publish.message };
    if (/^\/api\/zones\/\d+\/reverse$/.test(path)) return clone(samples.reverse);
    if (/^\/api\/zones\/\d+\/import$/.test(path)) return clone(samples.import_into);
    if (path === '/api/zones/import') {
        if (body?.dry_run) return clone(samples.import_new);
        const zone = create('/api/zones', { name: body?.name, description: body?.description, nameservers: [{ host: 'ns1.demo-isp.net' }] });
        save();
        return { ...clone(samples.import_new), zone };
    }
    if (path === '/api/rpz/build') return clone(samples.build);
    if (path === '/api/rpz/pause') return clone(method === 'DELETE' ? samples.resume : samples.pause);
    if (path === '/api/settings/alerts/test') return { results: { webhook: 'ok' } };
    if (/^\/api\/rpz\/blocklists\/\d+\/refresh$/.test(path)) return update(path.replace(/\/refresh$/, ''), { last_checked: now(), last_status: 'ok' });
    m = path.match(/^\/api\/groups\/(\d+)\/networks(?:\/(\d+))?$/);
    if (m) {
        const group = store.fixtures[`/api/groups/${m[1]}`];
        if (!group) throw notInDemo();
        if (method === 'DELETE') group.networks = group.networks.filter((n: Json) => n.id !== Number(m![2]));
        else group.networks.push({ id: nextId(), network: body?.network ?? '', comment: body?.comment ?? '' });
        save();
        return clone(group);
    }

    let out: Json;
    if (method === 'POST') out = create(path, body ?? {});
    else if (method === 'PUT' || method === 'PATCH') out = update(path, body ?? {});
    else if (method === 'DELETE') out = remove(path);
    else throw notInDemo();
    save();
    return out;
}

/** A file the console offers as a download (zone file, backup). */
export function demoDownload(url: string): { name: string; type: string; body: string } | null {
    const parsed = new URL(url, window.location.origin);
    const raw = parsed.pathname + parsed.search;
    const text = store.texts[raw] ?? store.texts[parsed.pathname];
    const zone = parsed.pathname.match(/^\/api\/zones\/(\d+)\/export$/);
    if (zone) {
        const row = store.fixtures['/api/zones?size=500'].rows.find((z: Json) => z.id === Number(zone[1]));
        return { name: `${row?.name ?? 'zone'}.zone`, type: 'text/plain', body: text ?? `; zone ${row?.name} (demo)\n` };
    }
    if (parsed.pathname === '/api/settings/backup') {
        return { name: 'dnsone-backup-demo.json', type: 'application/json', body: JSON.stringify(store.fixtures['/api/settings/backup'], null, 2) };
    }
    return text ? { name: parsed.pathname.split('/').pop() ?? 'download', type: 'text/plain', body: text } : null;
}
