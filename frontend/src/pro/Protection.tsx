// SPDX-License-Identifier: Elastic-2.0
// DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
// Protection (1.5): what dnsdist is blocking by itself (floods, random-subdomain attacks, infected
// clients, amplification), its history, the operators' own blocks and the thresholds.
import { router, usePage } from '@inertiajs/react';
import { useEffect, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable, Pagination } from '@/components/table';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, ListPanel, Panel, Select } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, del, post, put, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { query } from '@/lib/format';
import type { Paginated } from '@/lib/types';
import { applyFirewall } from '@/pro/FirewallTab';

type Live = { target: string; kind: string; reason: string; seconds: number; blocks: number; action: string };
type Block = { id: number; kind: 'client' | 'domain'; value: string; reason: string; created_by: string; created_at: string; expires_at: string | null };
type Config = {
    random_subdomain: { enabled: boolean; nxdomains: number; names: number; seconds: number };
    nxdomain_clients: { enabled: boolean; percent: number; responses: number; seconds: number };
    amplification: { enabled: boolean; kbytes: number; seconds: number };
};
type Overview = {
    node: string; now: Live[] | null; blocks: Block[]; config: Config;
    day: { by_kind: Record<string, number>; top: { target: string; kind: string; episodes: number; blocks: number; last_seen: string }[] };
};
type Event = { id: number; node: string; kind: string; target: string; reason: string; action: string; first_seen: string; last_seen: string; blocks: number; minutes: number };

const KINDS: Record<string, [string, string]> = {
    'random-subdomain': ['Random-subdomain attack', 'A domain asked for with many names that do not exist: refused for everyone while it lasts.'],
    nxdomain: ['Infected client', 'A client whose answers are mostly NXDOMAIN: dropped.'],
    amplification: ['Amplification', 'A client receiving far more bytes than a real user: answered with TC.'],
    flood: ['Query flood', 'A client above twice its query rate: refused.'],
    servfail: ['SERVFAIL flood', 'A client causing many SERVFAILs: refused.'],
};
const kindLabel = (k: string) => KINDS[k]?.[0] ?? k;
const isClient = (target: string) => target.includes('/');

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

function BlockDialog({ initial, canFirewall, onClose, onDone }: { initial: { kind: 'client' | 'domain'; value: string; reason: string }; canFirewall: boolean; onClose: () => void; onDone: () => void }) {
    const toast = useToast();
    const [form, setForm] = useState({ ...initial, minutes: '1440', where: 'dnsdist' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const firewall = form.kind === 'client' && form.where === 'firewall';
    return (
        <FormDialog open title={form.kind === 'client' ? 'Block a client' : 'Block a domain'} submitLabel="Block" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                if (firewall) {
                    await post('/api/firewall/rules', { action: 'drop', protocol: 'any', source: form.value, comment: form.reason || 'Blocked from Protection', minutes: Number(form.minutes) });
                    toast('Firewall rule added; applying…');
                    const st = await applyFirewall(() => undefined);
                    toast(st.message ?? st.state, st.state === 'applied' ? undefined : 'danger');
                } else {
                    await post('/api/protection/blocks', { kind: form.kind, value: form.value, reason: form.reason, minutes: Number(form.minutes) });
                    toast('Blocked. dnsdist applies it on every node within a minute.');
                }
                onDone();
            } catch (e) {
                setErrors(errorsOf(e, 'value'));
            } finally {
                setBusy(false);
            }
        }}>
            <ErrorSummary errors={errors} />
            <div className="form-grid">
                <Select label="Block" name="kind" value={form.kind} options={[{ value: 'client', label: 'A client address or network' }, { value: 'domain', label: 'A domain (and every name below it)' }]}
                    onChange={(e) => setForm({ ...form, kind: e.target.value as 'client' | 'domain' })} />
                <Field label={form.kind === 'client' ? 'Address or network' : 'Domain'} name="value" required spellCheck={false} value={form.value} error={errors.value}
                    placeholder={form.kind === 'client' ? '198.51.100.7 or 198.51.100.0/24' : 'victim.example'} onChange={(e) => setForm({ ...form, value: e.target.value })} />
                {form.kind === 'client' && canFirewall && (
                    <Select label="Where" name="where" value={form.where} className="span2"
                        hint={firewall ? 'Every packet from it is dropped by the server\'s firewall (Settings → Firewall), not only DNS.' : 'Its DNS queries are dropped by dnsdist, on every node.'}
                        options={[{ value: 'dnsdist', label: 'DNS queries (dnsdist)' }, { value: 'firewall', label: 'Everything (firewall)' }]}
                        onChange={(e) => setForm({ ...form, where: e.target.value })} />
                )}
                <Field label="Reason" name="reason" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
                <Select label="For" name="minutes" value={form.minutes}
                    options={[{ value: '60', label: '1 hour' }, { value: '1440', label: '1 day' }, { value: '10080', label: '1 week' }, { value: '0', label: 'Until removed' }]}
                    onChange={(e) => setForm({ ...form, minutes: e.target.value })} />
                {form.kind === 'domain' && <p className="hint">Every customer gets REFUSED for it while blocked. Domains hosted here can be blocked too.</p>}
            </div>
        </FormDialog>
    );
}

function Thresholds({ config, onSaved }: { config: Config; onSaved: (c: Config) => void }) {
    const toast = useToast();
    const [form, setForm] = useState(config);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const num = <S extends keyof Config>(section: S, key: keyof Config[S] & string, label: string, hint?: string) => (
        <Field label={label} name={`${section}.${key}`} type="number" min={1} hint={hint} value={String(form[section][key])} error={errors[`${section}.${key}`]}
            onChange={(e) => setForm({ ...form, [section]: { ...form[section], [key]: Number(e.target.value) } })} />
    );
    const on = <S extends keyof Config>(section: S, label: string) => (
        <div className="span2"><Check label={label} checked={form[section].enabled} onChange={(e) => setForm({ ...form, [section]: { ...form[section], enabled: e.target.checked } })} /></div>
    );
    return (
        <Panel title="Thresholds">
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                try {
                    onSaved(await put<Config>('/api/protection/config', form));
                    setErrors({});
                    toast('Saved. dnsdist applies it within 2 seconds.');
                } catch (err) {
                    setErrors(errorsOf(err, 'random_subdomain.nxdomains'));
                }
            }}>
                <p className="span2 hint">dnsdist looks at the last 10 seconds of traffic. Floods above twice a client's query rate (Settings → DNS server) are always refused; NAT addresses and the server itself are never blocked by these.</p>
                {on('random_subdomain', 'Block domains under a random-subdomain ("water torture") attack')}
                {form.random_subdomain.enabled && <>
                    {num('random_subdomain', 'nxdomains', 'NXDOMAIN answers in 10 s', 'Below the domain, all clients together.')}
                    {num('random_subdomain', 'names', 'Different names asked for')}
                    {num('random_subdomain', 'seconds', 'Block for (seconds)')}
                </>}
                {on('nxdomain_clients', 'Drop clients whose answers are mostly NXDOMAIN (infected devices)')}
                {form.nxdomain_clients.enabled && <p className="span2 hint">Ad-blocked names are answered NXDOMAIN too: keep the threshold above what a busy household behind one address sends.</p>}
                {form.nxdomain_clients.enabled && <>
                    {num('nxdomain_clients', 'percent', 'NXDOMAIN share (%)')}
                    {num('nxdomain_clients', 'responses', 'At least this many answers in 10 s')}
                    {num('nxdomain_clients', 'seconds', 'Drop for (seconds)')}
                </>}
                {on('amplification', 'Truncate answers to clients receiving too much (spoofed amplification victims)')}
                {form.amplification.enabled && <>
                    {num('amplification', 'kbytes', 'kB per second to one client')}
                    {num('amplification', 'seconds', 'For (seconds)')}
                </>}
                <FormActions><button className="primary">Save</button></FormActions>
            </form>
        </Panel>
    );
}

function History() {
    const { url } = usePage();
    const params = searchOf(url);
    const filters = { q: params.get('q') ?? '', kind: params.get('kind') ?? '', page: params.get('page') ?? '' };
    const { data } = useApi<Paginated<Event>>(`/api/protection/events${query(filters)}`);
    const [q, setQ] = useState(filters.q);
    const go = (patch: Record<string, string>) => {
        const next = { ...filters, ...patch, page: '' };
        router.get('/protection', Object.fromEntries(Object.entries(next).filter(([, v]) => v !== '')), { preserveScroll: true });
    };
    return (
        <ListPanel title="History" description="What dnsdist blocked during the last week, one row per target and episode (recorded every minute).">
            <form className="toolbar list-filterbar" onSubmit={(e) => { e.preventDefault(); go({ q }); }}>
                <label className="list-search"><span>Search</span><input type="search" placeholder="Address or domain" value={q} onChange={(e) => setQ(e.target.value)} /></label>
                <label className="list-filter"><span>Kind</span>
                    <select value={filters.kind} onChange={(e) => go({ kind: e.target.value })}>
                        <option value="">All</option>{Object.entries(KINDS).map(([k, [label]]) => <option key={k} value={k}>{label}</option>)}
                    </select>
                </label>
                <div className="list-filter-buttons"><button className="primary">Search</button></div>
            </form>
            {data ? (
                <>
                    <DataTable rows={data.rows} rowKey={(r) => r.id} serverPaginated emptyText="Nothing was blocked."
                        columns={[
                            { header: 'Target', cell: (r) => <span className="mono">{r.target}</span> },
                            { header: 'Kind', cell: (r) => <div className="list-cell-stack"><span>{kindLabel(r.kind)}</span><span className="list-subline">{r.reason}</span></div> },
                            { header: 'When', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.first_seen}</span><span className="list-subline">{r.minutes} min</span></div> },
                            { header: 'Blocked queries', cell: (r) => r.blocks.toLocaleString() },
                            { header: 'Node', cell: (r) => r.node },
                        ]} />
                    {data.pages > 1 && <Pagination result={data} path="/protection" query={filters} noun="events" />}
                </>
            ) : <Empty>Loading…</Empty>}
        </ListPanel>
    );
}

export default function Protection() {
    const can = useCan();
    const canManage = can('protection.manage');
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, reload } = useApi<Overview>('/api/protection');
    const [blocking, setBlocking] = useState<{ kind: 'client' | 'domain'; value: string; reason: string } | null>(null);
    useEffect(() => {
        const timer = window.setInterval(() => void reload(), 15000);
        return () => window.clearInterval(timer);
    }, [reload]);
    if (!data) return <AppLayout title="Protection"><Empty>Loading…</Empty></AppLayout>;

    const unblock = async (b: Block) => {
        if (!(await ask({ title: `Unblock ${b.value}?`, message: 'dnsdist stops blocking it within a minute.', confirmLabel: 'Unblock' }))) return;
        try {
            await del(`/api/protection/blocks/${b.id}`);
            setData({ ...data, blocks: data.blocks.filter((x) => x.id !== b.id) });
            toast(`${b.value} unblocked.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const blockButton = (target: string, reason: string) => canManage && (
        <button type="button" className="link" onClick={() => setBlocking({ kind: isClient(target) ? 'client' : 'domain', value: target.replace(/\.$/, '').replace(/\/(32|128)$/, ''), reason })}>Block longer</button>
    );
    return (
        <AppLayout title="Protection">
            <div className="toolbar">
                {canManage && <button type="button" className="primary" onClick={() => setBlocking({ kind: 'client', value: '', reason: '' })}><Icon name="plus" />Block a client or domain</button>}
                <button type="button" onClick={() => void reload()}><Icon name="refresh" />Refresh</button>
            </div>
            <Panel title="Last 24 hours">
                <div className="kind-tiles">
                    {Object.entries(KINDS).map(([k, [label, hint]]) => (
                        <div key={k} className="kind-tile" title={hint}><strong>{data.day.by_kind[k] ?? 0}</strong><span>{label}</span></div>
                    ))}
                </div>
            </Panel>
            <ListPanel title={`Blocked now on ${data.node}`} description="dnsdist's dynamic blocks; they lift by themselves when the traffic stops.">
                {data.now === null ? <Empty tone="danger">dnsdist's API does not answer on this node.</Empty> : (
                    <DataTable rows={data.now} rowKey={(r) => r.target} emptyText="Nothing is blocked right now."
                        columns={[
                            { header: 'Target', cell: (r) => <span className="mono">{r.target}</span> },
                            { header: 'Kind', cell: (r) => <div className="list-cell-stack"><span>{kindLabel(r.kind)}</span><span className="list-subline">{r.reason}</span></div> },
                            { header: 'Lifts in', cell: (r) => `${r.seconds} s` },
                            { header: 'Blocked queries', cell: (r) => (r.blocks ?? 0).toLocaleString() },
                            { header: 'Action', cell: (r) => <Badge>{r.action}</Badge> },
                            ...(canManage ? [{ header: '', noExport: true, cell: (r: Live) => blockButton(r.target, kindLabel(r.kind)) }] : []),
                        ]} />
                )}
            </ListPanel>
            {data.day.top.length > 0 && (
                <ListPanel title="Most blocked, 24 hours">
                    <DataTable rows={data.day.top} rowKey={(r) => `${r.kind}:${r.target}`}
                        columns={[
                            { header: 'Target', cell: (r) => <span className="mono">{r.target}</span> },
                            { header: 'Kind', cell: (r) => kindLabel(r.kind) },
                            { header: 'Episodes', cell: (r) => r.episodes },
                            { header: 'Blocked queries', cell: (r) => r.blocks.toLocaleString() },
                            { header: 'Last', cell: (r) => <span className="mono">{r.last_seen}</span> },
                            ...(canManage ? [{ header: '', noExport: true, cell: (r: { target: string; kind: string }) => blockButton(r.target, kindLabel(r.kind)) }] : []),
                        ]} />
                </ListPanel>
            )}
            <ListPanel title="Blocks you added" description="Clients whose queries dnsdist drops, and domains it refuses, on every node.">
                <DataTable rows={data.blocks} rowKey={(r) => r.id} emptyText="None."
                    columns={[
                        { header: 'Blocked', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.value}</span><span className="list-subline">{r.kind === 'client' ? 'client: queries dropped' : 'domain: refused'}</span></div> },
                        { header: 'Reason', cell: (r) => r.reason || '-' },
                        { header: 'Added', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.created_at}</span><span className="list-subline">{r.created_by}</span></div> },
                        { header: 'Until', cell: (r) => r.expires_at ?? 'removed by hand' },
                        ...(canManage ? [{ header: 'Actions', noExport: true, cell: (r: Block) => <button type="button" className="link danger-text" onClick={() => void unblock(r)}>Unblock</button> }] : []),
                    ]} />
            </ListPanel>
            <History />
            {canManage && <Thresholds key={JSON.stringify(data.config)} config={data.config} onSaved={(config) => setData({ ...data, config })} />}
            {blocking && <BlockDialog initial={blocking} canFirewall={can('firewall.manage')} onClose={() => setBlocking(null)} onDone={() => { setBlocking(null); void reload(); }} />}
        </AppLayout>
    );
}
