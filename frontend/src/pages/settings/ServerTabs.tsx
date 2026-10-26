// Settings → DNS server, Privacy, Backup and Cluster.
import { useState } from 'react';
import { DownloadLink, useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { SettingsRows, Sheet } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select, TextArea } from '@/components/ui';
import { ApiError, del, post, put, useApi } from '@/lib/api';

type Server = {
    client_networks: string[]; nat_addresses: string[]; client_qps: number; client_burst: number; nat_qps: number; nat_burst: number;
    public_authoritative: boolean; stored: boolean; loopback: string[]; legacy_file: string; dns64_prefix: string; ddns: 'off' | 'customers' | 'everyone';
};

const lines = (text: string) => text.split('\n').map((l) => l.split('#')[0].trim()).filter(Boolean);

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

export function DnsServerTab() {
    const toast = useToast();
    const { data, error } = useApi<Server>('/api/settings/dns-server');
    const resolver = useApi<Resolver>('/api/settings/resolver');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    return (
        <>
            <ServerForm key={JSON.stringify(data)} data={data} onSaved={() => toast('Saved. dnsdist and the Recursor apply it within 2 seconds.')} />
            {resolver.data && <ResolverForm key={JSON.stringify(resolver.data)} data={resolver.data} onSaved={resolver.setData} />}
        </>
    );
}

type Resolver = { serve_stale_hours: number; max_stale_hours: number; ecs: { enabled: boolean; domains: string[]; ipv4_bits: number; ipv6_bits: number } };

/** Settings → DNS server → Resolver: serve-stale and EDNS Client Subnet (the Recursor restarts to apply them). */
function ResolverForm({ data, onSaved }: { data: Resolver; onSaved: (r: Resolver) => void }) {
    const toast = useToast();
    const ask = useConfirm();
    const [form, setForm] = useState({ stale: String(data.serve_stale_hours), enabled: data.ecs.enabled, domains: data.ecs.domains.join('\n'), v4: String(data.ecs.ipv4_bits), v6: String(data.ecs.ipv6_bits) });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const listError = Object.entries(errors).find(([k]) => k.startsWith('ecs.domains'))?.[1];
    return (
        <Sheet title="Resolver" icon="refresh" meta={<>{data.serve_stale_hours ? <Badge tone="success">serve-stale {data.serve_stale_hours} h</Badge> : <Badge>serve-stale off</Badge>} {data.ecs.enabled ? <Badge tone="info">ECS on</Badge> : null}</>}>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                if (!(await ask({ title: 'Restart the Recursor?', message: 'It reads these settings only at start: it restarts on every node within a minute, and its cache starts empty (answers are a little slower for a few minutes).', confirmLabel: 'Save and restart' }))) return;
                setBusy(true);
                try {
                    const saved = await put<Resolver>('/api/settings/resolver', {
                        serve_stale_hours: Number(form.stale) || 0,
                        ecs: { enabled: form.enabled, domains: lines(form.domains), ipv4_bits: Number(form.v4), ipv6_bits: Number(form.v6) },
                    });
                    setErrors({});
                    onSaved(saved);
                    toast('Saved. The Recursor restarts with them.');
                } catch (err) {
                    setErrors(errorsOf(err, 'serve_stale_hours'));
                } finally {
                    setBusy(false);
                }
            }}>
                <Field label="Serve stale answers for (hours)" name="serve_stale_hours" type="number" min={0} max={data.max_stale_hours} value={form.stale} error={errors.serve_stale_hours}
                    hint="When a domain's name servers cannot be reached, customers keep getting its last answers this long (RFC 8767). 0: off."
                    onChange={(e) => setForm({ ...form, stale: e.target.value })} />
                <div className="span2">
                    <Check label="EDNS Client Subnet: send the customer's subnet to these domains' name servers (CDNs answer with a server near the customer)" checked={form.enabled}
                        onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                </div>
                {form.enabled && (
                    <>
                        <TextArea label="Domains" name="ecs_domains" rows={5} spellCheck={false} value={form.domains} error={listError}
                            hint="One per line, e.g. akamaiedge.net, cloudfront.net; every name below each is included. Only listed domains get the subnet (privacy). Private and CGNAT customer addresses are never sent."
                            onChange={(e) => setForm({ ...form, domains: e.target.value })} />
                        <Field label="IPv4 prefix sent" name="ipv4_bits" type="number" min={8} max={32} value={form.v4} error={errors['ecs.ipv4_bits']} hint="24 (a /24) is usual." onChange={(e) => setForm({ ...form, v4: e.target.value })} />
                        <Field label="IPv6 prefix sent" name="ipv6_bits" type="number" min={16} max={128} value={form.v6} error={errors['ecs.ipv6_bits']} hint="56 is usual." onChange={(e) => setForm({ ...form, v6: e.target.value })} />
                    </>
                )}
                <FormActions><button className="primary" disabled={busy}>Save</button></FormActions>
            </form>
        </Sheet>
    );
}

function ServerForm({ data, onSaved }: { data: Server; onSaved: () => void }) {
    const [form, setForm] = useState({ ...data, networks: data.client_networks.join('\n'), nat: data.nat_addresses.join('\n') });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const number = (key: 'client_qps' | 'client_burst' | 'nat_qps' | 'nat_burst', label: string) => (
        <Field label={label} name={key} type="number" min={1} required value={form[key]} error={errors[key]} onChange={(e) => setForm({ ...form, [key]: Number(e.target.value) })} />
    );
    // Errors for list entries come back as client_networks.3: show them on the textarea.
    const listError = (field: string) => Object.entries(errors).find(([k]) => k === field || k.startsWith(`${field}.`))?.[1];
    return (
        <Sheet title="DNS server" icon="server" meta={data.stored ? <Badge tone="success">managed here</Badge> : <Badge tone="warning">from {data.legacy_file}</Badge>}>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                    await put('/api/settings/dns-server', {
                        client_networks: lines(form.networks), nat_addresses: lines(form.nat), public_authoritative: form.public_authoritative,
                        client_qps: form.client_qps, client_burst: form.client_burst, nat_qps: form.nat_qps, nat_burst: form.nat_burst,
                        dns64_prefix: form.dns64_prefix, ddns: form.ddns,
                    });
                    setErrors({});
                    onSaved();
                } catch (err) {
                    setErrors(errorsOf(err, 'client_networks'));
                } finally {
                    setBusy(false);
                }
            }}>
                <TextArea label="Customer networks" name="client_networks" rows={8} spellCheck={false} value={form.networks} error={listError('client_networks')}
                    hint={`One per line. Only these may use the resolver (recursion and ad-blocking). ${data.loopback.join(' and ')} are always allowed.`}
                    onChange={(e) => setForm({ ...form, networks: e.target.value })} />
                <TextArea label="NAT addresses" name="nat_addresses" rows={8} spellCheck={false} value={form.nat} error={listError('nat_addresses')}
                    hint="CGNAT or NAT gateways that carry many homes each: they get the NAT rate limit and are never dynamically blocked."
                    onChange={(e) => setForm({ ...form, nat: e.target.value })} />
                {number('client_qps', 'Queries per second, per customer address')}
                {number('client_burst', 'Burst, per customer address')}
                {number('nat_qps', 'Queries per second, per NAT address')}
                {number('nat_burst', 'Burst, per NAT address')}
                <div className="span2">
                    <Check label="Public authoritative DNS: anyone on the internet may ask for the zones hosted here (nothing else)" checked={form.public_authoritative}
                        onChange={(e) => setForm({ ...form, public_authoritative: e.target.checked })} />
                </div>
                <p className="span2 hint">Rates are per IPv4 address or IPv6 /64; queries above them are dropped. Listen addresses stay in /etc/dnsdist/dnsdist.conf (they need a restart).</p>
                <Field label="DNS64 prefix" name="dns64_prefix" spellCheck={false} required value={form.dns64_prefix} error={errors.dns64_prefix}
                    hint="A /96 your NAT64 gateway translates; 64:ff9b::/96 is the well-known one. Used for client groups with DNS64 on." onChange={(e) => setForm({ ...form, dns64_prefix: e.target.value })} />
                <Select label="Dynamic DNS updates (RFC 2136)" name="ddns" value={form.ddns} error={errors.ddns}
                    hint="Signed updates with a zone's keys (Zone → Dynamic DNS). Unsigned ones are always refused."
                    options={[{ value: 'off', label: 'Off' }, { value: 'customers', label: 'From customer networks' }, { value: 'everyone', label: 'From anywhere (the key decides)' }]}
                    onChange={(e) => setForm({ ...form, ddns: e.target.value as Server['ddns'] })} />
                <FormActions><button className="primary" disabled={busy}>Save</button></FormActions>
            </form>
        </Sheet>
    );
}

type Privacy = { level: number; retention_hours: number; max_retention_hours: number; mode: string; levels: { level: number; label: string }[] };

export function PrivacyTab() {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, error } = useApi<Privacy>('/api/settings/privacy');
    const [errors, setErrors] = useState<Record<string, string>>({});
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    const erase = async (stats: boolean) => {
        if (!(await ask({ title: stats ? 'Erase the query log and statistics?' : 'Erase the query log?', message: stats ? 'Every stored query, top list and history is deleted.' : 'Every stored query is deleted; top lists and history stay.', confirmLabel: 'Erase', typeToConfirm: 'erase' }))) return;
        try {
            const r = await del<{ rows: number; counters: number }>(`/api/queries${stats ? '?stats=true' : ''}`);
            toast(`${r.rows.toLocaleString()} queries erased${stats ? `, and ${r.counters.toLocaleString()} counters` : ''}.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <>
            <Sheet title="Query log privacy" icon="lock" meta={<Badge>{data.mode === 'full' ? 'query log on' : data.mode === 'aggregate' ? 'totals only (server setting)' : 'off (server setting)'}</Badge>}>
                <form className="form-grid" onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                        setData(await put<Privacy>('/api/settings/privacy', { level: data.level, retention_hours: data.retention_hours }));
                        setErrors({});
                        toast('Saved. dnsone-querylog applies it within 15 seconds, to new queries.');
                    } catch (err) {
                        setErrors(errorsOf(err, 'level'));
                    }
                }}>
                    <Select label="What is kept" name="level" options={data.levels.map((l) => ({ value: String(l.level), label: l.label }))} value={String(data.level)} error={errors.level}
                        hint="Hidden values are stored as “hidden”. Queries already stored keep their detail until they expire or are erased."
                        onChange={(e) => setData({ ...data, level: Number(e.target.value) })} />
                    <Field label="Keep queries for (hours)" name="retention_hours" type="number" min={1} max={data.max_retention_hours} required value={data.retention_hours} error={errors.retention_hours}
                        hint={`At most ${data.max_retention_hours} hours on this server (DNSONE_QUERYLOG_RETENTION_HOURS).`}
                        onChange={(e) => setData({ ...data, retention_hours: Number(e.target.value) })} />
                    <FormActions><button className="primary">Save</button></FormActions>
                </form>
            </Sheet>
            <Sheet title="Erase now" icon="logs">
                <div className="inline-actions panel-text">
                    <button type="button" className="danger" onClick={() => void erase(false)}>Erase the query log</button>
                    <button type="button" className="danger" onClick={() => void erase(true)}>Erase the log and statistics</button>
                </div>
            </Sheet>
        </>
    );
}

const SECTION_LABELS: Record<string, string> = { zones: 'Zones and records', ad_blocking: 'Ad-blocking: lists, groups, rules, block policy', settings: 'Settings: DNS server, privacy' };
type Report = { zones: number; blocklists: number; groups: number; networks: number; rules: number; settings: string[]; skipped: string[]; skipped_count: number };

export function BackupTab() {
    const toast = useToast();
    const ask = useConfirm();
    const [download, setDownload] = useState<string[]>(Object.keys(SECTION_LABELS));
    const [file, setFile] = useState<{ name: string; data: Record<string, unknown> } | null>(null);
    const [restore, setRestore] = useState<string[]>([]);
    const [report, setReport] = useState<Report | null>(null);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const toggle = (list: string[], key: string, on: boolean) => (on ? [...list, key] : list.filter((k) => k !== key));
    const href = `/api/settings/backup?${download.map((s) => `sections=${s}`).join('&')}`;
    return (
        <>
            <Sheet title="Download a backup" icon="server">
                <div className="form-grid">
                    <fieldset className="span2 group-picks">
                        <legend>Include</legend>
                        {Object.entries(SECTION_LABELS).map(([k, label]) => <Check key={k} label={label} checked={download.includes(k)} onChange={(e) => setDownload(toggle(download, k, e.target.checked))} />)}
                    </fieldset>
                    <p className="span2 hint">A JSON file. Operators, passwords, app passwords, the audit log and the query log are never included. The nightly dnsone-backup timer keeps full database backups on the server.</p>
                    <FormActions>{download.length ? <DownloadLink className="button primary" href={href}>Download</DownloadLink> : <button type="button" disabled>Download</button>}</FormActions>
                </div>
            </Sheet>
            <Sheet title="Restore" icon="refresh">
                <div className="form-grid">
                    <label className="span2">
                        <span>Backup file</span>
                        <input type="file" accept="application/json,.json" onChange={async (e) => {
                            setReport(null);
                            setError('');
                            const chosen = e.target.files?.[0];
                            if (!chosen) return setFile(null);
                            try {
                                const data = JSON.parse(await chosen.text()) as Record<string, unknown>;
                                if (data.dnsone_backup !== 1) throw new Error('not a DNSOne backup');
                                setFile({ name: chosen.name, data });
                                setRestore((data.sections as string[]) ?? []);
                            } catch {
                                setFile(null);
                                setError('This file is not a DNSOne backup.');
                            }
                        }} />
                        {error && <small className="field-error">{error}</small>}
                    </label>
                    {file && (
                        <>
                            <p className="span2 hint">From {String(file.data.node)}, {String(file.data.created_at)} (DNSOne {String(file.data.version)}).</p>
                            <fieldset className="span2 group-picks">
                                <legend>Replace</legend>
                                {((file.data.sections as string[]) ?? []).map((k) => <Check key={k} label={SECTION_LABELS[k] ?? k} checked={restore.includes(k)} onChange={(e) => setRestore(toggle(restore, k, e.target.checked))} />)}
                            </fieldset>
                            <FormActions>
                                <button type="button" className="danger" disabled={busy || !restore.length} onClick={async () => {
                                    if (!(await ask({ title: 'Restore this backup?', message: `Everything in: ${restore.map((k) => SECTION_LABELS[k]).join('; ')} is replaced by the backup's copy. Zones are republished and lists downloaded again.`, confirmLabel: 'Restore', typeToConfirm: 'restore' }))) return;
                                    setBusy(true);
                                    try {
                                        const r = await post<Report>('/api/settings/restore', { backup: file.data, sections: restore });
                                        setReport(r);
                                        toast('Backup restored.');
                                    } catch (err) {
                                        toast((err as ApiError).message, 'danger');
                                    } finally {
                                        setBusy(false);
                                    }
                                }}>{busy ? 'Restoring…' : 'Restore'}</button>
                            </FormActions>
                        </>
                    )}
                    {report && (
                        <div className="span2">
                            <SettingsRows rows={[
                                ['Zones', report.zones], ['Lists', report.blocklists], ['Groups', report.groups], ['Client networks', report.networks], ['Rules', report.rules],
                                ['Settings', report.settings.join(', ') || '-'], ['Skipped', report.skipped_count],
                            ]} />
                            {report.skipped.length > 0 && <pre className="publish-error">{report.skipped.join('\n')}</pre>}
                        </div>
                    )}
                </div>
            </Sheet>
        </>
    );
}

type Node = {
    node: string; role: string; version: string; last_seen: string; stale: boolean; rpz_behind: boolean; policy_serial: number;
    rpz: { serial: number | null; state: string; entries: number | null }; daemons: { recursor_policy: number | null; dnsdist_settings: number | null }; messages: string[];
};
type Secondary = { address: string; port: number; name: string };
type Cluster = { node: string; role: string; nodes: Node[]; secondaries: Secondary[]; catalog_zone: string; catalog_serial: number | null; stale_minutes: number };

export function ClusterTab() {
    const toast = useToast();
    const { data, error, reload } = useApi<Cluster>('/api/cluster');
    const [text, setText] = useState<string | null>(null);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [primary, setPrimary] = useState('');
    const [snippet, setSnippet] = useState('');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    const value = text ?? data.secondaries.map((s) => `${s.address}${s.port !== 5301 ? ` ${s.port}` : ''}${s.name ? ` # ${s.name}` : ''}`).join('\n');
    return (
        <>
            <Sheet title="Nodes" icon="server" meta={<Badge>this node: {data.node} ({data.role})</Badge>}>
                <DataTable
                    rows={data.nodes}
                    rowKey={(r) => r.node}
                    emptyText="No node has synced yet: dnsone-sync.timer runs dnsone-ctl sync every 30 seconds."
                    columns={[
                        { header: 'Node', cell: (r) => <div className="list-cell-stack"><span>{r.node}</span><span className="list-subline">{r.role}, DNSOne {r.version}</span></div> },
                        { header: 'Last sync', cell: (r) => <>{r.last_seen.replace('T', ' ')} UTC {r.stale && <Badge tone="danger">not syncing</Badge>}</> },
                        { header: 'RPZ', cell: (r) => <>{r.rpz.state} {r.rpz.serial ?? ''} {r.rpz_behind && <Badge tone="warning">behind</Badge>}</> },
                        { header: 'Recursor policy', cell: (r) => (r.daemons.recursor_policy === r.policy_serial ? <Badge tone="success">current</Badge> : <Badge tone="warning">{r.daemons.recursor_policy === null ? 'not loaded' : 'older'}</Badge>) },
                        { header: 'dnsdist settings', cell: (r) => (r.daemons.dnsdist_settings !== null ? <Badge tone="success">reporting</Badge> : <Badge tone="warning">not loaded</Badge>) },
                        { header: 'Last messages', className: 'cell-wrap', cell: (r) => r.messages.slice(-2).join('; ') || '-' },
                    ]}
                />
                <p className="hint panel-text">Every node shares this MySQL database and builds its own RPZ and runtime files from it. Replicas (DNSONE_ROLE=replica) never publish zones: their BIND is a secondary of this primary.</p>
            </Sheet>
            <Sheet title="BIND secondaries" icon="services" meta={data.catalog_serial ? <Badge>catalog {data.catalog_zone} serial {data.catalog_serial}</Badge> : <Badge>no catalog</Badge>}>
                <ErrorSummary errors={errors} />
                <form className="form-grid" onSubmit={async (e) => {
                    e.preventDefault();
                    // "address [port] # name" per line.
                    const servers = value.split('\n').filter((l) => l.split('#')[0].trim()).map((l) => {
                        const [left, ...comment] = l.split('#');
                        const [address, port] = left.trim().split(/\s+/);
                        return { address, port: port ? Number(port) : 5301, name: comment.join('#').trim() };
                    });
                    try {
                        await put('/api/cluster/secondaries', { servers });
                        setText(null);
                        setErrors({});
                        toast(servers.length ? 'Saved. Secondaries are notified and may transfer every zone.' : 'Saved. No secondaries: the catalog zone is removed.');
                        void reload();
                    } catch (err) {
                        setErrors(errorsOf(err, 'servers'));
                    }
                }}>
                    <TextArea label="Secondaries" rows={5} spellCheck={false} placeholder={'10.0.0.12          # ns2\n10.0.0.13 5301     # ns3'} value={value}
                        hint="One per line: address, optional port (5301), # name. The primary notifies them, lets them transfer, and serves a catalog zone so they add and drop zones by themselves."
                        onChange={(e) => setText(e.target.value)} />
                    <FormActions><button className="primary">Save secondaries</button></FormActions>
                </form>
                <form className="inline-form panel-text" onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                        setSnippet(await fetch(`/api/cluster/secondary-config?primary=${encodeURIComponent(primary)}`, { credentials: 'same-origin' }).then((r) => {
                            if (!r.ok) throw new Error('Enter the primary\'s IP address.');
                            return r.text();
                        }));
                    } catch (err) {
                        toast((err as Error).message, 'danger');
                    }
                }}>
                    <Field label="Configuration for a secondary: this primary's address" required spellCheck={false} placeholder="10.0.0.11" value={primary} onChange={(e) => setPrimary(e.target.value)} />
                    <button>Show</button>
                </form>
                {snippet && <pre className="zone-preview">{snippet}</pre>}
            </Sheet>
        </>
    );
}
