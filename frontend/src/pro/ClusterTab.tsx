// SPDX-License-Identifier: Elastic-2.0
// DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
// Settings → Cluster (DNSOne Pro): the nodes sharing this database, setting the cluster up (add a server on the
// primary, join with its key on the new one, leave, remove) and the BIND secondaries.
import { useEffect, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { Sheet } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Badge, Empty, ErrorSummary, Field, FormActions, TextArea } from '@/components/ui';
import { ApiError, del, get, post, put, useApi } from '@/lib/api';

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

type Node = {
    node: string; role: string; version: string; last_seen: string; server_id?: string; stale: boolean; rpz_behind: boolean; policy_serial: number;
    rpz: { serial: number | null; state: string; entries: number | null }; daemons: { recursor_policy: number | null; dnsdist_settings: number | null }; messages: string[];
};
type Secondary = { address: string; port: number; name: string };
type Server = { address: string; name: string; state: string; node: string | null; message: string | null; created: string; key_ready: boolean };
type Status = { action?: string; state?: string; message?: string; log?: string; finished?: string | null };
type Setup = { servers: Server[]; primary: string | null; can_manage: boolean; busy: boolean; standalone: boolean; status: Status };
type Cluster = {
    node: string; role: string; nodes: Node[]; secondaries: Secondary[]; catalog_zone: string; catalog_serial: number | null; stale_minutes: number;
    setup: Setup;
};

const SERVER_STATE: Record<string, [string, string]> = {
    preparing: ['preparing…', 'info'], ready: ['ready to join', 'warning'], joined: ['joined', 'success'], failed: ['failed', 'danger'], left: ['left', ''],
};
const ACTION: Record<string, string> = { add: 'Adding a server', remove: 'Removing a server', join: 'Joining the cluster', leave: 'Leaving the cluster' };
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** What dnsone-cluster did last on this server, with its log while it runs or when it failed. */
function LastChange({ status, busy }: { status: Status; busy: boolean }) {
    if (!status.state && !busy) return null;
    const what = ACTION[status.action ?? ''] ?? 'Cluster change';
    if (busy || status.state === 'running') return <div className="flash panel-text">{what}… {status.log && <pre className="cluster-log">{status.log}</pre>}</div>;
    if (status.state === 'failed') return <div className="flash danger panel-text">{what} failed: {status.message}{status.log && <pre className="cluster-log">{status.log}</pre>}</div>;
    return <p className="hint panel-text">Last change: {status.message}</p>;
}

/** On the primary: the servers added from here, their join keys, and adding one. */
function Servers({ data, reload }: { data: Cluster; reload: () => Promise<void> }) {
    const toast = useToast();
    const ask = useConfirm();
    const { setup } = data;
    const here = window.location.hostname;
    const [form, setForm] = useState({ address: '', name: '', listen: setup.primary ?? (IPV4.test(here) ? here : '') });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [shown, setShown] = useState<{ address: string; key: string } | null>(null);

    const add = async () => {
        try {
            const r = await post<{ message: string }>('/api/cluster/servers', form);
            setErrors({});
            setForm({ ...form, address: '', name: '' });
            toast(r.message);
            void reload();
        } catch (e) {
            setErrors(errorsOf(e, 'address'));
        }
    };
    const showKey = async (s: Server) => {
        try {
            setShown({ address: s.address, key: (await get<{ key: string }>(`/api/cluster/servers/${s.address}/key`)).key });
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const remove = async (s: Server) => {
        const ok = await ask({
            title: `Remove ${s.address} from the cluster?`,
            message: s.state === 'joined'
                ? 'Its database account is removed, so it stops syncing and its console stops working. Use Leave the cluster on that server first to give it back its own configuration.'
                : 'Its database account is removed; its join key stops working.',
            confirmLabel: 'Remove',
        });
        if (!ok) return;
        try {
            toast((await del<{ message: string }>(`/api/cluster/servers/${s.address}`)).message);
            if (shown?.address === s.address) setShown(null);
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <Sheet title="Servers in this cluster" icon="server" meta={setup.primary ? <Badge>primary at {setup.primary}</Badge> : undefined}>
            {!setup.can_manage && <div className="flash warning panel-text">Setting up the cluster from the console is not ready on this server yet: update it once (Settings → Overview → Software update).</div>}
            <LastChange status={setup.status} busy={setup.busy} />
            {setup.servers.length > 0 && (
                <DataTable
                    rows={setup.servers}
                    rowKey={(r) => r.address}
                    columns={[
                        { header: 'Server', cell: (r) => <div className="list-cell-stack"><span>{r.address}</span>{r.name && <span className="list-subline">{r.name}</span>}</div> },
                        {
                            header: 'State', className: 'cell-wrap',
                            cell: (r) => <>{(() => { const [label, tone] = SERVER_STATE[r.state] ?? [r.state, '']; return <Badge tone={tone}>{label}</Badge>; })()} {r.message && <span className="list-subline">{r.message}</span>}</>,
                        },
                        { header: 'Node', cell: (r) => r.node ?? '-' },
                        {
                            header: '', cell: (r) => (
                                <span className="inline-actions">
                                    {r.key_ready && <button type="button" onClick={() => void showKey(r)}>Join key</button>}
                                    <button type="button" className="danger" disabled={setup.busy} onClick={() => void remove(r)}>Remove</button>
                                </span>
                            ),
                        },
                    ]}
                />
            )}
            {shown && (
                <div className="panel-text">
                    <TextArea label={`Join key for ${shown.address}`} rows={4} readOnly spellCheck={false} value={shown.key}
                        onFocus={(e) => e.target.select()}
                        hint="On that server: Settings → Cluster → Join a cluster, paste this key. It holds the password of that server's database account: keep it to yourself." />
                    <FormActions>
                        <button type="button" className="primary" onClick={() => void navigator.clipboard?.writeText(shown.key).then(() => toast('Join key copied.'))}>Copy</button>
                        <button type="button" onClick={() => setShown(null)}>Hide</button>
                    </FormActions>
                </div>
            )}
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void add(); }}>
                <Field label="New server's address" required spellCheck={false} placeholder="10.0.0.12" value={form.address} error={errors.address}
                    hint="A server with DNSOne installed, at the same version as this one." onChange={(e) => setForm({ ...form, address: e.target.value })} />
                <Field label="Name" spellCheck={false} placeholder="ns2" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Field label="This server's address" required spellCheck={false} placeholder="10.0.0.11" value={form.listen} error={errors.listen}
                    hint="The new server reaches this one's database (3306) and BIND (5301) here; both are opened to it alone." onChange={(e) => setForm({ ...form, listen: e.target.value })} />
                <FormActions><button className="primary" disabled={setup.busy || !setup.can_manage}>Add server</button></FormActions>
            </form>
            <p className="hint panel-text">
                Adding a server creates a database account only that address may use, over TLS only, and shows its join key here. Then join on the new server.
                With ufw or Settings → Firewall on, the ports are opened to the server by themselves; without a firewall, MySQL listens on this address for everyone (only the cluster's accounts can sign in).
            </p>
        </Sheet>
    );
}

/** On a server on its own: becomes a replica with a key from the primary. */
function Join({ setup }: { setup: Setup }) {
    const toast = useToast();
    const ask = useConfirm();
    const [key, setKey] = useState('');
    const [error, setError] = useState('');
    const join = async () => {
        const ok = await ask({
            title: 'Join this server to the cluster?',
            message: 'It becomes a replica: from now on it uses the primary\'s database, so its own users, zones and settings are set aside (they come back if it leaves). '
                + 'BIND and DNSOne restart; DNS keeps answering. The console restarts too: then sign in with the primary\'s accounts.',
            confirmLabel: 'Join cluster',
        });
        if (!ok) return;
        try {
            toast((await post<{ message: string }>('/api/cluster/join', { key })).message);
            setError('');
        } catch (e) {
            setError((e as ApiError).message);
        }
    };
    return (
        <Sheet title="Join a cluster" icon="services">
            <LastChange status={setup.status.action === 'join' || setup.status.action === 'leave' ? setup.status : {}} busy={setup.busy} />
            <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void join(); }}>
                <TextArea label="Join key" rows={4} spellCheck={false} placeholder="DNSONE-JOIN1.…" value={key} error={error} onChange={(e) => setKey(e.target.value)}
                    hint="On the primary: Settings → Cluster → Add server with this server's address, then Join key." />
                <FormActions><button className="primary" disabled={!key.trim() || setup.busy || !setup.can_manage}>Join cluster</button></FormActions>
            </form>
        </Sheet>
    );
}

/** On a replica: its primary, and leaving. */
function Replica({ setup }: { setup: Setup }) {
    const toast = useToast();
    const ask = useConfirm();
    const leave = async () => {
        const ok = await ask({
            title: 'Leave the cluster?',
            message: 'This server goes back to its own database and zones, as they were when it joined. BIND and DNSOne restart; the console restarts too: then sign in with this server\'s own accounts. '
                + 'Remove it on the primary afterwards.',
            confirmLabel: 'Leave cluster',
        });
        if (!ok) return;
        try {
            toast((await post<{ message: string }>('/api/cluster/leave')).message);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <Sheet title="This server is a replica" icon="services" meta={setup.primary ? <Badge>primary at {setup.primary}</Badge> : undefined}>
            <LastChange status={setup.status} busy={setup.busy} />
            <p className="panel-text">It uses the primary's database and its BIND is a secondary of the primary's: change anything here or on the primary, every server takes it within 30 seconds.</p>
            <FormActions><button type="button" disabled={setup.busy || !setup.can_manage} onClick={() => void leave()}>Leave the cluster</button></FormActions>
        </Sheet>
    );
}

/** Without the cluster feature (no licence on this server): join a cluster with its licence, or leave it. */
export function JoinOnlyTab() {
    const { data, error, reload } = useApi<{ node: string; role: string; setup: Setup }>('/api/cluster/join');
    const busy = Boolean(data?.setup.busy);
    useEffect(() => {
        if (!busy) return undefined;
        const timer = window.setInterval(() => void reload(), 2000);
        return () => window.clearInterval(timer);
    }, [busy, reload]);
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    if (data.role === 'replica') return <Replica setup={data.setup} />;
    return (
        <>
            <Join setup={data.setup} />
            <p className="hint panel-text">
                This server runs DNSOne Community. It can join a cluster: it then runs with the cluster's DNSOne Pro licence, if that covers
                one more server. Creating a cluster (adding servers to this one) needs a DNSOne Pro licence on this server (Settings → License).
            </p>
        </>
    );
}

export function ClusterTab() {
    const toast = useToast();
    const { data, error, reload } = useApi<Cluster>('/api/cluster');
    const busy = Boolean(data?.setup.busy || data?.setup.servers.some((s) => s.state === 'preparing'));
    useEffect(() => {
        if (!busy) return undefined;
        // Follows dnsone-cluster; a join or leave restarts the API (and ends the session) on the way.
        const timer = window.setInterval(() => void reload(), 2000);
        return () => window.clearInterval(timer);
    }, [busy, reload]);
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
                        { header: 'Node', cell: (r) => <div className="list-cell-stack"><span>{r.node}</span><span className="list-subline">{r.role}, DNSOne {r.version}{r.server_id && <>, <span className="mono">{r.server_id}</span></>}</span></div> },
                        { header: 'Last sync', cell: (r) => <>{r.last_seen.replace('T', ' ')} UTC {r.stale && <Badge tone="danger">not syncing</Badge>}</> },
                        { header: 'RPZ', cell: (r) => <>{r.rpz.state} {r.rpz.serial ?? ''} {r.rpz_behind && <Badge tone="warning">behind</Badge>}</> },
                        { header: 'Recursor policy', cell: (r) => (r.daemons.recursor_policy === r.policy_serial ? <Badge tone="success">current</Badge> : <Badge tone="warning">{r.daemons.recursor_policy === null ? 'not loaded' : 'older'}</Badge>) },
                        { header: 'dnsdist settings', cell: (r) => (r.daemons.dnsdist_settings !== null ? <Badge tone="success">reporting</Badge> : <Badge tone="warning">not loaded</Badge>) },
                        { header: 'Last messages', className: 'cell-wrap', cell: (r) => r.messages.slice(-2).join('; ') || '-' },
                    ]}
                />
                <p className="hint panel-text">Every node shares this MySQL database and builds its own RPZ and runtime files from it. Replicas (DNSONE_ROLE=replica) never publish zones: their BIND is a secondary of this primary.</p>
            </Sheet>
            {data.role === 'primary' && <Servers data={data} reload={reload} />}
            {data.setup.standalone && data.nodes.length <= 1 && <Join setup={data.setup} />}
            {data.role === 'replica' && <Replica setup={data.setup} />}
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
                        hint="One per line: address, optional port (5301), # name. The primary notifies them, lets them transfer, and serves a catalog zone so they add and drop zones by themselves. Servers added above are here already; add other BIND servers by hand."
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
