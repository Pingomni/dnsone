// Settings → Cluster (DNSOne Pro): the nodes sharing this database and the BIND secondaries.
import { useState } from 'react';
import { useToast } from '@/components/dns/feedback';
import { Sheet } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Badge, Empty, ErrorSummary, Field, FormActions, TextArea } from '@/components/ui';
import { ApiError, put, useApi } from '@/lib/api';

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
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
