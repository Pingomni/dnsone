import { Link, router, usePage } from '@inertiajs/react';
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable } from '@/components/table';
import { Badge, Check, Empty, Field, FormActions, ListPanel, Panel, TextArea } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, del, get, patch, post, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import type { Paginated } from '@/lib/types';

type ListRef = { id: number; name: string; kind: 'block' | 'allow'; enabled: boolean; domain_count: number };
type Network = { id: number; network: string; comment: string; created_at: string };
type Group = {
    id: number; name: string; description: string; blocking: boolean; built_in: boolean; networks: number; blocklists: ListRef[];
    rules: number; regex_rules: number; entries: number | null; network_list?: Network[];
};
type Found = { client: string; group: { id: number; name: string; blocking: boolean }; network: string | null };

function GroupDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
    const toast = useToast();
    const [form, setForm] = useState({ name: '', description: '', blocking: true });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <FormDialog open={open} title="New client group" submitLabel="Create group" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                const g = await post<Group>('/api/groups', form);
                toast(`${g.name} created. Add its clients and lists next.`);
                router.get('/groups', { id: String(g.id) });
            } catch (e) {
                const ae = e as ApiError;
                setErrors(Object.keys(ae.errors).length ? ae.errors : { name: ae.message });
            } finally {
                setBusy(false);
            }
        }}>
            <div className="form-grid">
                <Field label="Name" name="name" required placeholder="Family filter, Business, No filtering" value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Field label="Description" name="description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                <div className="span2"><Check label="Ad-blocking on for these clients" checked={form.blocking} onChange={(e) => setForm({ ...form, blocking: e.target.checked })} /></div>
            </div>
        </FormDialog>
    );
}

function ClientLookup() {
    const [client, setClient] = useState('');
    const [found, setFound] = useState<Found | null>(null);
    const [error, setError] = useState('');
    return (
        <Panel title="Which group is a client in?">
            <form className="inline-form" onSubmit={async (e) => {
                e.preventDefault();
                try {
                    setFound(await get<Found>(`/api/groups/lookup?client=${encodeURIComponent(client)}`));
                    setError('');
                } catch (err) {
                    setFound(null);
                    setError((err as ApiError).message);
                }
            }}>
                <Field label="Client address" required spellCheck={false} placeholder="192.0.2.15" value={client} error={error || undefined} onChange={(e) => setClient(e.target.value)} />
                <button className="primary">Find</button>
            </form>
            {found && (
                <p className="check-result">
                    <span className="mono">{found.client}</span> is in <Link href={`/groups?id=${found.group.id}`}>{found.group.name}</Link>
                    {found.network ? <> through <span className="mono">{found.network}</span></> : ' (it is in no other group)'}
                    {!found.group.blocking && <> — <Badge tone="warning">no ad-blocking</Badge></>}
                    {' '}<Link href={`/queries?client=${encodeURIComponent(found.client)}`}>Its queries</Link>
                </p>
            )}
        </Panel>
    );
}

function GroupList({ canManage }: { canManage: boolean }) {
    const { data, error } = useApi<{ rows: Group[] }>('/api/groups');
    const [creating, setCreating] = useState(false);
    return (
        <>
            <ListPanel
                title="Client groups"
                description="Each group has its own blocklists, allowlists and rules. A client belongs to the group of its most specific network; clients in no group use Default."
                tools={canManage ? <button type="button" className="primary" onClick={() => setCreating(true)}><Icon name="plus" />New group</button> : undefined}
            >
                {error && <div className="flash danger">{error.message}</div>}
                {data && (
                    <DataTable
                        rows={data.rows}
                        rowKey={(r) => r.id}
                        columns={[
                            { header: 'Group', cell: (r) => <div className="list-cell-stack"><Link href={`/groups?id=${r.id}`}>{r.name}</Link>{r.description && <span className="list-subline">{r.description}</span>}</div> },
                            { header: 'Ad-blocking', cell: (r) => (r.blocking ? <Badge tone="success">on</Badge> : <Badge tone="warning">off</Badge>) },
                            { header: 'Clients', cell: (r) => (r.built_in ? 'everyone else' : `${r.networks.toLocaleString()} ${r.networks === 1 ? 'network' : 'networks'}`) },
                            { header: 'Lists', cell: (r) => r.blocklists.map((b) => b.name).join(', ') || '-' },
                            { header: 'Own rules', cell: (r) => `${r.rules}${r.regex_rules ? ` + ${r.regex_rules} regex` : ''}` },
                            { header: 'Blocked names', cell: (r) => (r.entries === null ? '-' : r.entries.toLocaleString()) },
                        ]}
                    />
                )}
            </ListPanel>
            <ClientLookup />
            <GroupDialog open={creating} onClose={() => setCreating(false)} />
        </>
    );
}

function Settings({ group, canManage, onSaved }: { group: Group; canManage: boolean; onSaved: (g: Group) => void }) {
    const toast = useToast();
    const lists = useApi<Paginated<ListRef>>('/api/rpz/blocklists?size=500');
    const [form, setForm] = useState({ name: group.name, description: group.description, blocking: group.blocking, blocklist_ids: group.blocklists.map((b) => b.id) });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const pick = (id: number, on: boolean) => setForm({ ...form, blocklist_ids: on ? [...form.blocklist_ids, id] : form.blocklist_ids.filter((x) => x !== id) });
    return (
        <Panel title="Settings">
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                    const g = await patch<Group>(`/api/groups/${group.id}`, form);
                    setErrors({});
                    toast(`${g.name} saved. Its clients get the change within a minute.`);
                    onSaved(g);
                } catch (err) {
                    const ae = err as ApiError;
                    setErrors(Object.keys(ae.errors).length ? ae.errors : { name: ae.message });
                } finally {
                    setBusy(false);
                }
            }}>
                <Field label="Name" name="name" required disabled={!canManage || group.built_in} value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Field label="Description" name="description" disabled={!canManage} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                <div className="span2"><Check label="Ad-blocking on for these clients (off: no list, rule or regex applies to them)" disabled={!canManage} checked={form.blocking} onChange={(e) => setForm({ ...form, blocking: e.target.checked })} /></div>
                <fieldset className="span2 group-picks">
                    <legend>Lists this group uses</legend>
                    {lists.data?.rows.map((b) => (
                        <Check key={b.id} disabled={!canManage} checked={form.blocklist_ids.includes(b.id)} onChange={(e) => pick(b.id, e.target.checked)}
                            label={<>{b.name} {b.kind === 'allow' && <Badge tone="success">allowlist</Badge>}{!b.enabled && <Badge tone="warning">off</Badge>}</>} />
                    ))}
                    {lists.data && !lists.data.rows.length && <span className="hint">No lists yet: add them under <Link href="/blocking?tab=blocklists">Ad-blocking → Lists</Link>.</span>}
                </fieldset>
                {canManage && <FormActions><button className="primary" disabled={busy}>Save group</button></FormActions>}
            </form>
        </Panel>
    );
}

function Networks({ group, canManage, onChanged }: { group: Group; canManage: boolean; onChanged: () => void }) {
    const toast = useToast();
    const ask = useConfirm();
    const [form, setForm] = useState({ network: '', comment: '' });
    const [error, setError] = useState('');
    const [importing, setImporting] = useState(false);
    const [text, setText] = useState('');
    const [busy, setBusy] = useState(false);
    if (group.built_in) {
        return <Panel title="Clients"><Empty>The Default group holds every client that is in no other group; it has no networks of its own.</Empty></Panel>;
    }
    const remove = async (n: Network) => {
        if (!(await ask({ title: `Remove ${n.network}?`, message: `Its clients move to Default (or to a group with a wider network) at once.`, confirmLabel: 'Remove' }))) return;
        try {
            await del(`/api/groups/${group.id}/networks/${n.id}`);
            toast(`${n.network} removed.`);
            onChanged();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <ListPanel
            title="Clients"
            description="Addresses and subnets in this group. Changes apply at once; a client in several groups' networks uses the most specific one."
            tools={canManage ? <button type="button" onClick={() => setImporting(true)}>Import list</button> : undefined}
        >
            {canManage && (
                <form className="toolbar list-filterbar" onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                        const n = await post<Network>(`/api/groups/${group.id}/networks`, form);
                        toast(`${n.network} added to ${group.name}.`);
                        setForm({ network: '', comment: '' });
                        setError('');
                        onChanged();
                    } catch (err) {
                        setError((err as ApiError).message);
                    }
                }}>
                    <label className="list-search"><span>Address or subnet</span><input required spellCheck={false} placeholder="192.0.2.0/24, 203.0.113.7 or 2001:db8::/48" value={form.network} aria-invalid={error ? true : undefined} onChange={(e) => setForm({ ...form, network: e.target.value })} /></label>
                    <label className="list-filter"><span>Comment</span><input value={form.comment} placeholder="Customer, contract…" onChange={(e) => setForm({ ...form, comment: e.target.value })} /></label>
                    <div className="list-filter-buttons"><button className="primary">Add</button></div>
                </form>
            )}
            {error && <div className="flash danger">{error}</div>}
            <DataTable
                rows={group.network_list ?? []}
                rowKey={(r) => r.id}
                exportRows
                emptyText="No clients yet: add an address or subnet."
                columns={[
                    { header: 'Network', cell: (r) => <span className="mono">{r.network}</span> },
                    { header: 'Comment', cell: (r) => r.comment },
                    { header: 'Added', cell: (r) => <span className="mono">{r.created_at}</span> },
                    ...(canManage ? [{ header: 'Actions', noExport: true, cell: (r: Network) => <button type="button" className="link danger-text" onClick={() => void remove(r)}>Remove</button> }] : []),
                ]}
            />
            <FormDialog open={importing} title={`Import clients into ${group.name}`} submitLabel="Import" busy={busy} onClose={() => setImporting(false)} onSubmit={async () => {
                setBusy(true);
                try {
                    const r = await post<{ added: number; skipped: string[]; skipped_count: number }>(`/api/groups/${group.id}/networks/import`, { text });
                    toast(`${r.added} added${r.skipped_count ? `, ${r.skipped_count} skipped: ${r.skipped.slice(0, 2).join('; ')}` : ''}.`, r.skipped_count ? 'warning' : 'success');
                    setText('');
                    setImporting(false);
                    onChanged();
                } catch (e) {
                    toast((e as ApiError).message, 'danger');
                } finally {
                    setBusy(false);
                }
            }}>
                <div className="form-grid">
                    <TextArea label="One address or subnet per line" rows={10} spellCheck={false} placeholder={'192.0.2.0/24  # Shop\n2001:db8:10::/48'} hint="Text after # becomes the comment. Networks already in a group are skipped, not moved." value={text} onChange={(e) => setText(e.target.value)} />
                </div>
            </FormDialog>
        </ListPanel>
    );
}

function GroupDetail({ id, canManage }: { id: number; canManage: boolean }) {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, error, reload } = useApi<Group>(`/api/groups/${id}`);
    if (error) return <Empty tone="danger">{error.message} <Link href="/groups">All groups</Link></Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    const remove = async () => {
        if (!(await ask({ title: `Delete ${data.name}?`, message: `Its ${data.networks} network(s) and ${data.rules + data.regex_rules} rule(s) are deleted; its clients move to Default.`, confirmLabel: 'Delete group', typeToConfirm: data.name }))) return;
        try {
            await del(`/api/groups/${data.id}`);
            toast(`${data.name} deleted.`);
            router.get('/groups');
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <>
            <div className="workspace-intro">
                <div className="workspace-actions">
                    <Link className="button" href="/groups">All groups</Link>
                    <Link className="button" href={`/blocking?tab=rules&group=${data.id}`}>{data.name}'s rules</Link>
                    {canManage && !data.built_in && <button type="button" className="danger" onClick={() => void remove()}>Delete group</button>}
                </div>
            </div>
            <Settings key={data.id} group={data} canManage={canManage} onSaved={(g) => setData({ ...data, ...g })} />
            <Networks group={data} canManage={canManage} onChanged={() => void reload()} />
        </>
    );
}

export default function Groups() {
    const can = useCan();
    const { url } = usePage();
    const id = Number(searchOf(url).get('id') ?? 0);
    return (
        <AppLayout title="Client groups">
            {id ? <GroupDetail key={id} id={id} canManage={can('rpz.manage')} /> : <GroupList canManage={can('rpz.manage')} />}
        </AppLayout>
    );
}
