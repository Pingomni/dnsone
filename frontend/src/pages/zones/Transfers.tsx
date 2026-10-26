// Zone → Transfers (1.5): the customer's own secondaries that may transfer the zone, and its transfer key.
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import type { ZoneRow } from '@/components/dns/zone';
import Icon from '@/components/Icon';
import { DataTable } from '@/components/table';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select } from '@/components/ui';
import { ApiError, del, post, put, useApi } from '@/lib/api';

type Transfer = { id: number; address: string; notify: boolean; notify_port: number; network: boolean; comment: string; created_by: string; created_at: string };
type Key = { enabled: boolean; name: string | null; algorithm: string | null; secret?: string };
type State = { rows: Transfer[]; key: Key; max: number };

const ALGORITHMS = ['hmac-sha256', 'hmac-sha512', 'hmac-sha384', 'hmac-sha224', 'hmac-sha1'];

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

function AddDialog({ zone, onClose, onAdded }: { zone: ZoneRow; onClose: () => void; onAdded: () => void }) {
    const [form, setForm] = useState({ address: '', notify: true, notify_port: '53', comment: '' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const network = form.address.includes('/');
    return (
        <FormDialog open title="Allow a secondary" submitLabel="Allow" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                await post(`/api/zones/${zone.id}/transfers`, { ...form, notify: form.notify && !network, notify_port: Number(form.notify_port) || 53 });
                onAdded();
            } catch (e) {
                setErrors(errorsOf(e, 'address'));
            } finally {
                setBusy(false);
            }
        }}>
            <ErrorSummary errors={errors} />
            <div className="form-grid">
                <Field label="Secondary's address" name="address" required spellCheck={false} placeholder="198.51.100.53 or 2001:db8::/64" value={form.address} error={errors.address}
                    hint="The address it transfers from; a network for several servers." onChange={(e) => setForm({ ...form, address: e.target.value })} />
                <Field label="Comment" name="comment" placeholder="ns2 at the customer's office" value={form.comment} onChange={(e) => setForm({ ...form, comment: e.target.value })} />
                <div className="span2 inline-actions">
                    <Check label="Notify it when the zone changes" disabled={network} checked={form.notify && !network} onChange={(e) => setForm({ ...form, notify: e.target.checked })} />
                    {form.notify && !network && <Field label="Notify port" name="notify_port" type="number" min={1} max={65535} value={form.notify_port} onChange={(e) => setForm({ ...form, notify_port: e.target.value })} />}
                </div>
                {network && <p className="hint">Networks can transfer but are not notified: the secondary checks the serial every SOA refresh ({zone.soa_refresh} s).</p>}
            </div>
        </FormDialog>
    );
}

function KeyShown({ zone, k, onClose }: { zone: ZoneRow; k: Key; onClose: () => void }) {
    return (
        <FormDialog open title={`Transfer key ${k.name}`} submitLabel="Done" onClose={onClose} onSubmit={onClose}>
            <p>Copy the secret now: it is not shown again (a new one can be made later). Give it to whoever runs the secondaries.</p>
            <code className="secret-once">{k.secret}</code>
            <h3 className="form-section-title">On a BIND secondary</h3>
            <pre className="zone-preview">{`key "${k.name}" {\n    algorithm ${k.algorithm};\n    secret "${k.secret}";\n};\nserver YOUR-DNS-SERVER-IP { keys { "${k.name}"; }; };\nzone "${zone.name}" {\n    type secondary;\n    primaries { YOUR-DNS-SERVER-IP; };\n    file "${zone.name}.db";\n};`}</pre>
            <h3 className="form-section-title">Check by hand</h3>
            <pre className="zone-preview">{`dig @YOUR-DNS-SERVER-IP ${zone.name} AXFR -y ${k.algorithm}:${k.name}:${k.secret}`}</pre>
        </FormDialog>
    );
}

export function TransfersPanel({ zone, canManage }: { zone: ZoneRow; canManage: boolean }) {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, reload } = useApi<State>(`/api/zones/${zone.id}/transfers`);
    const [adding, setAdding] = useState(false);
    const [shown, setShown] = useState<Key | null>(null);
    const [algorithm, setAlgorithm] = useState('hmac-sha256');
    if (!data) return <Empty>Loading…</Empty>;

    const remove = async (t: Transfer) => {
        if (!(await ask({ title: `Stop transfers to ${t.address}?`, message: 'It can no longer transfer the zone; the copy it has expires after the SOA expire time.', confirmLabel: 'Remove' }))) return;
        try {
            await del(`/api/zones/${zone.id}/transfers/${t.id}`);
            setData({ ...data, rows: data.rows.filter((r) => r.id !== t.id) });
            toast(`${t.address} removed.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const setKey = async (enabled: boolean) => {
        const ok = await ask(enabled
            ? { title: data.key.enabled ? 'Make a new transfer key?' : 'Require a transfer key?', message: 'Secondaries must sign their transfers with the key (TSIG). Those still using an old secret or none stop receiving the zone.', confirmLabel: data.key.enabled ? 'New key' : 'Require a key' }
            : { title: 'Stop requiring the key?', message: 'The listed addresses can transfer the zone without a key.', confirmLabel: 'Stop requiring' });
        if (!ok) return;
        try {
            const next = await put<State>(`/api/zones/${zone.id}/transfers/key`, { enabled, algorithm });
            setData(next);
            if (enabled) setShown(next.key);
            else toast('Transfers no longer need the key.');
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <>
            <p className="hint">Secondaries listed here (e.g. a customer's own name servers) may transfer {zone.name} from this server on port 53, and are notified when it changes. Every other transfer is refused. Up to {data.max} entries.</p>
            {canManage && <div className="toolbar"><button type="button" className="primary" onClick={() => setAdding(true)}><Icon name="plus" />Allow a secondary</button></div>}
            <DataTable
                rows={data.rows}
                rowKey={(r) => r.id}
                emptyText="No secondary may transfer this zone."
                columns={[
                    { header: 'Address', cell: (r) => <span className="mono">{r.address}</span> },
                    { header: 'Notify', cell: (r) => (r.notify ? <>port {r.notify_port}</> : <span className="list-subline">{r.network ? 'networks are not notified' : 'no'}</span>) },
                    { header: 'Comment', cell: (r) => r.comment || '-' },
                    { header: 'Added', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.created_at}</span><span className="list-subline">{r.created_by}</span></div> },
                    ...(canManage ? [{ header: 'Actions', noExport: true, cell: (r: Transfer) => <button type="button" className="link danger-text" onClick={() => void remove(r)}>Remove</button> }] : []),
                ]}
            />
            <h3 className="form-section-title">Transfer key (TSIG)</h3>
            <div className="form-grid">
                <p className="hint">
                    {data.key.enabled
                        ? <>Transfers must be signed with <code>{data.key.name}</code> ({data.key.algorithm}), on top of coming from a listed address. <Badge tone="success">key required</Badge></>
                        : <>Without a key, the address alone decides. A key protects against spoofed addresses on the way. <Badge>no key</Badge></>}
                </p>
                {canManage && (
                    <>
                        <Select label="Algorithm" name="algorithm" options={ALGORITHMS.map((a) => ({ value: a, label: a }))} value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} />
                        <FormActions>
                            <button type="button" className={data.key.enabled ? undefined : 'primary'} onClick={() => void setKey(true)}>{data.key.enabled ? 'Make a new key' : 'Require a key'}</button>
                            {data.key.enabled && <button type="button" className="danger" onClick={() => void setKey(false)}>Stop requiring the key</button>}
                        </FormActions>
                    </>
                )}
            </div>
            {adding && <AddDialog zone={zone} onClose={() => setAdding(false)} onAdded={() => { setAdding(false); toast('Allowed. dnsdist and BIND apply it within a few seconds.'); void reload(); }} />}
            {shown && <KeyShown zone={zone} k={shown} onClose={() => setShown(null)} />}
        </>
    );
}
