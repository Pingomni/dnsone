// Zone tabs added in 1.4: history (versions and rollback), dynamic DNS keys, applying a template.
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import type { ZoneRow } from '@/components/dns/zone';
import Icon from '@/components/Icon';
import { SettingsRows } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select } from '@/components/ui';
import { ApiError, del, get, patch, post, useApi } from '@/lib/api';
import { query } from '@/lib/format';
import type { Paginated } from '@/lib/types';

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

// --------------------------------------------------------------------------- history

type Snap = { name: string; type: string; value: string; ttl: number | null; priority: number | null; disabled: boolean; comment: string };
type Changes = { added?: number; removed?: number; changed?: number; settings?: string[]; first?: boolean };
type Version = { id: number; serial: number; record_count: number; changes: Changes; actors: string[]; created_at: string };
type Diff = { added: Snap[]; removed: Snap[]; changed: { from: Snap; to: Snap }[]; settings: { field: string; from: unknown; to: unknown }[] };
type VersionDetail = Version & { records: Snap[]; record_total: number; diff: Diff; rollback: Diff & { summary: Changes }; first: boolean };

const line = (r: Snap) => `${r.name}\t${r.ttl ?? ''}\t${r.type}\t${r.priority ?? ''}${r.priority !== null ? ' ' : ''}${r.value}${r.disabled ? '  (disabled)' : ''}`;

function summaryText(c: Changes): string {
    if (c.first) return `first version, ${c.added ?? 0} records`;
    const parts = [];
    if (c.added) parts.push(`${c.added} added`);
    if (c.removed) parts.push(`${c.removed} removed`);
    if (c.changed) parts.push(`${c.changed} changed`);
    if (c.settings?.length) parts.push(`settings: ${c.settings.join(', ')}`);
    return parts.join(', ') || 'no changes';
}

export function DiffView({ diff, empty }: { diff: Diff; empty: string }) {
    const rows = [
        ...diff.settings.map((s) => <span key={`s${s.field}`} className="chg">~ {s.field}: {String(s.from)} → {String(s.to)}{'\n'}</span>),
        ...diff.removed.map((r, i) => <span key={`d${i}`} className="del">- {line(r)}{'\n'}</span>),
        ...diff.added.map((r, i) => <span key={`a${i}`} className="add">+ {line(r)}{'\n'}</span>),
        ...diff.changed.map((c, i) => <span key={`c${i}`} className="chg">~ {line(c.from)}  →  ttl {c.to.ttl ?? 'default'}{c.to.disabled ? ', disabled' : ''}{c.to.comment !== c.from.comment ? `, comment "${c.to.comment}"` : ''}{'\n'}</span>),
    ];
    return rows.length ? <pre className="diff-list">{rows}</pre> : <p className="hint">{empty}</p>;
}

export function HistoryPanel({ zone, canManage, onRestored }: { zone: ZoneRow; canManage: boolean; onRestored: () => void }) {
    const toast = useToast();
    const ask = useConfirm();
    const [page, setPage] = useState('');
    const { data, reload } = useApi<Paginated<Version>>(`/api/zones/${zone.id}/versions${query({ page, size: 25 })}`);
    const [open, setOpen] = useState<VersionDetail | null>(null);
    const show = async (v: Version) => {
        try {
            setOpen(await get<VersionDetail>(`/api/zones/${zone.id}/versions/${v.id}`));
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const restore = async (v: VersionDetail) => {
        const s = v.rollback.summary;
        const ok = await ask({
            title: `Roll ${zone.name} back to serial ${v.serial}?`,
            message: `The zone's records and SOA settings become those of ${v.created_at}: ${summaryText(s)}. This is published at once and is itself kept in the history, so it can be undone.`,
            confirmLabel: 'Roll back',
        });
        if (!ok) return;
        try {
            const r = await post<{ message: string }>(`/api/zones/${zone.id}/versions/${v.id}/restore`);
            toast(r.message);
            setOpen(null);
            void reload();
            onRestored();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    if (!data) return <Empty>Loading…</Empty>;
    return (
        <>
            <p className="hint">Every publish that changed the zone is kept (the last 100): what changed, and who changed it. Rolling back makes the zone's records and SOA settings those of a version, as a new change. Status, DNSSEC and dynamic DNS keys are not part of it.</p>
            <DataTable
                rows={data.rows}
                rowKey={(r) => r.id}
                emptyText="No version yet: the first is kept at the next publish."
                columns={[
                    { header: 'Published', cell: (r, i) => <><span className="mono">{r.created_at}</span>{i === 0 && data.page === 1 && <> <Badge tone="success">live</Badge></>}</> },
                    { header: 'Serial', cell: (r) => <span className="mono">{r.serial}</span> },
                    { header: 'Changes', cell: (r) => summaryText(r.changes) },
                    { header: 'By', cell: (r) => r.actors.join(', ') || '-' },
                    { header: 'Records', cell: (r) => r.record_count.toLocaleString() },
                    { header: 'Actions', noExport: true, cell: (r) => <button type="button" className="link" onClick={() => void show(r)}>Show</button> },
                ]}
            />
            {data.pages > 1 && (
                <nav className="pagination" aria-label="Versions">
                    {Array.from({ length: data.pages }, (_, i) => i + 1).map((p) => (
                        <button key={p} type="button" className={p === data.page ? 'active' : undefined} aria-current={p === data.page ? 'page' : undefined} onClick={() => setPage(String(p))}>{p}</button>
                    ))}
                </nav>
            )}
            {open && (
                <FormDialog open title={`Serial ${open.serial}, published ${open.created_at}`} submitLabel={canManage ? 'Roll back to this version' : 'Close'} onClose={() => setOpen(null)}
                    onSubmit={() => (canManage ? void restore(open) : setOpen(null))}>
                    <h3 className="form-section-title">{open.first ? 'The first version' : 'What this version changed'}</h3>
                    <DiffView diff={open.diff} empty={open.first ? `${open.record_total} records.` : 'Nothing (republished).'} />
                    <h3 className="form-section-title">Rolling back to it now would</h3>
                    <DiffView diff={open.rollback} empty="Change nothing: the zone already matches this version." />
                </FormDialog>
            )}
        </>
    );
}

// --------------------------------------------------------------------------- dynamic DNS

type DdnsKey = { id: number; name: string; algorithm: string; names: string[]; types: string[]; enabled: boolean; comment: string; created_by: string;
    created_at: string; last_used_at: string | null; last_used_ip: string; secret?: string };
type Keys = { rows: DdnsKey[]; mode: 'off' | 'customers' | 'everyone'; types: string[] };

const ALGORITHMS = ['hmac-sha256', 'hmac-sha512', 'hmac-sha384', 'hmac-sha224', 'hmac-sha1'];

function KeyDialog({ zone, types, onClose, onCreated }: { zone: ZoneRow; types: string[]; onClose: () => void; onCreated: (k: DdnsKey) => void }) {
    const [form, setForm] = useState({ name: '', algorithm: 'hmac-sha256', names: '', types: ['A', 'AAAA'], comment: '', secret: '' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const pick = (t: string, on: boolean) => setForm({ ...form, types: on ? [...form.types, t] : form.types.filter((x) => x !== t) });
    return (
        <FormDialog open title="New dynamic DNS key" submitLabel="Create key" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                onCreated(await post<DdnsKey>(`/api/zones/${zone.id}/ddns-keys`, { ...form, names: form.names.split(/[\s,]+/).filter(Boolean) }));
            } catch (e) {
                setErrors(errorsOf(e, 'name'));
            } finally {
                setBusy(false);
            }
        }}>
            <ErrorSummary errors={errors} />
            <div className="form-grid">
                <Field label="Key name" name="name" required spellCheck={false} placeholder="router, certbot" hint={`A single word becomes name.${zone.name}.`} value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Select label="Algorithm" name="algorithm" options={ALGORITHMS.map((a) => ({ value: a, label: a }))} value={form.algorithm} onChange={(e) => setForm({ ...form, algorithm: e.target.value })} />
                <Field label="Names it may change" name="names" className="span2" required spellCheck={false} placeholder="home, _acme-challenge, *.dyn" hint="Relative to the zone; @ is the apex; *.dyn is every name below dyn." value={form.names} error={errors.names} onChange={(e) => setForm({ ...form, names: e.target.value })} />
                <fieldset className="span2 group-picks">
                    <legend>Record types it may change</legend>
                    {types.map((t) => <Check key={t} label={t} checked={form.types.includes(t)} onChange={(e) => pick(t, e.target.checked)} />)}
                    {errors.types && <small className="field-error">{errors.types}</small>}
                </fieldset>
                <Field label="Secret (base64, optional)" name="secret" type="password" autoComplete="off" hint="Leave empty for a new random 256-bit secret." value={form.secret} error={errors.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} />
                <Field label="Comment" name="comment" value={form.comment} onChange={(e) => setForm({ ...form, comment: e.target.value })} />
            </div>
        </FormDialog>
    );
}

function KeyShown({ zone, k, onClose }: { zone: ZoneRow; k: DdnsKey; onClose: () => void }) {
    const host = k.names.find((n) => !n.startsWith('*') && n !== '@') ?? 'home';
    const fqdn = `${host}.${zone.name}`;
    return (
        <FormDialog open title={`Key ${k.name}`} submitLabel="Done" onClose={onClose} onSubmit={onClose}>
            <p>Copy the secret now: it is not shown again (a new one can be made later).</p>
            <code className="secret-once">{k.secret}</code>
            <h3 className="form-section-title">nsupdate</h3>
            <pre className="zone-preview">{`nsupdate -y ${k.algorithm}:${k.name}:${k.secret} <<'END'\nserver YOUR-DNS-SERVER\nzone ${zone.name}.\nupdate delete ${fqdn}. A\nupdate add ${fqdn}. 300 A 198.51.100.7\nsend\nEND`}</pre>
            <h3 className="form-section-title">Routers (dyndns2 / "custom" dynamic DNS)</h3>
            <SettingsRows rows={[['Server', `${window.location.host} (path /nic/update)`], ['Username', k.name.replace(/\.$/, '').split('.')[0]], ['Password', 'the secret'], ['Host name', fqdn]]} />
            <h3 className="form-section-title">certbot (DNS-01 for wildcard certificates)</h3>
            <pre className="zone-preview">{`# /etc/letsencrypt/rfc2136.ini\ndns_rfc2136_server = YOUR-DNS-SERVER-IP\ndns_rfc2136_name = ${k.name}\ndns_rfc2136_secret = ${k.secret}\ndns_rfc2136_algorithm = ${k.algorithm.toUpperCase()}`}</pre>
        </FormDialog>
    );
}

export function DdnsPanel({ zone, canManage }: { zone: ZoneRow; canManage: boolean }) {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, reload } = useApi<Keys>(`/api/zones/${zone.id}/ddns-keys`);
    const [creating, setCreating] = useState(false);
    const [shown, setShown] = useState<DdnsKey | null>(null);
    if (!data) return <Empty>Loading…</Empty>;
    const toggle = async (k: DdnsKey) => {
        try {
            const next = await patch<DdnsKey>(`/api/zones/${zone.id}/ddns-keys/${k.id}`, { enabled: !k.enabled });
            setData({ ...data, rows: data.rows.map((r) => (r.id === k.id ? next : r)) });
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const renew = async (k: DdnsKey) => {
        if (!(await ask({ title: `New secret for ${k.name}?`, message: 'Devices using the old secret stop updating until they get the new one.', confirmLabel: 'Make a new secret' }))) return;
        try {
            setShown(await patch<DdnsKey>(`/api/zones/${zone.id}/ddns-keys/${k.id}`, { new_secret: true }));
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const remove = async (k: DdnsKey) => {
        if (!(await ask({ title: `Delete key ${k.name}?`, message: 'Devices using it can no longer update the zone. The records they set stay.', confirmLabel: 'Delete key' }))) return;
        try {
            await del(`/api/zones/${zone.id}/ddns-keys/${k.id}`);
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <>
            {data.mode === 'off' && <div className="flash warning">Dynamic DNS is off on this server: updates are not accepted until an administrator turns it on in Settings → DNS server.</div>}
            <p className="hint">TSIG keys that may change chosen names of this zone: routers and scripts (RFC 2136, nsupdate), certbot's rfc2136 plugin for wildcard certificates, and routers' "custom" dynamic DNS (dyndns2). Changes are checked like edits in the console, kept in the history and the audit log.</p>
            {canManage && <div className="toolbar"><button type="button" className="primary" onClick={() => setCreating(true)}><Icon name="plus" />New key</button></div>}
            <DataTable
                rows={data.rows}
                rowKey={(r) => r.id}
                emptyText="No keys."
                columns={[
                    { header: 'Key', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.name}</span>{r.comment && <span className="list-subline">{r.comment}</span>}</div> },
                    { header: 'May change', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.names.join(', ')}</span><span className="list-subline">{r.types.join(', ')}</span></div> },
                    { header: 'Status', cell: (r) => (r.enabled ? <Badge tone="success">on</Badge> : <Badge tone="warning">off</Badge>) },
                    { header: 'Last used', cell: (r) => (r.last_used_at ? <div className="list-cell-stack"><span className="mono">{r.last_used_at}</span><span className="list-subline">{r.last_used_ip}</span></div> : 'never') },
                    ...(canManage ? [{
                        header: 'Actions', noExport: true, cell: (r: DdnsKey) => (
                            <>
                                <button type="button" className="link" onClick={() => void toggle(r)}>{r.enabled ? 'Turn off' : 'Turn on'}</button>{' '}
                                <button type="button" className="link" onClick={() => void renew(r)}>New secret</button>{' '}
                                <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button>
                            </>
                        ),
                    }] : []),
                ]}
            />
            {creating && <KeyDialog zone={zone} types={data.types} onClose={() => setCreating(false)} onCreated={(k) => { setCreating(false); setShown(k); void reload(); }} />}
            {shown && <KeyShown zone={zone} k={shown} onClose={() => setShown(null)} />}
        </>
    );
}

// --------------------------------------------------------------------------- templates

export type Variable = { name: string; label: string; default: string };
export type TemplateRecord = { name: string; type: string; value: string; ttl: number | null; priority: number | null; comment: string };
export type Template = { id: number; name: string; description: string; default_ttl: number | null; soa_rname: string;
    nameservers: { host: string; address: string | null }[]; variables: Variable[]; records: TemplateRecord[]; created_by: string; updated_at: string };

export function VariableFields({ template, values, setValues, errors }: { template: Template; values: Record<string, string>; setValues: (v: Record<string, string>) => void; errors: Record<string, string> }) {
    if (!template.variables.length) return null;
    return (
        <>
            {template.variables.map((v) => (
                <Field key={v.name} label={v.label || v.name} name={`variables.${v.name}`} spellCheck={false} placeholder={v.default || undefined}
                    hint={v.default ? `Default: ${v.default}` : undefined} required={!v.default} value={values[v.name] ?? ''} error={errors[`variables.${v.name}`]}
                    onChange={(e) => setValues({ ...values, [v.name]: e.target.value })} />
            ))}
        </>
    );
}

type ApplyReport = { added: number; unchanged: number; skipped: string[]; records: Omit<TemplateRecord, 'comment'>[] };

export function ApplyTemplatePanel({ zone, onDone }: { zone: ZoneRow; onDone: () => void }) {
    const toast = useToast();
    const list = useApi<{ rows: Template[] }>('/api/templates');
    const [id, setId] = useState('');
    const [values, setValues] = useState<Record<string, string>>({});
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [report, setReport] = useState<ApplyReport | null>(null);
    const [busy, setBusy] = useState(false);
    if (!list.data) return <Empty>Loading…</Empty>;
    if (!list.data.rows.length) return <Empty>No templates yet. They are made under Zones → Templates.</Empty>;
    const template = list.data.rows.find((t) => String(t.id) === id);
    const run = async (dry: boolean) => {
        if (!template) return;
        setBusy(true);
        try {
            const r = await post<ApplyReport>(`/api/zones/${zone.id}/template`, { template_id: template.id, variables: values, dry_run: dry });
            setErrors({});
            setReport(dry ? r : null);
            if (!dry) {
                toast(`${r.added} record(s) added from ${template.name}${r.skipped.length ? `, ${r.skipped.length} skipped` : ''}. Publishing…`, r.skipped.length ? 'warning' : 'success');
                onDone();
            }
        } catch (e) {
            setErrors(errorsOf(e, 'template_id'));
        } finally {
            setBusy(false);
        }
    };
    return (
        <>
            <p className="hint">Adds a template's records to this zone. Records the zone already has are left alone; ones that conflict (e.g. a CNAME where there are other records) are skipped and listed.</p>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void run(false); }}>
                <Select label="Template" name="template_id" placeholder="Choose…" options={list.data.rows.map((t) => ({ value: String(t.id), label: t.name }))} value={id} error={errors.template_id}
                    onChange={(e) => { setId(e.target.value); setReport(null); setValues({}); }} />
                {template && <p className="hint">{template.description || `${template.records.length} records`}</p>}
                {template && <VariableFields template={template} values={values} setValues={setValues} errors={errors} />}
                {report && (
                    <div className="span2">
                        <SettingsRows rows={[['Would add', report.added], ['Already in the zone', report.unchanged], ['Skipped', report.skipped.length]]} />
                        {report.records.length > 0 && <pre className="zone-preview">{report.records.map((r) => `${r.name}\t${r.ttl ?? ''}\t${r.type}\t${r.priority ?? ''}${r.priority !== null ? ' ' : ''}${r.value}`).join('\n')}</pre>}
                        {report.skipped.length > 0 && <pre className="publish-error">{report.skipped.join('\n')}</pre>}
                    </div>
                )}
                <FormActions>
                    <button type="button" disabled={!template || busy} onClick={() => void run(true)}>Preview</button>
                    <button className="primary" disabled={!template || busy}>Add the records</button>
                </FormActions>
            </form>
        </>
    );
}

