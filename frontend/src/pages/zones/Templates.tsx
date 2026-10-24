// Zone templates: records new zones start with (Zones → Templates), with {variables}.
import { Link, router, usePage } from '@inertiajs/react';
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable } from '@/components/table';
import { Empty, ErrorSummary, Field, FormActions, ListPanel, Panel } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, del, post, put, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import type { Template, TemplateRecord, Variable } from './More';

const TYPES = ['A', 'AAAA', 'CNAME', 'ALIAS', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR', 'TLSA', 'SSHFP', 'NAPTR', 'HTTPS', 'SVCB', 'DS'];
const STARTER: Omit<Template, 'id' | 'created_by' | 'updated_at'> = {
    name: '', description: 'Website and mail at the ISP', default_ttl: 3600, soa_rname: 'hostmaster@{zone}',
    nameservers: [{ host: 'ns1.isp.example', address: null }, { host: 'ns2.isp.example', address: null }],
    variables: [{ name: 'ip', label: 'Web server address', default: '' }, { name: 'mx', label: 'Mail server', default: 'mail.isp.example' }],
    records: [
        { name: '@', type: 'A', value: '{ip}', ttl: null, priority: null, comment: 'website' },
        { name: 'www', type: 'CNAME', value: '@', ttl: null, priority: null, comment: '' },
        { name: '@', type: 'MX', value: '{mx}', ttl: null, priority: 10, comment: '' },
        { name: '@', type: 'TXT', value: 'v=spf1 mx include:_spf.isp.example -all', ttl: null, priority: null, comment: 'SPF' },
        { name: '_dmarc', type: 'TXT', value: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{zone}', ttl: null, priority: null, comment: 'DMARC' },
        { name: '@', type: 'CAA', value: '0 issue "letsencrypt.org"', ttl: null, priority: null, comment: '' },
    ],
};
type Draft = typeof STARTER;

function errorsOf(e: unknown): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { name: ae.message };
}

function Editor({ initial, id, canManage }: { initial: Draft; id: number | null; canManage: boolean }) {
    const toast = useToast();
    const [t, setT] = useState<Draft>(initial);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const setVar = (i: number, patch: Partial<Variable>) => setT({ ...t, variables: t.variables.map((v, j) => (j === i ? { ...v, ...patch } : v)) });
    const setRec = (i: number, patch: Partial<TemplateRecord>) => setT({ ...t, records: t.records.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
    const setNs = (i: number, host: string) => setT({ ...t, nameservers: t.nameservers.map((n, j) => (j === i ? { ...n, host } : n)) });
    const num = (v: string) => (v.trim() === '' ? null : Number(v));
    return (
        <Panel title={id ? `Template ${initial.name}` : 'New template'}>
            <p className="hint">Names are relative to the zone (@ is the apex). <code>{'{zone}'}</code> is the zone's name; declare your own variables below and use them as <code>{'{ip}'}</code>: they are asked for when the template is used.</p>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                    const saved = id ? await put<Template>(`/api/templates/${id}`, t) : await post<Template>('/api/templates', t);
                    setErrors({});
                    toast(`Template ${saved.name} saved.`);
                    router.get('/templates', { id: String(saved.id) });
                } catch (err) {
                    setErrors(errorsOf(err));
                } finally {
                    setBusy(false);
                }
            }}>
                <Field label="Name" name="name" required disabled={!canManage} value={t.name} error={errors.name} onChange={(e) => setT({ ...t, name: e.target.value })} />
                <Field label="Description" name="description" disabled={!canManage} value={t.description} onChange={(e) => setT({ ...t, description: e.target.value })} />
                <Field label="Default TTL (optional)" name="default_ttl" type="number" min={60} max={604800} disabled={!canManage} value={t.default_ttl ?? ''} error={errors.default_ttl} onChange={(e) => setT({ ...t, default_ttl: num(e.target.value) })} />
                <Field label="Zone contact (optional)" name="soa_rname" disabled={!canManage} placeholder="hostmaster@{zone}" value={t.soa_rname} onChange={(e) => setT({ ...t, soa_rname: e.target.value })} />

                <h3 className="span2 form-section-title">Name servers</h3>
                <div className="span2 row-editor">
                    {t.nameservers.map((n, i) => (
                        <div className="row-editor-row" key={i}>
                            <Field label={`Name server ${i + 1}`} name={`nameservers.${i}.host`} disabled={!canManage} spellCheck={false} value={n.host} error={errors[`nameservers.${i}.host`]} onChange={(e) => setNs(i, e.target.value)} />
                            {canManage && <button type="button" onClick={() => setT({ ...t, nameservers: t.nameservers.filter((_, j) => j !== i) })}>Remove</button>}
                        </div>
                    ))}
                    {canManage && t.nameservers.length < 10 && <div><button type="button" onClick={() => setT({ ...t, nameservers: [...t.nameservers, { host: '', address: null }] })}>Add name server</button></div>}
                </div>

                <h3 className="span2 form-section-title">Variables</h3>
                <div className="span2 row-editor">
                    {t.variables.map((v, i) => (
                        <div className="row-editor-row" key={i}>
                            <Field label="Variable" name={`variables.${i}.name`} disabled={!canManage} spellCheck={false} placeholder="ip" value={v.name} error={errors[`variables.${i}.name`]} onChange={(e) => setVar(i, { name: e.target.value })} />
                            <Field label="Asked as" name={`variables.${i}.label`} disabled={!canManage} placeholder="Web server address" value={v.label} onChange={(e) => setVar(i, { label: e.target.value })} />
                            <Field label="Default (optional)" name={`variables.${i}.default`} disabled={!canManage} spellCheck={false} value={v.default} onChange={(e) => setVar(i, { default: e.target.value })} />
                            {canManage && <button type="button" onClick={() => setT({ ...t, variables: t.variables.filter((_, j) => j !== i) })}>Remove</button>}
                        </div>
                    ))}
                    {canManage && <div><button type="button" onClick={() => setT({ ...t, variables: [...t.variables, { name: '', label: '', default: '' }] })}>Add variable</button></div>}
                </div>

                <h3 className="span2 form-section-title">Records</h3>
                <div className="span2 row-editor">
                    {t.records.map((r, i) => (
                        <div className="row-editor-row" key={i}>
                            <Field label="Name" name={`records.${i}.name`} disabled={!canManage} spellCheck={false} value={r.name} error={errors[`records.${i}.name`]} onChange={(e) => setRec(i, { name: e.target.value })} />
                            <label><span>Type</span>
                                <select disabled={!canManage} value={r.type} onChange={(e) => setRec(i, { type: e.target.value })}>{TYPES.map((x) => <option key={x}>{x}</option>)}</select>
                            </label>
                            <Field label="Value" name={`records.${i}.value`} disabled={!canManage} spellCheck={false} value={r.value} error={errors[`records.${i}.value`] ?? errors[`records.${i}.type`]} onChange={(e) => setRec(i, { value: e.target.value })} />
                            {(r.type === 'MX' || r.type === 'SRV') && <Field label="Priority" name={`records.${i}.priority`} type="number" disabled={!canManage} value={r.priority ?? ''} error={errors[`records.${i}.priority`]} onChange={(e) => setRec(i, { priority: num(e.target.value) })} />}
                            <Field label="TTL" name={`records.${i}.ttl`} type="number" disabled={!canManage} placeholder="default" value={r.ttl ?? ''} error={errors[`records.${i}.ttl`]} onChange={(e) => setRec(i, { ttl: num(e.target.value) })} />
                            {canManage && <button type="button" onClick={() => setT({ ...t, records: t.records.filter((_, j) => j !== i) })}>Remove</button>}
                        </div>
                    ))}
                    {canManage && <div><button type="button" onClick={() => setT({ ...t, records: [...t.records, { name: '@', type: 'A', value: '', ttl: null, priority: null, comment: '' }] })}>Add record</button></div>}
                </div>
                {canManage && <FormActions><Link className="button" href="/templates">Cancel</Link><button className="primary" disabled={busy}>Save template</button></FormActions>}
            </form>
        </Panel>
    );
}

export default function Templates() {
    const can = useCan();
    const canManage = can('templates.manage');
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const params = searchOf(url);
    const id = params.get('id');
    const { data, reload } = useApi<{ rows: Template[] }>('/api/templates');
    if (!data) return <AppLayout title="Zone templates"><Empty>Loading…</Empty></AppLayout>;
    if (id === 'new' || (id && data.rows.some((t) => String(t.id) === id))) {
        const existing = data.rows.find((t) => String(t.id) === id);
        return <AppLayout title="Zone templates"><Editor key={id} id={existing?.id ?? null} initial={existing ?? STARTER} canManage={canManage} /></AppLayout>;
    }
    const remove = async (t: Template) => {
        if (!(await ask({ title: `Delete template ${t.name}?`, message: 'Zones made from it keep their records.', confirmLabel: 'Delete template' }))) return;
        try {
            await del(`/api/templates/${t.id}`);
            toast(`${t.name} deleted.`);
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <AppLayout title="Zone templates">
            <ListPanel title="Zone templates" description="Records a new zone starts with: pick one under New zone, or add one to an existing zone (Zone → Template)."
                tools={canManage ? <Link className="button primary" href="/templates?id=new"><Icon name="plus" />New template</Link> : undefined}>
                <DataTable
                    rows={data.rows}
                    rowKey={(r) => r.id}
                    emptyText="No templates yet."
                    columns={[
                        { header: 'Template', cell: (r) => <div className="list-cell-stack"><Link href={`/templates?id=${r.id}`}>{r.name}</Link>{r.description && <span className="list-subline">{r.description}</span>}</div> },
                        { header: 'Records', cell: (r) => r.records.length },
                        { header: 'Asks for', cell: (r) => r.variables.map((v) => v.label || v.name).join(', ') || '-' },
                        { header: 'Name servers', cell: (r) => r.nameservers.map((n) => n.host).join(', ') || '-' },
                        { header: 'Changed', cell: (r) => <span className="mono">{r.updated_at}</span> },
                        ...(canManage ? [{ header: 'Actions', noExport: true, cell: (r: Template) => <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button> }] : []),
                    ]}
                />
            </ListPanel>
        </AppLayout>
    );
}
