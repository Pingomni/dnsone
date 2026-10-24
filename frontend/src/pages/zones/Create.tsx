import { Link, router } from '@inertiajs/react';
import { useState } from 'react';
import { useToast } from '@/components/dns/feedback';
import { ErrorSummary, Field, FormActions, Panel, Select } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, post, useApi } from '@/lib/api';
import { type Template, VariableFields } from './More';

type NameServer = { host: string; address: string };

export default function ZoneCreate() {
    const toast = useToast();
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [ttl, setTtl] = useState('3600');
    const [rname, setRname] = useState('');
    const [servers, setServers] = useState<NameServer[]>([{ host: '', address: '' }, { host: '', address: '' }]);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const templates = useApi<{ rows: Template[] }>('/api/templates');
    const [templateId, setTemplateId] = useState('');
    const [variables, setVariables] = useState<Record<string, string>>({});
    const template = templates.data?.rows.find((t) => String(t.id) === templateId);

    const zone = name.trim().toLowerCase().replace(/\.$/, '');
    // A template brings its name servers, contact and TTL; the form keeps whatever was typed over them.
    const chooseTemplate = (id: string) => {
        setTemplateId(id);
        setVariables({});
        const t = templates.data?.rows.find((x) => String(x.id) === id);
        if (!t) return;
        if (t.nameservers.length) setServers(t.nameservers.map((n) => ({ host: n.host, address: n.address ?? '' })));
        if (t.default_ttl) setTtl(String(t.default_ttl));
        if (t.soa_rname) setRname(t.soa_rname.includes('{zone}') ? '' : t.soa_rname);
    };
    const contact = template?.soa_rname.includes('{zone}') && zone ? template.soa_rname.replaceAll('{zone}', zone) : '';
    const inZone = (host: string) => {
        const h = host.trim().toLowerCase().replace(/\.$/, '');
        return Boolean(h) && Boolean(zone) && (!h.includes('.') || h === zone || h.endsWith(`.${zone}`));
    };
    const setServer = (i: number, patch: Partial<NameServer>) => setServers(servers.map((s, j) => (j === i ? { ...s, ...patch } : s)));

    return (
        <AppLayout title="New zone">
            <div className="toolbar"><Link className="button" href="/zones">Back to zones</Link></div>
            <Panel title="New zone">
                <p className="hint">DNSOne writes the zone file, checks it with named-checkzone and loads it into BIND. You add records on the next page.</p>
                <ErrorSummary errors={errors} />
                <form
                    className="form-grid"
                    onSubmit={async (event) => {
                        event.preventDefault();
                        setBusy(true);
                        try {
                            const created = await post<{ id: number; name: string; skipped: string[] }>('/api/zones', {
                                name, description, default_ttl: Number(ttl), soa_rname: rname || contact || `hostmaster@${zone}`,
                                nameservers: servers.filter((s) => s.host.trim()).map((s) => ({ host: s.host.replaceAll('{zone}', zone), address: s.address || null })),
                                template_id: template ? template.id : null, variables,
                            });
                            toast(`Zone ${created.name} created${template ? ` from ${template.name}` : ''}. Publishing to BIND…`);
                            if (created.skipped.length) toast(`Skipped from the template: ${created.skipped.join('; ')}`, 'warning');
                            router.get(`/zones/${created.id}`);
                        } catch (e) {
                            const err = e as ApiError;
                            setErrors(Object.keys(err.errors).length ? err.errors : { name: err.message });
                        } finally {
                            setBusy(false);
                        }
                    }}
                >
                    {templates.data && templates.data.rows.length > 0 && (
                        <Select label="Template" name="template_id" className="span2" placeholder="None: name servers only" value={templateId}
                            hint={template ? (template.description || `${template.records.length} records`) : 'Start the zone with a template’s records (web hosting, mail, …).'}
                            options={templates.data.rows.map((t) => ({ value: String(t.id), label: t.name }))} error={errors.template_id} onChange={(e) => chooseTemplate(e.target.value)} />
                    )}
                    <Field label="Domain" name="name" required autoComplete="off" spellCheck={false} placeholder="example.com" hint="The zone apex, e.g. example.com or 2.0.192.in-addr.arpa." value={name} error={errors.name} onChange={(e) => setName(e.target.value)} />
                    <Field label="Description" name="description" autoComplete="off" hint="Optional, e.g. the customer." value={description} error={errors.description} onChange={(e) => setDescription(e.target.value)} />
                    <Field label="Default TTL (seconds)" name="default_ttl" type="number" min={60} max={604800} required hint="Used by records without their own TTL. 3600 is typical." value={ttl} error={errors.default_ttl} onChange={(e) => setTtl(e.target.value)} />
                    <Field label="Zone contact (SOA email)" name="soa_rname" type="email" autoComplete="off" placeholder={contact || (zone ? `hostmaster@${zone}` : 'hostmaster@example.com')} hint={contact ? 'Leave empty for the template’s contact.' : 'Leave empty for hostmaster@ the zone.'} value={rname} error={errors.soa_rname} onChange={(e) => setRname(e.target.value)} />
                    {template && template.variables.length > 0 && (
                        <>
                            <h3 className="span2 form-section-title">{template.name}</h3>
                            <VariableFields template={template} values={variables} setValues={setVariables} errors={errors} />
                        </>
                    )}
                    <h3 className="span2 form-section-title">Name servers</h3>
                    <p className="span2 hint">The servers the domain is delegated to. The first one becomes the SOA primary. A name server inside this zone (ns1, or ns1.{zone || 'example.com'}) needs its IP address, which DNSOne publishes as glue.</p>
                    <div className="span2 ns-rows">
                        {servers.map((s, i) => (
                            <div className="ns-row" key={i}>
                                <Field label={`Name server ${i + 1}`} name={`nameservers.${i}.host`} autoComplete="off" spellCheck={false} placeholder={i === 0 ? 'ns1.example.net' : 'ns2.example.net'} required={i === 0} value={s.host} error={errors[`nameservers.${i}.host`]} onChange={(e) => setServer(i, { host: e.target.value })} />
                                <Field label="IP address (glue)" name={`nameservers.${i}.address`} autoComplete="off" disabled={!inZone(s.host)} placeholder={inZone(s.host) ? '192.0.2.53' : 'not needed'} value={inZone(s.host) ? s.address : ''} error={errors[`nameservers.${i}.address`]} onChange={(e) => setServer(i, { address: e.target.value })} />
                                <button type="button" disabled={servers.length === 1} onClick={() => setServers(servers.filter((_, j) => j !== i))}>Remove</button>
                            </div>
                        ))}
                        {servers.length < 10 && <div><button type="button" onClick={() => setServers([...servers, { host: '', address: '' }])}>Add name server</button></div>}
                    </div>
                    <FormActions><button className="primary" disabled={busy}>{busy ? 'Creating…' : 'Create zone'}</button></FormActions>
                </form>
            </Panel>
        </AppLayout>
    );
}
