import { Link, router } from '@inertiajs/react';
import { useState } from 'react';
import { useToast } from '@/components/dns/feedback';
import { ErrorSummary, Field, FormActions, Panel } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, post } from '@/lib/api';

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

    const zone = name.trim().toLowerCase().replace(/\.$/, '');
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
                            const created = await post<{ id: number; name: string }>('/api/zones', {
                                name, description, default_ttl: Number(ttl), soa_rname: rname || `hostmaster@${zone}`,
                                nameservers: servers.filter((s) => s.host.trim()).map((s) => ({ host: s.host, address: s.address || null })),
                            });
                            toast(`Zone ${created.name} created. Publishing to BIND…`);
                            router.get(`/zones/${created.id}`);
                        } catch (e) {
                            const err = e as ApiError;
                            setErrors(Object.keys(err.errors).length ? err.errors : { name: err.message });
                        } finally {
                            setBusy(false);
                        }
                    }}
                >
                    <Field label="Domain" name="name" required autoComplete="off" spellCheck={false} placeholder="example.com" hint="The zone apex, e.g. example.com or 2.0.192.in-addr.arpa." value={name} error={errors.name} onChange={(e) => setName(e.target.value)} />
                    <Field label="Description" name="description" autoComplete="off" hint="Optional, e.g. the customer." value={description} error={errors.description} onChange={(e) => setDescription(e.target.value)} />
                    <Field label="Default TTL (seconds)" name="default_ttl" type="number" min={60} max={604800} required hint="Used by records without their own TTL. 3600 is typical." value={ttl} error={errors.default_ttl} onChange={(e) => setTtl(e.target.value)} />
                    <Field label="Zone contact (SOA email)" name="soa_rname" type="email" autoComplete="off" placeholder={zone ? `hostmaster@${zone}` : 'hostmaster@example.com'} hint="Leave empty for hostmaster@ the zone." value={rname} error={errors.soa_rname} onChange={(e) => setRname(e.target.value)} />
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
