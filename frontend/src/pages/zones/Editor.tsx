import { Link, router, usePage } from '@inertiajs/react';
import { useEffect, useState } from 'react';
import { DownloadLink, useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { DnssecState, PublishState, type ZoneRow } from '@/components/dns/zone';
import Icon from '@/components/Icon';
import { Tabs } from '@/components/tabs';
import { Badge, Empty, ErrorSummary, Field, FormActions, Panel } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, del, patch, post, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { RecordsTable } from './Records';
import { ApplyTemplatePanel, DdnsPanel, HistoryPanel } from './More';
import { DnssecPanel, ImportPanel, ReversePanel } from './Tools';
import { TransfersPanel } from './Transfers';

type ZoneDetail = ZoneRow & { type_counts: Record<string, number> };
type SoaForm = { description: string; default_ttl: string; soa_mname: string; soa_rname: string; soa_refresh: string; soa_retry: string; soa_expire: string; soa_minimum: string };

function Summary({ zone }: { zone: ZoneDetail }) {
    const stats = [
        { label: 'Records', value: String(zone.record_count ?? 0), note: Object.entries(zone.type_counts).map(([t, n]) => `${n} ${t}`).join(', ') || 'none' },
        { label: 'Serving serial', value: zone.published_serial ? String(zone.published_serial) : '–', note: zone.published_at ? `published ${zone.published_at}` : 'not published yet' },
        { label: 'Default TTL', value: `${zone.default_ttl} s`, note: `negative cache ${zone.soa_minimum} s` },
    ];
    return (
        <section className="client-hero nas-summary" aria-label="Zone summary">
            <div className="client-identity">
                <span className="client-avatar nas-avatar" aria-hidden="true"><Icon name="server" /></span>
                <div className="client-identity-text">
                    <h2>{zone.name}</h2>
                    <div className="client-identity-meta">
                        <PublishState zone={zone} />
                        <DnssecState zone={zone} />
                        <code>{zone.soa_mname}</code>
                    </div>
                    {zone.description && <div className="client-contacts"><span>{zone.description}</span></div>}
                </div>
            </div>
            <div className="client-stats">
                {stats.map((s) => <div key={s.label} className="client-stat"><span>{s.label}</span><strong>{s.value}</strong><small>{s.note}</small></div>)}
            </div>
        </section>
    );
}

function SoaSettings({ zone, canManage, onSaved }: { zone: ZoneDetail; canManage: boolean; onSaved: (z: ZoneDetail) => void }) {
    const toast = useToast();
    const initial: SoaForm = {
        description: zone.description, default_ttl: String(zone.default_ttl), soa_mname: zone.soa_mname, soa_rname: zone.soa_rname,
        soa_refresh: String(zone.soa_refresh), soa_retry: String(zone.soa_retry), soa_expire: String(zone.soa_expire), soa_minimum: String(zone.soa_minimum),
    };
    const [form, setForm] = useState(initial);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const field = (key: keyof SoaForm, label: string, hint: string, number = true) => (
        <Field label={label} name={key} hint={hint} type={number ? 'number' : 'text'} disabled={!canManage} value={form[key]} error={errors[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} />
    );
    return (
        <>
            <ErrorSummary errors={errors} />
            <form
                className="form-grid"
                onSubmit={async (event) => {
                    event.preventDefault();
                    setBusy(true);
                    try {
                        const changed = Object.fromEntries(Object.entries(form).filter(([k, v]) => v !== initial[k as keyof SoaForm]).map(([k, v]) => [k, k === 'description' || k.endsWith('name') ? v : Number(v)]));
                        const saved = await patch<ZoneDetail>(`/api/zones/${zone.id}`, changed);
                        setErrors({});
                        toast('Zone settings saved. Publishing…');
                        onSaved({ ...zone, ...saved });
                    } catch (e) {
                        const err = e as ApiError;
                        setErrors(Object.keys(err.errors).length ? err.errors : { description: err.message });
                    } finally {
                        setBusy(false);
                    }
                }}
            >
                {field('description', 'Description', 'Shown in the zone list.', false)}
                {field('default_ttl', 'Default TTL (seconds)', '$TTL for records without their own.')}
                {field('soa_mname', 'Primary name server (SOA MNAME)', 'Usually the first NS record.', false)}
                {field('soa_rname', 'Zone contact (SOA RNAME)', 'hostmaster@example.com or hostmaster.example.com.', false)}
                {field('soa_refresh', 'Refresh', 'How often secondaries check for changes (300–86400).')}
                {field('soa_retry', 'Retry', 'Retry after a failed refresh; shorter than refresh.')}
                {field('soa_expire', 'Expire', 'Secondaries stop answering after this without contact.')}
                {field('soa_minimum', 'Negative-cache TTL', 'How long resolvers cache "does not exist".')}
                {canManage && <FormActions><button className="primary" disabled={busy}>Save settings</button></FormActions>}
            </form>
        </>
    );
}

export default function ZoneEditor({ params }: { params: string[] }) {
    const zoneId = Number(params[0]);
    const can = useCan();
    const canManage = can('zones.manage');
    const canDelete = can('zones.create');
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const search = searchOf(url);
    const { data: zone, setData: setZone, error, reload } = useApi<ZoneDetail>(`/api/zones/${zoneId}`);
    const [tab, setTab] = useState(search.get('tab') ?? 'records');
    const preview = useApi<{ text: string; serial: number }>(tab === 'file' && zone ? `/api/zones/${zoneId}/preview?v=${encodeURIComponent(zone.updated_at)}` : null);
    const [publishing, setPublishing] = useState(false);

    // While BIND has not caught up, poll the zone so the state badge and errors update by themselves.
    const waiting = zone && zone.status === 'active' && (zone.publish_state === 'pending' || zone.pending);
    useEffect(() => {
        if (!waiting) return;
        const timer = window.setTimeout(() => void reload(), 1500);
        return () => window.clearTimeout(timer);
    }, [waiting, zone, reload]);

    if (error) return <AppLayout title="Zone"><Empty tone="danger">{error.message}</Empty></AppLayout>;
    if (!zone) return <AppLayout title="Zone"><Empty>Loading…</Empty></AppLayout>;

    const publishNow = async () => {
        setPublishing(true);
        try {
            const result = await post<ZoneDetail & { message: string }>(`/api/zones/${zone.id}/publish`);
            toast(`${zone.name}: ${result.message}.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        } finally {
            setPublishing(false);
            void reload();
        }
    };

    const setStatus = async (status: 'active' | 'disabled') => {
        if (status === 'disabled') {
            const ok = await ask({ title: `Disable ${zone.name}?`, message: 'BIND stops answering for this zone; its records are kept and come back when you enable it.', confirmLabel: 'Disable zone' });
            if (!ok) return;
        }
        try {
            setZone({ ...zone, ...(await patch<ZoneDetail>(`/api/zones/${zone.id}`, { status })) });
            toast(status === 'active' ? `${zone.name} enabled. Publishing…` : `${zone.name} disabled.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    const remove = async () => {
        const ok = await ask({ title: `Delete zone ${zone.name}?`, message: `BIND stops answering for ${zone.name} and its ${zone.record_count} records are deleted. This cannot be undone.`, confirmLabel: 'Delete zone', typeToConfirm: zone.name });
        if (!ok) return;
        try {
            await del(`/api/zones/${zone.id}`);
            toast(`Zone ${zone.name} deleted.`);
            router.get('/zones');
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <AppLayout title={zone.name}>
            <div className="toolbar">
                <Link className="button" href="/zones">Back to zones</Link>
                {canManage && <button type="button" onClick={() => void publishNow()} disabled={publishing || zone.status !== 'active'}><Icon name="refresh" />{publishing ? 'Publishing…' : 'Publish now'}</button>}
                {canManage && (zone.status === 'active'
                    ? <button type="button" onClick={() => void setStatus('disabled')}>Disable zone</button>
                    : <button type="button" className="primary" onClick={() => void setStatus('active')}>Enable zone</button>)}
                {canDelete && <button type="button" className="danger" onClick={() => void remove()}>Delete zone</button>}
            </div>
            <Summary zone={zone} />
            {zone.publish_state === 'error' && zone.last_error && (
                <div className="flash danger" role="alert">
                    <strong>The last change could not be published. BIND is still serving serial {zone.published_serial ?? '–'}.</strong>
                    <pre className="publish-error">{zone.last_error}</pre>
                </div>
            )}
            <Tabs
                label="Zone"
                className="tabs nas-tabs"
                onChange={setTab}
                tabs={[
                    {
                        key: 'records',
                        title: 'Records',
                        icon: 'services',
                        count: zone.record_count ?? undefined,
                        content: (
                            <Panel className="list-panel">
                                <RecordsTable
                                    key={url}
                                    zoneId={zone.id}
                                    zoneName={zone.name}
                                    defaultTtl={zone.default_ttl}
                                    canManage={canManage}
                                    filters={{ q: search.get('q') ?? '', type: search.get('type') ?? '', page: search.get('page') ?? '' }}
                                    onChanged={() => void reload()}
                                />
                            </Panel>
                        ),
                    },
                    {
                        key: 'settings',
                        title: 'SOA and settings',
                        icon: 'settings',
                        content: <Panel title="SOA and zone settings"><SoaSettings key={zone.updated_at} zone={zone} canManage={canManage} onSaved={setZone} /></Panel>,
                    },
                    {
                        key: 'file',
                        title: 'Zone file',
                        icon: 'logs',
                        content: (
                            <Panel title={`Zone file${preview.data ? `, serial ${preview.data.serial}` : ''}`} actions={<><Badge tone="info">read-only preview</Badge> <DownloadLink href={`/api/zones/${zone.id}/export`}>Download</DownloadLink></>}>
                                <p className="hint">What the generator writes to /var/lib/bind/zones/{zone.name}.zone{zone.dnssec !== 'off' ? ' (BIND signs it into a .signed copy and serves that)' : ''}. {zone.pending ? 'Changes not yet published are included, with the next serial.' : ''}</p>
                                {preview.data ? <pre className="zone-preview">{preview.data.text}</pre> : <Empty>Loading…</Empty>}
                            </Panel>
                        ),
                    },
                    {
                        key: 'history',
                        title: 'History',
                        icon: 'logs',
                        content: <Panel title="History"><HistoryPanel zone={zone} canManage={canManage} onRestored={() => void reload()} /></Panel>,
                    },
                    {
                        key: 'ddns',
                        title: 'Dynamic DNS',
                        icon: 'refresh',
                        content: <Panel title="Dynamic DNS keys"><DdnsPanel zone={zone} canManage={canManage} /></Panel>,
                    },
                    {
                        key: 'transfers',
                        title: 'Transfers',
                        icon: 'server',
                        content: <Panel title="Zone transfers to secondaries"><TransfersPanel zone={zone} canManage={canManage} /></Panel>,
                    },
                    {
                        key: 'dnssec',
                        title: 'DNSSEC',
                        icon: 'lock',
                        content: <Panel title="DNSSEC signing"><DnssecPanel zone={zone} canManage={canManage} onChanged={(z) => setZone({ ...zone, ...z })} /></Panel>,
                    },
                    ...(canManage ? [{
                        key: 'template',
                        title: 'Template',
                        icon: 'plus',
                        content: <Panel title="Add records from a template"><ApplyTemplatePanel zone={zone} onDone={() => void reload()} /></Panel>,
                    }, {
                        key: 'import',
                        title: 'Import',
                        icon: 'refresh',
                        content: <Panel title="Import records"><ImportPanel zone={zone} onDone={() => void reload()} /></Panel>,
                    }] : []),
                    ...(canManage && /\.(in-addr|ip6)\.arpa$/.test(zone.name) ? [{
                        key: 'reverse',
                        title: 'Reverse DNS',
                        icon: 'signal',
                        content: <Panel title="Generate reverse DNS for a subnet"><ReversePanel zone={zone} onDone={() => void reload()} /></Panel>,
                    }] : []),
                ]}
            />
        </AppLayout>
    );
}
