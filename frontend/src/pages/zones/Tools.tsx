// Zone tools: import (zone file or AXFR), bulk reverse DNS, DNSSEC signing.
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import type { ZoneRow } from '@/components/dns/zone';
import { SettingsRows } from '@/components/settings';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select, TextArea } from '@/components/ui';
import { ApiError, patch, post, useApi } from '@/lib/api';

type Imported = { name: string; type: string; value: string; ttl: number | null; priority: number | null };
export type ImportReport = {
    added: number; unchanged: number; removed: number; updated: number; skipped: string[]; skipped_count: number;
    warnings: string[]; dnssec_dropped: number; records: Imported[];
};
export type Source = { kind: 'text' | 'axfr'; text: string; server: string; port: string; tsig_name: string; tsig_secret: string; tsig_algorithm: string };

export const EMPTY_SOURCE: Source = { kind: 'text', text: '', server: '', port: '53', tsig_name: '', tsig_secret: '', tsig_algorithm: 'hmac-sha256' };
const TSIG = [{ value: 'hmac-sha256', label: 'hmac-sha256' }, { value: 'hmac-sha512', label: 'hmac-sha512' }, { value: 'hmac-sha1', label: 'hmac-sha1' }, { value: 'hmac-md5', label: 'hmac-md5' }];

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

export function sourceBody(s: Source) {
    if (s.kind === 'text') return { text: s.text };
    return { axfr: { server: s.server.trim(), port: Number(s.port) || 53, tsig_name: s.tsig_name, tsig_secret: s.tsig_secret, tsig_algorithm: s.tsig_algorithm } };
}

/** Where the records come from: a pasted or uploaded zone file, or a transfer from the old server. */
export function SourceFields({ source, setSource, errors }: { source: Source; setSource: (s: Source) => void; errors: Record<string, string> }) {
    return (
        <>
            <fieldset className="span2 group-picks">
                <legend>Import from</legend>
                <Check type="radio" name="source" label="A zone file (BIND format)" checked={source.kind === 'text'} onChange={() => setSource({ ...source, kind: 'text' })} />
                <Check type="radio" name="source" label="A zone transfer (AXFR) from the current DNS server" checked={source.kind === 'axfr'} onChange={() => setSource({ ...source, kind: 'axfr' })} />
            </fieldset>
            {source.kind === 'text' ? (
                <>
                    <label className="span2">
                        <span>Zone file</span>
                        <input type="file" accept=".zone,.db,.txt,text/plain" onChange={async (e) => {
                            const file = e.target.files?.[0];
                            if (file) setSource({ ...source, text: await file.text() });
                        }} />
                    </label>
                    <TextArea label="Or paste it" name="text" rows={12} spellCheck={false} className="span2 mono" value={source.text} error={errors.text}
                        placeholder={'$ORIGIN example.com.\n$TTL 3600\n@    IN SOA ns1 hostmaster ( 1 7200 1800 1209600 300 )\n@    NS  ns1\nns1  A   192.0.2.53\nwww  A   192.0.2.10'}
                        hint="Exported from BIND, cPanel or another panel. Without $TTL, records get the zone's default TTL. DNSSEC records are dropped: DNSOne signs zones itself."
                        onChange={(e) => setSource({ ...source, text: e.target.value })} />
                </>
            ) : (
                <>
                    <Field label="Server address" name="axfr.server" required spellCheck={false} placeholder="198.51.100.53" value={source.server} error={errors['axfr.server']}
                        hint="The server that serves the zone now. It must allow transfers to this server (allow-transfer)." onChange={(e) => setSource({ ...source, server: e.target.value })} />
                    <Field label="Port" name="axfr.port" type="number" min={1} max={65535} value={source.port} error={errors['axfr.port']} onChange={(e) => setSource({ ...source, port: e.target.value })} />
                    <Field label="TSIG key name (optional)" name="axfr.tsig_name" spellCheck={false} autoComplete="off" value={source.tsig_name} error={errors['axfr.tsig_name']} onChange={(e) => setSource({ ...source, tsig_name: e.target.value })} />
                    <Field label="TSIG secret (base64)" name="axfr.tsig_secret" type="password" autoComplete="off" value={source.tsig_secret} error={errors['axfr.tsig_secret']} onChange={(e) => setSource({ ...source, tsig_secret: e.target.value })} />
                    <Select label="TSIG algorithm" name="axfr.tsig_algorithm" options={TSIG} value={source.tsig_algorithm} error={errors['axfr.tsig_algorithm']} onChange={(e) => setSource({ ...source, tsig_algorithm: e.target.value })} />
                </>
            )}
        </>
    );
}

export function ImportResult({ report, preview }: { report: ImportReport; preview: boolean }) {
    return (
        <div className="span2">
            <SettingsRows rows={[
                [preview ? 'Would add' : 'Added', report.added], ['Already in the zone', report.unchanged],
                ...(report.removed || report.updated ? [[preview ? 'Would remove' : 'Removed', report.removed] as [string, number], ['TTL updated', report.updated] as [string, number]] : []),
                ['Skipped', report.skipped_count], ['DNSSEC records dropped', report.dnssec_dropped],
            ]} />
            {report.warnings.length > 0 && <pre className="zone-preview">{report.warnings.join('\n')}</pre>}
            {report.skipped.length > 0 && <pre className="publish-error">{report.skipped.join('\n')}</pre>}
            {preview && report.records.length > 0 && (
                <pre className="zone-preview">{report.records.map((r) => `${r.name}\t${r.ttl ?? ''}\t${r.type}\t${r.priority ?? ''}${r.priority !== null ? ' ' : ''}${r.value}`).join('\n')}{report.added > report.records.length ? `\n… and ${report.added - report.records.length} more` : ''}</pre>
            )}
        </div>
    );
}

/** Zone editor → Import: merge records into the zone, or make it match the file. */
export function ImportPanel({ zone, onDone }: { zone: ZoneRow; onDone: () => void }) {
    const toast = useToast();
    const ask = useConfirm();
    const [source, setSource] = useState<Source>(EMPTY_SOURCE);
    const [mode, setMode] = useState<'merge' | 'replace'>('merge');
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [report, setReport] = useState<{ report: ImportReport; preview: boolean } | null>(null);
    const [busy, setBusy] = useState(false);

    const run = async (dryRun: boolean) => {
        setBusy(true);
        try {
            const result = await post<ImportReport>(`/api/zones/${zone.id}/import`, { ...sourceBody(source), mode, dry_run: dryRun });
            setErrors({});
            setReport({ report: result, preview: dryRun });
            if (!dryRun) {
                toast(`${result.added} record(s) imported${result.removed ? `, ${result.removed} removed` : ''}. Publishing…`);
                onDone();
            }
        } catch (e) {
            setErrors(errorsOf(e, source.kind === 'text' ? 'text' : 'axfr.server'));
            setReport(null);
        } finally {
            setBusy(false);
        }
    };

    return (
        <>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                if (mode === 'replace' && report?.preview && report.report.removed) {
                    const ok = await ask({ title: `Replace the records of ${zone.name}?`, message: `${report.report.removed} record(s) not in the import are deleted, ${report.report.added} added.`, confirmLabel: 'Replace records' });
                    if (!ok) return;
                }
                await run(false);
            }}>
                <SourceFields source={source} setSource={(s) => { setSource(s); setReport(null); }} errors={errors} />
                <fieldset className="span2 group-picks">
                    <legend>How</legend>
                    <Check type="radio" name="mode" label="Merge: add the records the zone does not have yet" checked={mode === 'merge'} onChange={() => { setMode('merge'); setReport(null); }} />
                    <Check type="radio" name="mode" label="Replace: the zone ends up with exactly the imported records" checked={mode === 'replace'} onChange={() => { setMode('replace'); setReport(null); }} />
                </fieldset>
                <p className="span2 hint">The zone's SOA settings are kept. Preview first: nothing changes until you import.</p>
                {report && <ImportResult report={report.report} preview={report.preview} />}
                <FormActions>
                    <button type="button" disabled={busy} onClick={() => void run(true)}>Preview</button>
                    <button className="primary" disabled={busy || (mode === 'replace' && !report?.preview)}>{busy ? 'Working…' : 'Import'}</button>
                </FormActions>
            </form>
        </>
    );
}

type ReverseReport = {
    addresses: number; added: number; replaced: number; unchanged: number; skipped: string[]; skipped_count: number;
    sample: { address: string; name: string; value: string }[];
    forward: { added: number; replaced: number; zones: string[]; skipped: string[]; skipped_count: number };
};

/** Zone editor → Reverse DNS (reverse zones only): PTR records for a whole pool from a pattern. */
export function ReversePanel({ zone, onDone }: { zone: ZoneRow; onDone: () => void }) {
    const toast = useToast();
    const v6 = zone.name.endsWith('.ip6.arpa');
    const [form, setForm] = useState({ network: '', template: v6 ? '{ip}.dyn.isp.example' : 'pool-{a}-{b}-{c}-{d}.isp.example', ttl: '', overwrite: false, forward: false });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [report, setReport] = useState<{ report: ReverseReport; preview: boolean } | null>(null);
    const [busy, setBusy] = useState(false);

    const run = async (dryRun: boolean) => {
        setBusy(true);
        try {
            const r = await post<ReverseReport>(`/api/zones/${zone.id}/reverse`, { ...form, ttl: form.ttl ? Number(form.ttl) : null, dry_run: dryRun });
            setErrors({});
            setReport({ report: r, preview: dryRun });
            if (!dryRun) {
                toast(`${r.added + r.replaced} PTR record(s) written${r.forward.added ? `, ${r.forward.added} forward record(s)` : ''}. Publishing…`);
                onDone();
            }
        } catch (e) {
            setErrors(errorsOf(e, 'network'));
            setReport(null);
        } finally {
            setBusy(false);
        }
    };
    const r = report?.report;
    return (
        <>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void run(false); }}>
                <Field label="Subnet" name="network" required spellCheck={false} placeholder={v6 ? '2001:db8::/120' : '192.0.2.0/24'} value={form.network} error={errors.network}
                    hint={`Inside ${zone.name}; at most 65,536 addresses at a time.`} onChange={(e) => { setForm({ ...form, network: e.target.value }); setReport(null); }} />
                <Field label="Name pattern" name="template" required spellCheck={false} value={form.template} error={errors.template}
                    hint={v6 ? '{ip} is the address written out in full with dashes.' : '{a}.{b}.{c}.{d} are the address\'s numbers; {ip} is all four with dashes.'}
                    onChange={(e) => { setForm({ ...form, template: e.target.value }); setReport(null); }} />
                <Field label="TTL (seconds)" name="ttl" type="number" min={60} max={604800} placeholder={`default (${zone.default_ttl})`} value={form.ttl} error={errors.ttl} onChange={(e) => setForm({ ...form, ttl: e.target.value })} />
                <div className="span2">
                    <Check label="Also add the matching A/AAAA records, in the hosted zone of each name (forward-confirmed reverse DNS, which mail servers check)" checked={form.forward} onChange={(e) => { setForm({ ...form, forward: e.target.checked }); setReport(null); }} />
                    <Check label="Replace records already there (otherwise they are kept)" checked={form.overwrite} onChange={(e) => { setForm({ ...form, overwrite: e.target.checked }); setReport(null); }} />
                </div>
                {r && (
                    <div className="span2">
                        <SettingsRows rows={[
                            ['Addresses', r.addresses.toLocaleString()], [report.preview ? 'PTR to add' : 'PTR added', r.added.toLocaleString()], ['PTR replaced', r.replaced.toLocaleString()],
                            ['Already right', r.unchanged.toLocaleString()], ['Skipped', r.skipped_count.toLocaleString()],
                            ...(form.forward ? [['Forward records', `${r.forward.added.toLocaleString()} in ${r.forward.zones.join(', ') || 'no zone'}`] as [string, string]] : []),
                        ]} />
                        <pre className="zone-preview">{r.sample.map((s) => `${s.address}\t→ ${s.value}`).join('\n')}{r.addresses > r.sample.length ? '\n…' : ''}</pre>
                        {(r.skipped.length > 0 || r.forward.skipped.length > 0) && <pre className="publish-error">{[...r.skipped, ...r.forward.skipped].join('\n')}</pre>}
                    </div>
                )}
                <FormActions>
                    <button type="button" disabled={busy} onClick={() => void run(true)}>Preview</button>
                    <button className="primary" disabled={busy}>{busy ? 'Working…' : 'Generate'}</button>
                </FormActions>
            </form>
        </>
    );
}

type DnssecKey = { tag: number; flags: number; algorithm: string; dnskey: string; role: string | null; goal: string | null; ds: string | null; ds_record: string | null };
type Dnssec = {
    state: 'off' | 'on' | 'insecure'; summary: string; secure: boolean; ds: string[]; cds: string[]; parent_ds: string[] | null; parent_zone: string | null;
    rolling: boolean; bind_status: string; keys: DnssecKey[];
};

// BIND's view of a key's DS at the parent, in words.
const DS_STATE: Record<string, string> = {
    hidden: 'not at the parent', rumoured: 'being published at the parent', omnipresent: 'at the parent', unretentive: 'being removed from the parent',
};

/** Zone editor → DNSSEC: signing on or off, the DS records, CDS, the parent's DS and key rollovers. */
export function DnssecPanel({ zone, canManage, onChanged }: { zone: ZoneRow; canManage: boolean; onChanged: (z: ZoneRow) => void }) {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, error, reload } = useApi<Dnssec>(`/api/zones/${zone.id}/dnssec?v=${encodeURIComponent(zone.updated_at)}`);
    const [busy, setBusy] = useState(false);
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;

    const hosted = data.parent_zone !== null;
    const set = async (on: boolean) => {
        const ok = await ask(on
            ? { title: `Sign ${zone.name}?`, message: hosted
                ? `BIND creates a signing key and signs the zone. Its parent ${data.parent_zone} is hosted here too: DNSOne adds the DS record there by itself once the key has reached every resolver.`
                : 'BIND creates a signing key and signs the zone. It becomes secure once the DS record shown here is at the registrar (registries that read CDS records pick it up by themselves).', confirmLabel: 'Sign the zone' }
            : { title: `Stop signing ${zone.name}?`, message: hosted
                ? `DNSOne removes the DS records from ${data.parent_zone}; BIND then removes the signatures and keys.`
                : 'Remove the DS records at the registrar first and wait a day. BIND then removes the signatures and keys.', confirmLabel: 'Stop signing' });
        if (!ok) return;
        setBusy(true);
        try {
            onChanged(await patch<ZoneRow>(`/api/zones/${zone.id}`, { dnssec: on }));
            toast(on ? `${zone.name}: signing on. Publishing…` : `${zone.name}: signing being removed.`);
            window.setTimeout(() => void reload(), 3000);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        } finally {
            setBusy(false);
        }
    };
    const check = async () => {
        setBusy(true);
        try {
            const r = await post<Dnssec & { done: string[] }>(`/api/zones/${zone.id}/dnssec/check`);
            setData(r);
            toast(r.done.length ? r.done.join('; ') : 'Checked: nothing to change.');
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        } finally {
            setBusy(false);
        }
    };
    const rollover = async () => {
        const ok = await ask({
            title: `Roll the signing key of ${zone.name}?`,
            message: hosted
                ? `BIND introduces a new key, and DNSOne swaps the DS in ${data.parent_zone} once it has reached every resolver (hours, with the default timings); nothing is needed from you. The old key stays published until BIND has re-signed the zone with the new one (days).`
                : 'BIND introduces a new key and publishes its CDS once it has reached every resolver (hours, with the default timings). Registries that read CDS update the DS by themselves; otherwise replace the DS at the registrar then. DNSOne sees the new DS within 5 minutes and tells BIND; the old key stays published until BIND has re-signed the zone (days).',
            confirmLabel: 'Roll the key',
        });
        if (!ok) return;
        setBusy(true);
        try {
            const r = await post<Dnssec & { message: string }>(`/api/zones/${zone.id}/dnssec/rollover`);
            setData(r);
            toast(r.message);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        } finally {
            setBusy(false);
        }
    };
    const tone = data.secure ? 'success' : data.state === 'on' ? 'warning' : '';
    const deleting = data.cds.length === 1 && data.cds[0] === '0 0 0 00';
    return (
        <div className="form-grid">
            <div className="span2">
                <SettingsRows rows={[
                    ['State', <Badge key="s" tone={tone}>{data.summary}</Badge>],
                    ['Policy', data.state === 'off' ? 'not signed' : 'one ECDSA P-256 key (algorithm 13), rolled only when you ask; NSEC3 without iterations'],
                    ['Keys', data.keys.map((k) => `${k.tag} (${k.role ?? (k.flags === 257 ? 'KSK/CSK' : 'ZSK')}${k.ds ? `, DS ${DS_STATE[k.ds] ?? k.ds}` : ''}${k.goal === 'hidden' ? ', retiring' : ''})`).join('; ') || '–'],
                    ['CDS published', data.state === 'off' ? '–' : deleting ? 'delete (asks the parent to remove the DS)' : data.cds.length ? data.cds.join('\n') : 'not yet: BIND publishes it once the key has reached every resolver'],
                    [hosted ? `DS in ${data.parent_zone} (hosted here)` : 'DS at the parent', data.parent_ds === null ? 'could not check' : data.parent_ds.length ? data.parent_ds.join('\n') : 'none'],
                ]} />
            </div>
            {hosted && data.state !== 'off' && <p className="span2 hint">{data.parent_zone} is hosted on this server: DNSOne keeps the DS records of {zone.name} there in step with its CDS, every 5 minutes or with Check now.</p>}
            {data.ds.length > 0 && !hosted && (
                <div className="span2">
                    <h3 className="form-section-title">DS record for the registrar</h3>
                    <p className="hint">Enter this at the registrar of {zone.name} (key tag, algorithm 13, digest type 2 = SHA-256, digest). Some registrars ask for the DNSKEY instead. Registries that read CDS records (RFC 8078) take it from the zone by themselves.</p>
                    <pre className="zone-preview">{data.keys.filter((k) => k.ds_record && k.goal !== 'hidden').map((k) => `${zone.name}. IN DS ${k.ds_record}`).join('\n')}</pre>
                    <pre className="zone-preview">{data.keys.filter((k) => k.flags === 257 && k.goal !== 'hidden').map((k) => `${zone.name}. IN DNSKEY ${k.dnskey}`).join('\n')}</pre>
                </div>
            )}
            {data.bind_status && <details className="span2"><summary>BIND key status</summary><pre className="zone-preview">{data.bind_status}</pre></details>}
            {canManage && (
                <FormActions>
                    {data.state === 'on'
                        ? <button type="button" className="danger" disabled={busy} onClick={() => void set(false)}>Stop signing</button>
                        : <button type="button" className="primary" disabled={busy || zone.status !== 'active'} onClick={() => void set(true)}>Sign this zone</button>}
                    {data.state === 'on' && <button type="button" disabled={busy || data.rolling} title={data.rolling ? 'Not yet: a rollover is under way, or the DS is not at the parent yet' : undefined} onClick={() => void rollover()}>Roll the key</button>}
                    {data.state !== 'off' && <button type="button" disabled={busy} onClick={() => void check()}>Check the parent now</button>}
                    <button type="button" onClick={() => void reload()}>Refresh</button>
                </FormActions>
            )}
        </div>
    );
}
