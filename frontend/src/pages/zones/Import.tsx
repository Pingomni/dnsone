import { Link, router } from '@inertiajs/react';
import { useState } from 'react';
import { useToast } from '@/components/dns/feedback';
import { ErrorSummary, Field, FormActions, Panel } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, post } from '@/lib/api';
import { EMPTY_SOURCE, ImportResult, SourceFields, sourceBody, type ImportReport, type Source } from './Tools';

type Created = ImportReport & { zone: { id?: number; name: string; default_ttl: number; soa_mname: string; soa_rname: string } };

/** A new zone from a zone file or an AXFR: moving customers from another DNS server. */
export default function ZoneImport() {
    const toast = useToast();
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [rname, setRname] = useState('');
    const [source, setSource] = useState<Source>(EMPTY_SOURCE);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [preview, setPreview] = useState<Created | null>(null);
    const [busy, setBusy] = useState(false);

    const run = async (dryRun: boolean) => {
        setBusy(true);
        try {
            const result = await post<Created>('/api/zones/import', { name, description, soa_rname: rname || null, ...sourceBody(source), dry_run: dryRun });
            setErrors({});
            if (dryRun) {
                setPreview(result);
                return;
            }
            toast(`Zone ${result.zone.name} created with ${result.added} records. Publishing to BIND…`);
            router.get(`/zones/${result.zone.id}`);
        } catch (e) {
            const err = e as ApiError;
            setErrors(Object.keys(err.errors).length ? err.errors : { name: err.message });
            setPreview(null);
        } finally {
            setBusy(false);
        }
    };

    return (
        <AppLayout title="Import a zone">
            <div className="toolbar"><Link className="button" href="/zones">Back to zones</Link></div>
            <Panel title="Import a zone">
                <p className="hint">Creates the zone with the SOA, name servers and records of the file (or of the zone on the old server). Every record is checked as if typed in; anything DNSOne does not manage is listed, not imported.</p>
                <ErrorSummary errors={errors} />
                <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void run(false); }}>
                    <Field label="Domain" name="name" required autoComplete="off" spellCheck={false} placeholder="example.com" value={name} error={errors.name}
                        onChange={(e) => { setName(e.target.value); setPreview(null); }} />
                    <Field label="Description" name="description" autoComplete="off" hint="Optional, e.g. the customer." value={description} error={errors.description} onChange={(e) => setDescription(e.target.value)} />
                    <SourceFields source={source} setSource={(s) => { setSource(s); setPreview(null); }} errors={errors} />
                    <Field label="Zone contact, if the file has no SOA" name="soa_rname" type="email" autoComplete="off" placeholder="hostmaster@example.com" value={rname} error={errors.soa_rname} onChange={(e) => setRname(e.target.value)} />
                    {preview && (
                        <>
                            <p className="span2 hint">SOA {preview.zone.soa_mname} {preview.zone.soa_rname}, default TTL {preview.zone.default_ttl} s (the most common TTL in the file).</p>
                            <ImportResult report={preview} preview />
                        </>
                    )}
                    <FormActions>
                        <button type="button" disabled={busy} onClick={() => void run(true)}>Preview</button>
                        <button className="primary" disabled={busy}>{busy ? 'Importing…' : 'Create zone'}</button>
                    </FormActions>
                </form>
            </Panel>
        </AppLayout>
    );
}
