// Settings → License: this server's DNSOne Pro licence. Without one DNSOne runs as Community.
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { SettingsRows, Sheet } from '@/components/settings';
import { Badge, Empty, ErrorSummary, FormActions, TextArea } from '@/components/ui';
import { ApiError, del, put, useApi } from '@/lib/api';

type License = {
    state: 'none' | 'valid' | 'expired'; id: string | null; customer: string | null; issued?: string; expires: string | null; days_left?: number;
    features: string[]; all_features: Record<string, string>; error?: string;
    activation: Activation;
    server: string | null; servers: number | null; server_id: string; servers_used: number; servers_licensed: number | null; over: boolean;
};

/** The licence's registration with the PingOmni account portal (report only: Pro never depends on it). */
type Activation = {
    status: 'off' | 'replica' | 'pending' | 'registered' | 'in_use' | 'refused' | 'unreachable';
    message: string; account_url: string; hostname: string | null; last_ok: string | null; last_attempt: string | null;
};

const when = (iso: string | null) => (iso ? iso.replace('T', ' ').slice(0, 16) + ' UTC' : '');

function accountRow(a: Activation): string {
    switch (a.status) {
        case 'registered': return `Registered as ${a.hostname ?? 'this server'}, last check-in ${when(a.last_ok)}`;
        case 'pending': return 'Registering with your PingOmni account (within a minute)';
        case 'in_use': return `Not registered: ${a.message}`;
        case 'refused': return `Not registered: ${a.message}`;
        case 'unreachable': return `Not registered yet: ${a.message} Retried every hour.`;
        case 'replica': return 'Registered by the primary node';
        default: return 'Off (DNSONE_ACCOUNT_URL is empty)';
    }
}

const STATE: Record<License['state'], [string, 'success' | 'warning' | undefined]> = {
    none: ['DNSOne Community', undefined],
    valid: ['DNSOne Pro', 'success'],
    expired: ['Pro licence expired', 'warning'],
};

export function LicenseTab() {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, error } = useApi<License>('/api/settings/license');
    const [key, setKey] = useState('');
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    const [label, tone] = STATE[data.state];

    // The console shows the Pro pages from the licence it signed in with: reload it once the licence changes.
    const changed = (message: string) => {
        toast(message);
        window.setTimeout(() => window.location.reload(), 1200);
    };
    const install = async () => {
        setBusy(true);
        try {
            const lic = await put<License>('/api/settings/license', { key });
            setData(lic);
            setErrors({});
            setKey('');
            changed(`Licence for ${lic.customer} installed: the Pro features are on. DNS picks them up within a minute.`);
        } catch (e) {
            const ae = e as ApiError;
            setErrors(Object.keys(ae.errors).length ? ae.errors : { key: ae.message });
        } finally {
            setBusy(false);
        }
    };
    const remove = async () => {
        if (!(await ask({ title: 'Remove the licence?', message: 'The Pro features stop at once: DNSOne runs as Community. Their settings stay in the database, so installing a licence again brings them back.', confirmLabel: 'Remove', typeToConfirm: 'remove' }))) return;
        try {
            setData(await del<License>('/api/settings/license'));
            changed('Licence removed: DNSOne runs as Community.');
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <>
            <Sheet title="Licence" icon="lock" meta={<Badge tone={tone}>{label}</Badge>}>
                <SettingsRows rows={[
                    ['This server\'s ID', <span className="license-server-id"><code>{data.server_id}</code> <button type="button" className="link" onClick={() => void navigator.clipboard?.writeText(data.server_id).then(() => toast('Server ID copied.'))}>Copy</button></span>],
                ]} />
                <p className="hint panel-text">A licence is issued for this ID. For a cluster, one licence covers all its servers: give the ID of any one of them (the primary's) and how many servers there are.</p>
                {data.state === 'none' ? (
                    <p className="panel-text">
                        This server runs DNSOne Community: hosted zones, the customer resolver, ad-blocking, client groups and the query log.
                        A DNSOne Pro licence adds the features below. Licences, installation and support: <a href="https://pingomni.com/dnsone/" target="_blank" rel="noreferrer">pingomni.com/dnsone</a>.
                    </p>
                ) : (
                    <SettingsRows rows={[
                        ['Licensed to', data.customer],
                        ['Valid until', data.state === 'expired' ? `${data.expires} (expired)` : `${data.expires}${data.days_left !== undefined ? ` (${data.days_left} days left)` : ''}`],
                        ['Servers', data.servers_licensed === null ? 'any number' : `${data.servers_used} of ${data.servers_licensed}`],
                        ['Licence', data.id],
                        ['PingOmni account', accountRow(data.activation)],
                    ]} />
                )}
                {data.state === 'expired' && (
                    <p className="panel-text warning-text">
                        The Pro features keep running as they were, so DNS answers do not change, but they cannot be changed until the licence is renewed.
                    </p>
                )}
                {data.over && (
                    <p className="panel-text warning-text">
                        {data.servers_used} servers run with this licence, which covers {data.servers_licensed}. DNS keeps working; ask for a licence that covers all {data.servers_used}.
                    </p>
                )}
                {data.error && <p className="panel-text warning-text">The stored licence key was ignored: {data.error}</p>}
                <div className="panel-text">
                    <ul className="license-features">
                        {Object.entries(data.all_features).map(([feature, name]) => (
                            <li key={feature}><Badge tone={data.features.includes(feature) ? 'success' : undefined}>{data.features.includes(feature) ? 'on' : 'off'}</Badge>{name}</li>
                        ))}
                    </ul>
                </div>
            </Sheet>
            <Sheet title={data.state === 'none' ? 'Add a licence' : 'Replace the licence'} icon="plus">
                <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void install(); }}>
                    <ErrorSummary errors={errors} />
                    <TextArea label="Licence key" name="key" className="span2" rows={4} spellCheck={false} required value={key} error={errors.key}
                        placeholder="DNSONE1.…" hint="Paste the whole key from your PingOmni account. It is checked on this server; the server then registers with your account, so you see it there. Pro never depends on that."
                        onChange={(e) => setKey(e.target.value)} />
                    <FormActions>
                        <button className="primary" disabled={busy || !key.trim()}>{data.state === 'none' ? 'Add licence' : 'Replace licence'}</button>
                        {data.state !== 'none' && <button type="button" className="danger" onClick={() => void remove()}>Remove licence</button>}
                    </FormActions>
                </form>
            </Sheet>
        </>
    );
}
