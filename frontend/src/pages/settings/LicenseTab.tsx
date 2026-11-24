// Settings → License: this server's licence, the free DNSOne Community one (it registers the server) or a DNSOne Pro one.
import { useState, type ReactNode } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { SettingsRows, Sheet } from '@/components/settings';
import { Badge, Empty, ErrorSummary, FormActions, TextArea } from '@/components/ui';
import { ApiError, del, put, useApi } from '@/lib/api';

export type License = {
    state: 'none' | 'valid' | 'expired'; id: string | null; customer: string | null; issued?: string; expires: string | null; days_left?: number;
    edition: 'community' | 'pro' | null; features: string[]; all_features: Record<string, string>; error?: string;
    activation: Activation;
    server: string | null; servers: number | null; server_id: string; servers_used: number; servers_licensed: number | null; over: boolean;
};

/** The licence's registration with the PingOmni account portal (report only: Pro never depends on it). */
type Activation = {
    status: 'off' | 'replica' | 'pending' | 'registered' | 'in_use' | 'refused' | 'unreachable';
    message: string; account_url: string; hostname: string | null; last_ok: string | null; last_attempt: string | null;
};

// The free DNSOne Community licence, in the PingOmni account.
export const REGISTER_URL = 'https://account.pingomni.com/buy?product=dnsone&plan=Community&period=12';

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

function stateLabel(lic: License): [string, 'success' | 'warning' | undefined] {
    if (lic.state === 'none') return ['DNSOne Community (not registered)', 'warning'];
    const community = lic.edition === 'community';
    if (lic.state === 'expired') return [community ? 'Community licence expired' : 'Pro licence expired', 'warning'];
    return [community ? 'DNSOne Community (registered)' : 'DNSOne Pro', 'success'];
}

/** What installing a key says: the free key registers the server, a Pro key turns its features on. */
export const installedMessage = (lic: License) => (lic.edition === 'community'
    ? `Free DNSOne Community licence for ${lic.customer} installed: this server is registered.`
    : `Licence for ${lic.customer} installed: the Pro features are on. DNS picks them up within a minute.`);

/** Pasting a licence key (Settings → License, and the "Register this server" screen). */
export function LicenseKeyForm({ replace, onInstalled, children }: { replace: boolean; onInstalled: (lic: License) => void; children?: ReactNode }) {
    const [key, setKey] = useState('');
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const install = async () => {
        setBusy(true);
        try {
            const lic = await put<License>('/api/settings/license', { key });
            setErrors({});
            setKey('');
            onInstalled(lic);
        } catch (e) {
            const ae = e as ApiError;
            setErrors(Object.keys(ae.errors).length ? ae.errors : { key: ae.message });
        } finally {
            setBusy(false);
        }
    };
    return (
        <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void install(); }}>
            <ErrorSummary errors={errors} />
            <TextArea label="Licence key" name="key" className="span2" rows={4} spellCheck={false} required value={key} error={errors.key}
                placeholder="DNSONE1.…" hint="Paste the whole key from your PingOmni account. It is checked on this server; the server then registers with your account, so you see it there. DNS never depends on that."
                onChange={(e) => setKey(e.target.value)} />
            <FormActions>
                <button className="primary" disabled={busy || !key.trim()}>{replace ? 'Replace licence' : 'Add licence'}</button>
                {children}
            </FormActions>
        </form>
    );
}

export function LicenseTab() {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, error } = useApi<License>('/api/settings/license');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    const [label, tone] = stateLabel(data);
    const community = data.edition === 'community';

    // The console shows the Pro pages from the licence it signed in with: reload it once the licence changes.
    const changed = (message: string) => {
        toast(message);
        window.setTimeout(() => window.location.reload(), 1200);
    };
    const remove = async () => {
        const message = community
            ? 'This server is no longer registered: once its grace has ended, the console asks for a key again. DNS keeps answering as before.'
            : 'The Pro features stop at once: DNSOne runs as Community, and the server is no longer registered. Their settings stay in the database, so installing a licence again brings them back.';
        if (!(await ask({ title: 'Remove the licence?', message, confirmLabel: 'Remove', typeToConfirm: 'remove' }))) return;
        try {
            setData(await del<License>('/api/settings/license'));
            changed('Licence removed: DNSOne runs as Community, not registered.');
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
                {data.state === 'none' || community ? (
                    <p className="panel-text">
                        This server runs DNSOne Community: hosted zones, the customer resolver, ad-blocking, client groups and the query log.
                        {data.state === 'none' && <> Every server is registered with a licence key: the DNSOne Community one is free, for a year, and renewed for free. Get it at <a href={REGISTER_URL} target="_blank" rel="noreferrer">account.pingomni.com</a> and paste it below.</>}
                        {' '}A DNSOne Pro licence adds the features below. Licences, installation and support: <a href="https://pingomni.com/dnsone/" target="_blank" rel="noreferrer">pingomni.com/dnsone</a>.
                    </p>
                ) : null}
                {data.state !== 'none' && (
                    <SettingsRows rows={[
                        ['Licensed to', data.customer],
                        ['Valid until', data.state === 'expired' ? `${data.expires} (expired)` : `${data.expires}${data.days_left !== undefined ? ` (${data.days_left} days left)` : ''}`],
                        ['Servers', data.servers_licensed === null ? 'any number' : `${data.servers_used} of ${data.servers_licensed}`],
                        ['Licence', data.id],
                        ['PingOmni account', accountRow(data.activation)],
                    ]} />
                )}
                {data.state === 'expired' && (community ? (
                    <p className="panel-text warning-text">
                        Renew your free licence at <a href={REGISTER_URL} target="_blank" rel="noreferrer">account.pingomni.com</a>: 30 days after it expired, the console asks for a key again. DNS keeps answering as before.
                    </p>
                ) : (
                    <p className="panel-text warning-text">
                        The Pro features keep running as they were, so DNS answers do not change, but they cannot be changed until the licence is renewed.
                    </p>
                ))}
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
                <LicenseKeyForm replace={data.state !== 'none'} onInstalled={(lic) => { setData(lic); changed(installedMessage(lic)); }}>
                    {data.state !== 'none' && <button type="button" className="danger" onClick={() => void remove()}>Remove licence</button>}
                </LicenseKeyForm>
            </Sheet>
        </>
    );
}
