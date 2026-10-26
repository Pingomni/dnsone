// SPDX-License-Identifier: Elastic-2.0
// DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
// Settings → Query log export (syslog, dnstap) and Settings → Single sign-on (OpenID Connect).
import { useState } from 'react';
import { useToast } from '@/components/dns/feedback';
import { SettingsRows, Sheet } from '@/components/settings';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select } from '@/components/ui';
import { ApiError, post, put, useApi } from '@/lib/api';

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

// --------------------------------------------------------------------------- export

type Syslog = { enabled: boolean; host: string; port: number; protocol: 'udp' | 'tcp'; format: 'json' | 'text'; facility: string; only: 'all' | 'blocked' };
type Dnstap = { enabled: boolean; target: string; queries: boolean; responses: boolean };
type Export = { syslog: Syslog; dnstap: Dnstap; nodes: { node: string; export: { enabled: boolean; sent: number; dropped: number; error: string | null } | null; updated_at: string }[] };

export function ExportTab() {
    const { data, setData, error } = useApi<Export>('/api/settings/export');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    return <ExportForm key={JSON.stringify([data.syslog, data.dnstap])} data={data} onSaved={setData} />;
}

function ExportForm({ data, onSaved }: { data: Export; onSaved: (d: Export) => void }) {
    const toast = useToast();
    const [syslog, setSyslog] = useState(data.syslog);
    const [tap, setTap] = useState(data.dnstap);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const s = (patch: Partial<Syslog>) => setSyslog({ ...syslog, ...patch });
    return (
        <>
            <Sheet title="Query log export" icon="logs" meta={<>{syslog.enabled && <Badge tone="success">syslog</Badge>} {tap.enabled && <Badge tone="success">dnstap</Badge>}</>}>
                <ErrorSummary errors={errors} />
                <form className="form-grid" onSubmit={async (e) => {
                    e.preventDefault();
                    setBusy(true);
                    try {
                        onSaved(await put<Export>('/api/settings/export', { syslog, dnstap: tap }));
                        setErrors({});
                        toast('Saved. The collector picks it up within 15 seconds; dnsdist within 2 seconds.');
                    } catch (err) {
                        setErrors(errorsOf(err, 'syslog.host'));
                    } finally {
                        setBusy(false);
                    }
                }}>
                    <h3 className="span2 form-section-title">Syslog (SIEM)</h3>
                    <div className="span2">
                        <Check label="Send every answer as a syslog message: client, name, type, reply, verdict (ok, blocked, allowed, court order) and client group" checked={syslog.enabled} onChange={(e) => s({ enabled: e.target.checked })} />
                    </div>
                    <Field label="Collector" name="syslog.host" spellCheck={false} placeholder="siem.isp.example or 192.0.2.50" value={syslog.host} error={errors['syslog.host']} onChange={(e) => s({ host: e.target.value })} />
                    <Field label="Port" name="syslog.port" type="number" min={1} max={65535} value={syslog.port} error={errors['syslog.port']} onChange={(e) => s({ port: Number(e.target.value) })} />
                    <Select label="Protocol" name="syslog.protocol" value={syslog.protocol} options={[{ value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP (queued, reconnects)' }]} onChange={(e) => s({ protocol: e.target.value as Syslog['protocol'] })} />
                    <Select label="Message" name="syslog.format" value={syslog.format} options={[{ value: 'json', label: 'RFC 5424 with JSON' }, { value: 'text', label: 'RFC 5424 with key=value' }]} onChange={(e) => s({ format: e.target.value as Syslog['format'] })} />
                    <Select label="Facility" name="syslog.facility" value={syslog.facility} options={Array.from({ length: 8 }, (_, i) => ({ value: `local${i}`, label: `local${i}` }))} onChange={(e) => s({ facility: e.target.value })} />
                    <Select label="Which answers" name="syslog.only" value={syslog.only} options={[{ value: 'all', label: 'All' }, { value: 'blocked', label: 'Blocked and court orders only' }]} onChange={(e) => s({ only: e.target.value as Syslog['only'] })} />
                    <p className="span2 hint">Privacy levels apply (Settings → Privacy): hidden domains and clients stay hidden, and "totals only" sends nothing. Messages are dropped, never DNS, if the collector is slow.</p>

                    <h3 className="span2 form-section-title">dnstap</h3>
                    <div className="span2">
                        <Check label="Stream the raw DNS messages from dnsdist in dnstap (Frame Streams), for dnstap collectors" checked={tap.enabled} onChange={(e) => setTap({ ...tap, enabled: e.target.checked })} />
                    </div>
                    <Field label="Collector" name="dnstap.target" spellCheck={false} placeholder="192.0.2.50:6000 or /run/dnstap.sock" value={tap.target} error={errors['dnstap.target']} onChange={(e) => setTap({ ...tap, target: e.target.value })} />
                    <div>
                        <Check label="Queries" checked={tap.queries} onChange={(e) => setTap({ ...tap, queries: e.target.checked })} />
                        <Check label="Responses" checked={tap.responses} onChange={(e) => setTap({ ...tap, responses: e.target.checked })} />
                    </div>
                    <p className="span2 hint">dnstap carries every message as it is (no verdict, not filtered by privacy level). Each node streams its own.</p>
                    <FormActions><button className="primary" disabled={busy}>Save</button></FormActions>
                </form>
            </Sheet>
            {data.nodes.length > 0 && (
                <Sheet title="Sent" icon="activity">
                    <SettingsRows rows={data.nodes.map((n) => [n.node, n.export?.enabled ? `${n.export.sent.toLocaleString()} sent, ${n.export.dropped.toLocaleString()} dropped${n.export.error ? `; ${n.export.error}` : ''}` : 'syslog off'])} />
                </Sheet>
            )}
        </>
    );
}

// --------------------------------------------------------------------------- single sign-on

type Mapping = { value: string; role: string };
type Sso = {
    enabled: boolean; issuer: string; client_id: string; client_secret_set: boolean; label: string; scopes: string; public_url: string; redirect_uri: string;
    role_claim: string; role_map: Mapping[]; default_role: string; auto_create: boolean; allowed_domains: string[]; username_claim: string; end_session: boolean;
};
type ProviderCheck = { issuer: string; authorization_endpoint: string; token_endpoint: string; userinfo_endpoint: string | null; end_session_endpoint: string | null; keys: number; problems: string[]; redirect_uri: string };

export function SsoTab() {
    const { data, setData, error } = useApi<{ config: Sso; roles: string[] }>('/api/settings/sso');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    return <SsoForm key={JSON.stringify(data.config)} config={data.config} roles={data.roles} onSaved={setData} />;
}

function SsoForm({ config, roles, onSaved }: { config: Sso; roles: string[]; onSaved: (d: { config: Sso; roles: string[] }) => void }) {
    const toast = useToast();
    const [form, setForm] = useState({ ...config, client_secret: '', domains: config.allowed_domains.join(', ') });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const [checked, setChecked] = useState<ProviderCheck | null>(null);
    const roleOptions = roles.map((r) => ({ value: r, label: r }));
    const setMap = (i: number, patch: Partial<Mapping>) => setForm({ ...form, role_map: form.role_map.map((m, j) => (j === i ? { ...m, ...patch } : m)) });
    const body = () => ({ ...form, allowed_domains: form.domains.split(/[\s,]+/).filter(Boolean) });
    const save = async () => {
        setBusy(true);
        try {
            onSaved(await put<{ config: Sso; roles: string[] }>('/api/settings/sso', body()));
            setErrors({});
            toast(form.enabled ? 'Saved. The sign-in page now offers single sign-on.' : 'Saved.');
            return true;
        } catch (err) {
            setErrors(errorsOf(err, 'issuer'));
            return false;
        } finally {
            setBusy(false);
        }
    };
    const test = async () => {
        if (!(await save())) return;
        try {
            setChecked(await post<ProviderCheck>('/api/settings/sso/test'));
        } catch (err) {
            setChecked(null);
            toast((err as ApiError).message, 'danger');
        }
    };
    const callback = form.public_url ? `${form.public_url.replace(/\/$/, '')}/api/auth/oidc/callback` : `${window.location.origin}/api/auth/oidc/callback`;
    return (
        <>
            <Sheet title="Single sign-on" icon="lock" meta={<Badge tone={config.enabled ? 'success' : ''}>{config.enabled ? 'on' : 'off'}</Badge>}>
                <p className="hint panel-text">Operators sign in with your identity provider: Google Workspace, Microsoft Entra ID, Okta, Authentik, Keycloak or any other OpenID Connect provider. Register DNSOne there as a confidential web application with this redirect URI: <code>{callback}</code>. DNSOne accounts keep working beside it (keep one as break-glass access).</p>
                <ErrorSummary errors={errors} />
                <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void save(); }}>
                    <div className="span2"><Check label="Offer single sign-on on the sign-in page" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /></div>
                    <Field label="Issuer" name="issuer" spellCheck={false} placeholder="https://login.microsoftonline.com/TENANT/v2.0" hint="DNSOne reads <issuer>/.well-known/openid-configuration." value={form.issuer} error={errors.issuer} onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
                    <Field label="Console address" name="public_url" spellCheck={false} placeholder={window.location.origin} hint="How operators reach this console; the redirect URI is made from it." value={form.public_url} error={errors.public_url} onChange={(e) => setForm({ ...form, public_url: e.target.value })} />
                    <Field label="Client id" name="client_id" spellCheck={false} autoComplete="off" value={form.client_id} error={errors.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
                    <Field label="Client secret" name="client_secret" type="password" autoComplete="new-password" placeholder={config.client_secret_set ? 'unchanged' : ''} value={form.client_secret} error={errors.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />
                    <Field label="Button label" name="label" value={form.label} error={errors.label} onChange={(e) => setForm({ ...form, label: e.target.value })} />
                    <Field label="Scopes" name="scopes" spellCheck={false} value={form.scopes} error={errors.scopes} hint="Add groups (Okta, Authentik) or the scope that makes your provider send groups or roles." onChange={(e) => setForm({ ...form, scopes: e.target.value })} />

                    <h3 className="span2 form-section-title">Roles</h3>
                    <Field label="Claim with the user's groups or roles" name="role_claim" spellCheck={false} placeholder="groups" hint="e.g. groups, roles, realm_access.roles (a dotted path)." value={form.role_claim} error={errors.role_claim} onChange={(e) => setForm({ ...form, role_claim: e.target.value })} />
                    <Select label="Role when no mapping matches (new accounts)" name="default_role" placeholder="None: refuse the sign-in" options={roleOptions} value={form.default_role} error={errors.default_role} onChange={(e) => setForm({ ...form, default_role: e.target.value })} />
                    <div className="span2 row-editor">
                        {form.role_map.map((m, i) => (
                            <div className="row-editor-row" key={i}>
                                <Field label="When the claim contains" name={`role_map.${i}.value`} spellCheck={false} placeholder="dns-admins" value={m.value} error={errors[`role_map.${i}.value`]} onChange={(e) => setMap(i, { value: e.target.value })} />
                                <Select label="DNSOne role" name={`role_map.${i}.role`} placeholder="Choose…" options={roleOptions} value={m.role} error={errors[`role_map.${i}.role`]} onChange={(e) => setMap(i, { role: e.target.value })} />
                                <button type="button" onClick={() => setForm({ ...form, role_map: form.role_map.filter((_, j) => j !== i) })}>Remove</button>
                            </div>
                        ))}
                        <div><button type="button" onClick={() => setForm({ ...form, role_map: [...form.role_map, { value: '', role: '' }] })}>Add mapping</button></div>
                        <p className="hint">The first match wins: list the most powerful role first. A mapped role is set at every sign-in; without a match an existing account keeps its role.</p>
                    </div>

                    <h3 className="span2 form-section-title">Accounts</h3>
                    <div className="span2">
                        <Check label="Create a DNSOne account at a user's first sign-in (otherwise only invited accounts: Settings → Users, sign-in “Single sign-on”, matched by email)" checked={form.auto_create} onChange={(e) => setForm({ ...form, auto_create: e.target.checked })} />
                        <Check label="Signing out of DNSOne also signs out of the provider" checked={form.end_session} onChange={(e) => setForm({ ...form, end_session: e.target.checked })} />
                    </div>
                    <Field label="Only these email domains (optional)" name="allowed_domains" spellCheck={false} placeholder="isp.example, noc.isp.example" value={form.domains} error={errors.allowed_domains} onChange={(e) => setForm({ ...form, domains: e.target.value })} />
                    <Field label="Username from claim" name="username_claim" spellCheck={false} value={form.username_claim} error={errors.username_claim} onChange={(e) => setForm({ ...form, username_claim: e.target.value })} />
                    <FormActions>
                        <button type="button" disabled={busy || !form.issuer} onClick={() => void test()}>Save and test</button>
                        <button className="primary" disabled={busy}>Save</button>
                    </FormActions>
                </form>
            </Sheet>
            {checked && (
                <Sheet title="Provider" icon="activity" meta={<Badge tone={checked.problems.length ? 'warning' : 'success'}>{checked.problems.length ? 'check the settings' : 'looks right'}</Badge>}>
                    {checked.problems.length > 0 && <div className="flash warning">{checked.problems.join(' ')}</div>}
                    <SettingsRows rows={[
                        ['Issuer', checked.issuer], ['Authorization', checked.authorization_endpoint], ['Token', checked.token_endpoint],
                        ['User info', checked.userinfo_endpoint ?? '-'], ['Sign-out', checked.end_session_endpoint ?? 'not offered'], ['Signing keys', String(checked.keys)],
                        ['Redirect URI to register', checked.redirect_uri],
                    ]} />
                </Sheet>
            )}
        </>
    );
}
