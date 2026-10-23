// Settings → Single sign-on: Keycloak's operators and realm settings, managed from DNSOne.
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import { SettingsRows, Sheet } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Tabs } from '@/components/tabs';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select } from '@/components/ui';
import { ApiError, del, patch, post, put, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { query } from '@/lib/format';

type Overview = {
    enabled: boolean; admin_api: boolean; local_login: boolean; realm: string; issuer: string; admin_console: string; account_console: string;
    roles: { keycloak: string; dnsone: string }[]; local_accounts: string[];
};
type SsoUser = {
    id: string; username: string; email: string; first_name: string; last_name: string; name: string; enabled: boolean; role: string | null;
    two_factor: boolean; passkey: boolean; required_actions: string[]; federated: boolean; last_login_at: string | null; self: boolean;
    sessions?: { ip: string; started: number; last_access: number; clients: string[] }[];
};
type Page<T> = { rows: T[]; total: number; page: number; pages: number; size: number };

const ROLES = [{ value: 'admin', label: 'Administrator' }, { value: 'operator', label: 'Operator' }, { value: 'viewer', label: 'Viewer (read-only)' }];

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

/** A password DNSOne generated: shown once, here, until dismissed. */
function Secret({ secret, onDone }: { secret: { who: string; password: string } | null; onDone: () => void }) {
    if (!secret) return null;
    return (
        <div className="flash warning" role="status">
            <strong>Temporary password for {secret.who}: </strong><code>{secret.password}</code>
            <p className="hint">Shown only now. Hand it over safely; Keycloak asks for a new password at the first sign-in.</p>
            <button type="button" onClick={onDone}>Done</button>
        </div>
    );
}

function UserDialog({ user, onClose, onSaved }: { user: SsoUser | 'new' | null; onClose: () => void; onSaved: (secret?: { who: string; password: string }) => void }) {
    const editing = user && user !== 'new' ? user : null;
    const [form, setForm] = useState({
        username: editing?.username ?? '', first_name: editing?.first_name ?? '', last_name: editing?.last_name ?? '', email: editing?.email ?? '',
        role: editing?.role ?? 'operator', method: 'generate', password: '', require_2fa: editing ? editing.required_actions.includes('CONFIGURE_TOTP') : false,
    });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <FormDialog open={user !== null} title={editing ? `Edit ${editing.username}` : 'New operator'} submitLabel={editing ? 'Save' : 'Create operator'} busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                if (editing) {
                    await patch(`/api/sso/users/${editing.id}`, { first_name: form.first_name, last_name: form.last_name, email: form.email, role: form.role, require_2fa: form.require_2fa });
                    onSaved();
                } else {
                    const r = await post<{ temporary_password: string | null }>('/api/sso/users', {
                        username: form.username, first_name: form.first_name, last_name: form.last_name, email: form.email, role: form.role,
                        password: form.method === 'set' ? form.password : '', temporary: true, invite: form.method === 'invite', require_2fa: form.require_2fa,
                    });
                    onSaved(r.temporary_password ? { who: form.username, password: r.temporary_password } : undefined);
                }
                onClose();
            } catch (e) {
                setErrors(errorsOf(e, 'username'));
            } finally {
                setBusy(false);
            }
        }}>
            <ErrorSummary errors={errors} />
            <div className="form-grid">
                <Field label="Username" name="username" required disabled={Boolean(editing)} autoComplete="off" spellCheck={false} value={form.username} error={errors.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
                <Select label="DNSOne role" name="role" options={ROLES} value={form.role} error={errors.role} onChange={(e) => setForm({ ...form, role: e.target.value })} />
                <Field label="First name" name="first_name" value={form.first_name} onChange={(e) => setForm({ ...form, first_name: e.target.value })} />
                <Field label="Last name" name="last_name" value={form.last_name} onChange={(e) => setForm({ ...form, last_name: e.target.value })} />
                <Field label="Email" name="email" type="email" className="span2" value={form.email} error={errors.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
                {!editing && (
                    <fieldset className="span2 group-picks">
                        <legend>First password</legend>
                        <Check type="radio" name="method" label="Generate a temporary password (shown once)" checked={form.method === 'generate'} onChange={() => setForm({ ...form, method: 'generate' })} />
                        <Check type="radio" name="method" label="Email an invitation to set a password (needs the Email tab)" checked={form.method === 'invite'} onChange={() => setForm({ ...form, method: 'invite' })} />
                        <Check type="radio" name="method" label="Set a temporary password now" checked={form.method === 'set'} onChange={() => setForm({ ...form, method: 'set' })} />
                    </fieldset>
                )}
                {!editing && form.method === 'set' && (
                    <Field label="Temporary password" name="password" type="password" autoComplete="new-password" className="span2" value={form.password} error={errors.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                )}
                <div className="span2"><Check label="Must set up two-factor sign-in (authenticator app) at the next sign-in" checked={form.require_2fa} onChange={(e) => setForm({ ...form, require_2fa: e.target.checked })} /></div>
            </div>
        </FormDialog>
    );
}

function UsersPanel({ overview, onChanged }: { overview: Overview; onChanged: () => void }) {
    const toast = useToast();
    const ask = useConfirm();
    const [q, setQ] = useState('');
    const [search, setSearch] = useState('');
    const [page, setPage] = useState(1);
    const { data, error, reload } = useApi<Page<SsoUser>>(`/api/sso/users${query({ q: search, page: String(page) })}`);
    const [dialog, setDialog] = useState<SsoUser | 'new' | null>(null);
    const [secret, setSecret] = useState<{ who: string; password: string } | null>(null);
    const [moved, setMoved] = useState<{ username: string; temporary_password: string | null; linked: boolean }[] | null>(null);

    const act = async (label: string, fn: () => Promise<unknown>) => {
        try {
            await fn();
            toast(label);
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const resetPassword = async (u: SsoUser, email: boolean) => {
        if (!(await ask({ title: `New password for ${u.username}?`, message: email ? 'Keycloak emails a link to set a new password (valid 24 hours).' : 'A temporary password is generated and shown once; Keycloak asks for a new one at the next sign-in.', confirmLabel: email ? 'Send email' : 'Generate' }))) return;
        try {
            const r = await post<{ temporary_password: string | null }>(`/api/sso/users/${u.id}/password`, { email });
            if (r.temporary_password) setSecret({ who: u.username, password: r.temporary_password });
            else toast(`Password email sent to ${u.email}.`);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <>
            {overview.local_accounts.length > 0 && (
                <div className="flash warning" role="status">
                    <strong>{overview.local_accounts.length} account(s) still sign in with a DNSOne password: </strong>{overview.local_accounts.join(', ')}.{' '}
                    <button type="button" className="primary" onClick={async () => {
                        if (!(await ask({ title: 'Move local accounts to Keycloak?', message: 'Each gets a Keycloak user with the same username, email and role, and a temporary password shown once. Their DNSOne passwords and two-factor stop working; app passwords keep working.', confirmLabel: 'Move accounts' }))) return;
                        try {
                            setMoved((await post<{ moved: typeof moved }>('/api/sso/migrate-local-users')).moved);
                            onChanged();
                            void reload();
                        } catch (e) {
                            toast((e as ApiError).message, 'danger');
                        }
                    }}>Move them to Keycloak</button>
                </div>
            )}
            {moved && (
                <div className="flash warning" role="status">
                    <strong>Moved to Keycloak. Temporary passwords, shown only now:</strong>
                    <pre className="zone-preview">{moved.map((m) => `${m.username.padEnd(24)} ${m.linked ? '(linked to the existing Keycloak user)' : m.temporary_password}`).join('\n')}</pre>
                    <button type="button" onClick={() => setMoved(null)}>Done</button>
                </div>
            )}
            <Secret secret={secret} onDone={() => setSecret(null)} />
            <Sheet title="Operators" icon="clients" meta={<Badge>{data ? `${data.total} in Keycloak` : '…'}</Badge>}>
                <form className="toolbar list-filterbar" role="search" onSubmit={(e) => { e.preventDefault(); setPage(1); setSearch(q); }}>
                    <label className="list-search"><span>Search</span><input type="search" placeholder="Username, name or email" value={q} onChange={(e) => setQ(e.target.value)} /></label>
                    <div className="list-filter-buttons"><button>Search</button><button type="button" className="primary" onClick={() => setDialog('new')}>New operator</button></div>
                </form>
                {error && <div className="flash danger">{error.message}</div>}
                {data && (
                    <DataTable
                        rows={data.rows}
                        rowKey={(r) => r.id}
                        emptyText={search ? 'No operator matches.' : 'No operators in Keycloak yet.'}
                        columns={[
                            { header: 'Operator', cell: (r) => <div className="list-cell-stack"><span>{r.username} {r.self && <Badge>you</Badge>}</span><span className="list-subline">{[r.name, r.email].filter(Boolean).join(' · ') || '–'}</span></div> },
                            { header: 'Role', cell: (r) => (r.role ? <Badge>{r.role}</Badge> : <Badge tone="warning">no DNSOne role</Badge>) },
                            { header: 'Two-factor', cell: (r) => (r.two_factor ? <Badge tone="success">on</Badge> : r.required_actions.includes('CONFIGURE_TOTP') ? <Badge tone="warning">at next sign-in</Badge> : <span className="list-subline">off</span>) },
                            { header: 'Status', cell: (r) => (r.enabled ? (r.federated ? <Badge>directory</Badge> : <Badge tone="success">active</Badge>) : <Badge tone="danger">disabled</Badge>) },
                            { header: 'Last DNSOne sign-in', cell: (r) => <span className="mono">{r.last_login_at ?? '–'}</span> },
                            {
                                header: 'Actions', noExport: true, cell: (r) => (
                                    <div className="inline-actions">
                                        <button type="button" className="link" onClick={() => setDialog(r)}>Edit</button>
                                        <button type="button" className="link" onClick={() => void resetPassword(r, false)}>New password</button>
                                        {r.email && <button type="button" className="link" onClick={() => void resetPassword(r, true)}>Email reset</button>}
                                        {r.two_factor && <button type="button" className="link" onClick={async () => { if (await ask({ title: `Reset two-factor for ${r.username}?`, message: 'For a lost phone: their authenticator app is removed and they set one up at the next sign-in.', confirmLabel: 'Reset' })) void act(`Two-factor reset for ${r.username}.`, () => del(`/api/sso/users/${r.id}/two-factor`)); }}>Reset two-factor</button>}
                                        <button type="button" className="link" onClick={() => void act(`${r.username} signed out everywhere.`, () => post(`/api/sso/users/${r.id}/sign-out`))}>Sign out</button>
                                        {!r.self && <button type="button" className="link" onClick={() => void act(r.enabled ? `${r.username} disabled.` : `${r.username} enabled.`, () => patch(`/api/sso/users/${r.id}`, { enabled: !r.enabled }))}>{r.enabled ? 'Disable' : 'Enable'}</button>}
                                        {!r.self && <button type="button" className="link danger-text" onClick={async () => { if (await ask({ title: `Delete ${r.username}?`, message: 'The Keycloak user is deleted and their DNSOne sessions end. Their history in the audit log stays.', confirmLabel: 'Delete', typeToConfirm: r.username })) void act(`${r.username} deleted.`, () => del(`/api/sso/users/${r.id}`)); }}>Delete</button>}
                                    </div>
                                ),
                            },
                        ]}
                    />
                )}
                {data && data.pages > 1 && (
                    <div className="inline-actions panel-text">
                        <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
                        <span className="list-subline">Page {data.page} of {data.pages}</span>
                        <button type="button" disabled={page >= data.pages} onClick={() => setPage(page + 1)}>Next</button>
                    </div>
                )}
                <p className="hint panel-text">Roles: {overview.roles.map((r) => `${r.keycloak} → ${r.dnsone}`).join(', ')}. Without one of them, Keycloak lets people in but DNSOne does not. Disabling, deleting or signing someone out ends their DNSOne sessions at once.</p>
            </Sheet>
            {dialog && <UserDialog user={dialog} onClose={() => setDialog(null)} onSaved={(s) => { if (s) setSecret(s); toast('Saved.'); void reload(); }} />}
        </>
    );
}

type Security = {
    password: { length: number; upper: number; lower: number; digits: number; special: number; history: number; expire_days: number; not_username: boolean };
    brute_force: { enabled: boolean; max_failures: number; lock_minutes: number; permanent: boolean };
    two_factor_required: boolean; sessions: { idle_minutes: number; max_hours: number }; remember_me: boolean; reset_password: boolean;
};

function SecurityPanel() {
    const toast = useToast();
    const { data, error } = useApi<Security>('/api/sso/security');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    return <SecurityForm key={JSON.stringify(data)} initial={data} onSaved={(applied) => toast(applied ? `Saved. ${applied} operator(s) set up two-factor at their next sign-in.` : 'Saved.')} />;
}

function SecurityForm({ initial, onSaved }: { initial: Security; onSaved: (applied: number) => void }) {
    const [f, setF] = useState(initial);
    const [applyAll, setApplyAll] = useState(true);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const num = (section: 'password' | 'brute_force' | 'sessions', key: string, label: string, hint?: string) => (
        <Field label={label} name={`${section}.${key}`} type="number" min={0} hint={hint} value={(f[section] as Record<string, number | boolean>)[key] as number}
            error={errors[`${section}.${key}`]} onChange={(e) => setF({ ...f, [section]: { ...f[section], [key]: Number(e.target.value) } })} />
    );
    return (
        <Sheet title="Sign-in security" icon="lock">
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                    const r = await put<Security & { applied: number }>('/api/sso/security', { ...f, apply_to_existing: applyAll });
                    setErrors({});
                    onSaved(r.applied);
                } catch (err) {
                    setErrors(errorsOf(err, 'password.length'));
                } finally {
                    setBusy(false);
                }
            }}>
                <h3 className="span2 form-section-title">Two-factor sign-in</h3>
                <div className="span2">
                    <Check label="Required for everyone: operators without an authenticator app set one up at their next sign-in" checked={f.two_factor_required} onChange={(e) => setF({ ...f, two_factor_required: e.target.checked })} />
                    {f.two_factor_required && !initial.two_factor_required && <Check label="Also for existing operators (not only new ones)" checked={applyAll} onChange={(e) => setApplyAll(e.target.checked)} />}
                </div>
                <h3 className="span2 form-section-title">Passwords</h3>
                {num('password', 'length', 'Minimum length', '0: no rule. 12 or more is recommended.')}
                {num('password', 'expire_days', 'Expire after (days)', '0: never (current advice: do not expire, use two-factor).')}
                {num('password', 'upper', 'Upper-case letters')}
                {num('password', 'lower', 'Lower-case letters')}
                {num('password', 'digits', 'Digits')}
                {num('password', 'special', 'Special characters')}
                {num('password', 'history', 'Not the same as the last … passwords')}
                <div><Check label="Not the same as the username" checked={f.password.not_username} onChange={(e) => setF({ ...f, password: { ...f.password, not_username: e.target.checked } })} /></div>
                <h3 className="span2 form-section-title">Lockout after failed sign-ins</h3>
                <div className="span2"><Check label="Lock accounts after repeated wrong passwords (brute-force protection)" checked={f.brute_force.enabled} onChange={(e) => setF({ ...f, brute_force: { ...f.brute_force, enabled: e.target.checked } })} /></div>
                {num('brute_force', 'max_failures', 'Wrong passwords before locking')}
                {num('brute_force', 'lock_minutes', 'Locked for (minutes)')}
                <div className="span2"><Check label="Lock permanently until an administrator unlocks (Disable → Enable)" checked={f.brute_force.permanent} onChange={(e) => setF({ ...f, brute_force: { ...f.brute_force, permanent: e.target.checked } })} /></div>
                <h3 className="span2 form-section-title">Sessions</h3>
                {num('sessions', 'idle_minutes', 'Sign out after inactivity (minutes)')}
                {num('sessions', 'max_hours', 'Sign in again after (hours)')}
                <div className="span2">
                    <Check label={'"Remember me" on the sign-in page'} checked={f.remember_me} onChange={(e) => setF({ ...f, remember_me: e.target.checked })} />
                    <Check label={'"Forgot password?" on the sign-in page (needs the Email tab)'} checked={f.reset_password} onChange={(e) => setF({ ...f, reset_password: e.target.checked })} />
                </div>
                <FormActions><button className="primary" disabled={busy}>Save</button></FormActions>
            </form>
        </Sheet>
    );
}

type Provider = { alias: string; type: string; name: string; enabled: boolean; redirect_uri: string };
type Directory = { id: string; name: string; url: string; vendor: string; users_dn: string; bind_dn: string; enabled: boolean };

function ProvidersPanel() {
    const toast = useToast();
    const ask = useConfirm();
    const providers = useApi<{ providers: Provider[] }>('/api/sso/providers');
    const dirs = useApi<{ directories: Directory[] }>('/api/sso/ldap');
    const [p, setP] = useState({ type: 'google', client_id: '', client_secret: '', tenant: '', hosted_domain: '', alias: '', name: '', discovery_url: '' });
    const [d, setD] = useState({ name: 'Active Directory', vendor: 'ad', url: '', bind_dn: '', bind_password: '', users_dn: '', filter: '' });
    const [pErrors, setPErrors] = useState<Record<string, string>>({});
    const [dErrors, setDErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const run = async (fn: () => Promise<unknown>, done: string, setErr: (e: Record<string, string>) => void, field: string) => {
        setBusy(true);
        try {
            await fn();
            setErr({});
            toast(done);
            void providers.reload();
            void dirs.reload();
        } catch (e) {
            setErr(errorsOf(e, field));
        } finally {
            setBusy(false);
        }
    };
    return (
        <>
            <Sheet title="Sign in with another account" icon="user">
                {providers.data && (
                    <DataTable rows={providers.data.providers} rowKey={(r) => r.alias} emptyText="Only Keycloak usernames and passwords for now."
                        columns={[
                            { header: 'Provider', cell: (r) => <div className="list-cell-stack"><span>{r.name}</span><span className="list-subline">redirect URI: <code>{r.redirect_uri}</code></span></div> },
                            { header: 'Status', cell: (r) => (r.enabled ? <Badge tone="success">on</Badge> : <Badge>off</Badge>) },
                            { header: 'Actions', noExport: true, cell: (r) => (
                                <div className="inline-actions">
                                    <button type="button" className="link" onClick={() => void run(() => patch(`/api/sso/providers/${r.alias}?enabled=${!r.enabled}`, {}), r.enabled ? `${r.name} off.` : `${r.name} on.`, setPErrors, 'type')}>{r.enabled ? 'Turn off' : 'Turn on'}</button>
                                    <button type="button" className="link danger-text" onClick={async () => { if (await ask({ title: `Remove ${r.name}?`, message: 'People who signed in with it keep their Keycloak user but cannot use this provider any more.', confirmLabel: 'Remove' })) void run(() => del(`/api/sso/providers/${r.alias}`), `${r.name} removed.`, setPErrors, 'type'); }}>Remove</button>
                                </div>
                            ) },
                        ]} />
                )}
                <ErrorSummary errors={pErrors} />
                <form className="form-grid panel-text" onSubmit={(e) => { e.preventDefault(); void run(() => post('/api/sso/providers', p), 'Provider added. Give its redirect URI to the provider.', setPErrors, 'client_id'); }}>
                    <Select label="Provider" name="type" options={[{ value: 'google', label: 'Google (Workspace or Gmail)' }, { value: 'microsoft', label: 'Microsoft (Entra ID / Microsoft 365)' }, { value: 'oidc', label: 'Another OpenID Connect provider' }]} value={p.type} onChange={(e) => setP({ ...p, type: e.target.value })} />
                    {p.type === 'oidc' && <Field label="Short name" name="alias" placeholder="company-sso" value={p.alias} error={pErrors.alias} onChange={(e) => setP({ ...p, alias: e.target.value })} />}
                    {p.type === 'oidc' && <Field label="Discovery URL" name="discovery_url" className="span2" placeholder="https://login.example.com/.well-known/openid-configuration" value={p.discovery_url} error={pErrors.discovery_url} onChange={(e) => setP({ ...p, discovery_url: e.target.value })} />}
                    {p.type === 'microsoft' && <Field label="Tenant ID (optional)" name="tenant" hint="Only your organisation's accounts." value={p.tenant} onChange={(e) => setP({ ...p, tenant: e.target.value })} />}
                    {p.type === 'google' && <Field label="Workspace domain (optional)" name="hosted_domain" placeholder="isp.example" hint="Only accounts of this domain." value={p.hosted_domain} onChange={(e) => setP({ ...p, hosted_domain: e.target.value })} />}
                    <Field label="Client ID" name="client_id" required spellCheck={false} value={p.client_id} error={pErrors.client_id} onChange={(e) => setP({ ...p, client_id: e.target.value })} />
                    <Field label="Client secret" name="client_secret" type="password" required autoComplete="off" value={p.client_secret} error={pErrors.client_secret} onChange={(e) => setP({ ...p, client_secret: e.target.value })} />
                    <p className="span2 hint">People who sign in this way for the first time get a Keycloak user without a DNSOne role: give them one in the Operators tab.</p>
                    <FormActions><button className="primary" disabled={busy}>Add provider</button></FormActions>
                </form>
            </Sheet>
            <Sheet title="Active Directory / LDAP" icon="server">
                {dirs.data && (
                    <DataTable rows={dirs.data.directories} rowKey={(r) => r.id} emptyText="No directory connected."
                        columns={[
                            { header: 'Directory', cell: (r) => <div className="list-cell-stack"><span>{r.name}</span><span className="list-subline">{r.url} · {r.users_dn}</span></div> },
                            { header: 'Actions', noExport: true, cell: (r) => (
                                <div className="inline-actions">
                                    <button type="button" className="link" onClick={() => void run(() => post(`/api/sso/ldap/${r.id}/sync`), 'Users synchronised.', setDErrors, 'url')}>Sync now</button>
                                    <button type="button" className="link danger-text" onClick={async () => { if (await ask({ title: `Disconnect ${r.name}?`, message: 'Users imported from it are removed from Keycloak.', confirmLabel: 'Disconnect' })) void run(() => del(`/api/sso/ldap/${r.id}`), 'Directory disconnected.', setDErrors, 'url'); }}>Disconnect</button>
                                </div>
                            ) },
                        ]} />
                )}
                <ErrorSummary errors={dErrors} />
                <form className="form-grid panel-text" onSubmit={(e) => { e.preventDefault(); void run(() => post('/api/sso/ldap', d), 'Directory connected and users imported (read-only).', setDErrors, 'url'); }}>
                    <Select label="Directory" name="vendor" options={[{ value: 'ad', label: 'Active Directory' }, { value: 'other', label: 'OpenLDAP / other' }]} value={d.vendor} onChange={(e) => setD({ ...d, vendor: e.target.value })} />
                    <Field label="Server" name="url" required spellCheck={false} placeholder="ldaps://dc1.example.local:636" value={d.url} error={dErrors.url} onChange={(e) => setD({ ...d, url: e.target.value })} />
                    <Field label="Bind user (DN)" name="bind_dn" spellCheck={false} placeholder="CN=svc-dnsone,OU=Service,DC=example,DC=local" value={d.bind_dn} onChange={(e) => setD({ ...d, bind_dn: e.target.value })} />
                    <Field label="Bind password" name="bind_password" type="password" autoComplete="off" value={d.bind_password} onChange={(e) => setD({ ...d, bind_password: e.target.value })} />
                    <Field label="Users are in (DN)" name="users_dn" required spellCheck={false} className="span2" placeholder="OU=Staff,DC=example,DC=local" value={d.users_dn} error={dErrors.users_dn} onChange={(e) => setD({ ...d, users_dn: e.target.value })} />
                    <Field label="Only users matching (LDAP filter, optional)" name="filter" spellCheck={false} className="span2" placeholder="(memberOf=CN=NOC,OU=Groups,DC=example,DC=local)" value={d.filter} onChange={(e) => setD({ ...d, filter: e.target.value })} />
                    <p className="span2 hint">Read-only: people sign in with their directory password, which never leaves the directory. Give each one a DNSOne role in the Operators tab.</p>
                    <FormActions>
                        <button type="button" disabled={busy} onClick={() => void run(() => post('/api/sso/ldap/test', d), 'Connection and bind work.', setDErrors, 'url')}>Test connection</button>
                        <button className="primary" disabled={busy}>Connect</button>
                    </FormActions>
                </form>
            </Sheet>
        </>
    );
}

type Event = { time: number; type: string; username: string; ip: string; client: string; error: string | null };

function EventsPanel() {
    const [type, setType] = useState('');
    const [page, setPage] = useState(1);
    const { data, error } = useApi<{ rows: Event[]; page: number; more: boolean }>(`/api/sso/events${query({ type, page: String(page) })}`);
    return (
        <Sheet title="Sign-in events (90 days)" icon="logs">
            <div className="toolbar list-filterbar">
                <label className="list-filter"><span>Event</span>
                    <select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }}>
                        <option value="">All</option><option value="LOGIN">Sign-ins</option><option value="LOGIN_ERROR">Failed sign-ins</option>
                        <option value="LOGOUT">Sign-outs</option><option value="UPDATE_PASSWORD">Password changes</option><option value="UPDATE_TOTP">Two-factor set up</option>
                    </select>
                </label>
            </div>
            {error && <div className="flash danger">{error.message}</div>}
            {data && (
                <DataTable rows={data.rows} rowKey={(r) => `${r.time}-${r.type}-${r.username}`} emptyText="No events."
                    columns={[
                        { header: 'Time', cell: (r) => <span className="mono">{new Date(r.time).toLocaleString()}</span> },
                        { header: 'Event', cell: (r) => <Badge tone={r.error ? 'danger' : ''}>{r.type}</Badge> },
                        { header: 'User', cell: (r) => r.username || '–' },
                        { header: 'Address', cell: (r) => <span className="mono">{r.ip}</span> },
                        { header: 'Detail', className: 'cell-wrap', cell: (r) => r.error ?? r.client ?? '' },
                    ]} />
            )}
            <div className="inline-actions panel-text">
                <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>Newer</button>
                <button type="button" disabled={!data?.more} onClick={() => setPage(page + 1)}>Older</button>
            </div>
        </Sheet>
    );
}

type Email = { host: string; port: number; from: string; from_name: string; security: string; user: string; password_set: boolean };

function EmailPanel() {
    const toast = useToast();
    const { data, error, setData } = useApi<Email>('/api/sso/email');
    const [password, setPassword] = useState('');
    const [testTo, setTestTo] = useState('');
    const [errors, setErrors] = useState<Record<string, string>>({});
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    const save = async (test: boolean) => {
        try {
            setData(await put<Email>('/api/sso/email', { ...data, password, test_to: test ? testTo : '' }));
            setErrors({});
            setPassword('');
            toast(test ? `Saved; test email sent to ${testTo}.` : 'Saved.');
        } catch (e) {
            setErrors(errorsOf(e, 'host'));
        }
    };
    return (
        <Sheet title="Email for invitations and password resets" icon="mail">
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void save(false); }}>
                <Field label="SMTP server" name="host" spellCheck={false} placeholder="smtp.isp.example" value={data.host} error={errors.host} onChange={(e) => setData({ ...data, host: e.target.value })} />
                <Field label="Port" name="port" type="number" value={data.port} error={errors.port} onChange={(e) => setData({ ...data, port: Number(e.target.value) })} />
                <Select label="Encryption" name="security" options={[{ value: 'starttls', label: 'STARTTLS (587)' }, { value: 'tls', label: 'TLS (465)' }, { value: 'none', label: 'None' }]} value={data.security} onChange={(e) => setData({ ...data, security: e.target.value })} />
                <Field label="Sender address" name="from" type="email" placeholder="no-reply@isp.example" value={data.from} error={errors.from} onChange={(e) => setData({ ...data, from: e.target.value })} />
                <Field label="Sender name" name="from_name" placeholder="Pingomni DNS" value={data.from_name} onChange={(e) => setData({ ...data, from_name: e.target.value })} />
                <Field label="User (optional)" name="user" autoComplete="off" value={data.user} onChange={(e) => setData({ ...data, user: e.target.value })} />
                <Field label="Password" name="password" type="password" autoComplete="new-password" placeholder={data.password_set ? 'unchanged' : ''} value={password} error={errors.password} onChange={(e) => setPassword(e.target.value)} />
                <Field label="Send a test to" name="test_to" type="email" value={testTo} error={errors.to} onChange={(e) => setTestTo(e.target.value)} />
                <FormActions>
                    <button type="button" disabled={!testTo} onClick={() => void save(true)}>Save and send a test</button>
                    <button className="primary">Save</button>
                </FormActions>
            </form>
        </Sheet>
    );
}

export function SsoTab() {
    const can = useCan();
    const { data, error, reload } = useApi<Overview>('/api/sso');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    if (!data.enabled || !data.admin_api) {
        return <Empty>Single sign-on is not set up on this server. Install it with <code>ops/dnsone-upgrade-1.3</code> (docs/RUNBOOK.md, "Single sign-on").</Empty>;
    }
    const admin = can('system.manage');
    return (
        <>
            <Sheet title="Single sign-on" icon="lock" meta={<Badge tone={data.local_login ? 'warning' : 'success'}>{data.local_login ? 'password sign-in also on' : 'SSO only'}</Badge>}>
                <SettingsRows rows={[
                    ['Keycloak realm', data.realm], ['Issuer', data.issuer],
                    ['Emergency access', 'dnsone-ctl sso emergency-login <user> on the server (one-time link, 10 minutes)'],
                ]} />
                <div className="inline-actions panel-text">
                    {data.admin_console && <a className="button" href={data.admin_console} target="_blank" rel="noreferrer">Keycloak admin console (everything else)</a>}
                </div>
            </Sheet>
            <Tabs
                label="Single sign-on"
                param="sso"
                className="tabs nas-tabs"
                tabs={[
                    { key: 'users', title: 'Operators', icon: 'clients', content: <UsersPanel overview={data} onChanged={() => void reload()} /> },
                    ...(admin ? [
                        { key: 'security', title: 'Security', icon: 'lock', content: <SecurityPanel /> },
                        { key: 'providers', title: 'Sign-in options', icon: 'user', content: <ProvidersPanel /> },
                        { key: 'events', title: 'Events', icon: 'logs', content: <EventsPanel /> },
                        { key: 'email', title: 'Email', icon: 'mail', content: <EmailPanel /> },
                    ] : []),
                ]}
            />
        </>
    );
}
