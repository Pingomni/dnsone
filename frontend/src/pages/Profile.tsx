import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { useToast } from '@/components/dns/feedback';
import { DataTable } from '@/components/table';
import { Badge, Check, ErrorSummary, Field, FormActions, HealthItem, Panel, Select } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, del, post, useApi } from '@/lib/api';
import { useShared } from '@/lib/auth';

type TwoFactor = { enabled: boolean; recovery_codes_left: number };
type Enrolment = { secret: string; uri: string; qr: string };
type Token = { id: number; name: string; prefix: string; read_only: boolean; created_at: string; last_used_at: string | null; last_used_ip: string; expires_at: string | null; expired: boolean };

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
    return (
        <div className="recovery-codes">
            <p><strong>Save these recovery codes now.</strong> Each signs you in once if you lose your phone; they are not shown again.</p>
            <pre className="mono">{codes.join('\n')}</pre>
            <div className="inline-actions">
                <button type="button" onClick={() => void navigator.clipboard?.writeText(codes.join('\n'))}>Copy</button>
                <button type="button" className="primary" onClick={onDone}>I have saved them</button>
            </div>
        </div>
    );
}

function TwoFactorPanel() {
    const toast = useToast();
    const { data, reload } = useApi<TwoFactor>('/api/auth/2fa');
    const [password, setPassword] = useState('');
    const [code, setCode] = useState('');
    const [enrolment, setEnrolment] = useState<Enrolment | null>(null);
    const [codes, setCodes] = useState<string[] | null>(null);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const call = async <T,>(url: string, body: unknown, then: (r: T) => void) => {
        setBusy(true);
        try {
            then(await post<T>(url, body));
            setErrors({});
        } catch (e) {
            const ae = e as ApiError;
            setErrors(Object.keys(ae.errors).length ? ae.errors : { password: ae.message });
        } finally {
            setBusy(false);
        }
    };
    if (!data) return null;
    const meta = data.enabled ? <Badge tone="success">on</Badge> : <Badge tone="warning">off</Badge>;
    if (codes) return <Panel title="Two-factor sign-in" actions={meta}><RecoveryCodes codes={codes} onDone={() => { setCodes(null); void reload(); }} /></Panel>;
    if (enrolment) {
        return (
            <Panel title="Two-factor sign-in: scan the code" actions={meta}>
                <div className="totp-enrol">
                    <img src={enrolment.qr} alt="QR code for your authenticator app" width={220} height={220} />
                    <div>
                        <p>Scan it with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, FreeOTP…), or enter this key by hand:</p>
                        <p className="mono totp-secret">{enrolment.secret.replace(/(.{4})/g, '$1 ').trim()}</p>
                        <form className="inline-form" onSubmit={(e) => {
                            e.preventDefault();
                            void call<{ recovery_codes: string[] }>('/api/auth/2fa/enable', { code }, (r) => {
                                setEnrolment(null);
                                setCode('');
                                setCodes(r.recovery_codes);
                                toast('Two-factor sign-in is on. Your other sessions were signed out.');
                            });
                        }}>
                            <Field label="Code from the app" required autoComplete="one-time-code" inputMode="numeric" value={code} error={errors.code ?? errors.password} onChange={(e) => setCode(e.target.value)} />
                            <button className="primary" disabled={busy}>Turn on</button>
                            <button type="button" onClick={() => setEnrolment(null)}>Cancel</button>
                        </form>
                    </div>
                </div>
            </Panel>
        );
    }
    return (
        <Panel title="Two-factor sign-in" actions={meta}>
            <p className="hint panel-text">
                {data.enabled
                    ? `Signing in asks for a code from your authenticator app. ${data.recovery_codes_left} recovery code(s) left.`
                    : 'Protect your account with a code from an authenticator app, asked for after your password.'}
            </p>
            <form className="form-grid" onSubmit={(e) => e.preventDefault()}>
                <Field label="Your password" type="password" autoComplete="current-password" required value={password} error={errors.password} onChange={(e) => setPassword(e.target.value)} />
                {data.enabled && <Field label="Code (to turn it off)" autoComplete="one-time-code" value={code} error={errors.code} onChange={(e) => setCode(e.target.value)} />}
                <FormActions>
                    {!data.enabled && <button type="button" className="primary" disabled={busy || !password} onClick={() => void call<Enrolment>('/api/auth/2fa/setup', { password }, (r) => { setEnrolment(r); setPassword(''); })}>Set up</button>}
                    {data.enabled && <button type="button" disabled={busy || !password} onClick={() => void call<{ recovery_codes: string[] }>('/api/auth/2fa/recovery-codes', { password }, (r) => { setCodes(r.recovery_codes); setPassword(''); })}>New recovery codes</button>}
                    {data.enabled && <button type="button" className="danger" disabled={busy || !password || !code} onClick={() => void call('/api/auth/2fa/disable', { password, code }, () => { setPassword(''); setCode(''); toast('Two-factor sign-in is off.'); void reload(); })}>Turn off</button>}
                </FormActions>
            </form>
        </Panel>
    );
}

function AppPasswords() {
    const toast = useToast();
    const ask = useConfirm();
    const { data, reload } = useApi<{ rows: Token[] }>('/api/auth/tokens');
    const [form, setForm] = useState({ name: '', read_only: true, expires_days: '' });
    const [created, setCreated] = useState<string | null>(null);
    const [error, setError] = useState('');
    const revoke = async (t: Token) => {
        if (!(await ask({ title: `Revoke ${t.name}?`, message: 'Scripts using it stop working at once.', confirmLabel: 'Revoke' }))) return;
        try {
            await del(`/api/auth/tokens/${t.id}`);
            toast(`${t.name} revoked.`);
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    return (
        <Panel title="App passwords">
            <p className="hint panel-text">For scripts and monitoring: send <span className="mono">Authorization: Bearer &lt;app password&gt;</span> to the API (<a href="/api/docs">/api/docs</a>). They act with your role, or read-only; two-factor does not apply to them.</p>
            {created && (
                <div className="flash success">
                    Copy it now; it is not shown again: <span className="mono">{created}</span>{' '}
                    <button type="button" className="link" onClick={() => void navigator.clipboard?.writeText(created)}>Copy</button>
                </div>
            )}
            <form className="toolbar list-filterbar" onSubmit={async (e) => {
                e.preventDefault();
                try {
                    const t = await post<Token & { token: string }>('/api/auth/tokens', { name: form.name, read_only: form.read_only, expires_days: form.expires_days ? Number(form.expires_days) : null });
                    setCreated(t.token);
                    setForm({ name: '', read_only: true, expires_days: '' });
                    setError('');
                    void reload();
                } catch (err) {
                    setError((err as ApiError).message);
                }
            }}>
                <label className="list-search"><span>Name</span><input required placeholder="monitoring, provisioning…" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
                <Select label="Expires" className="list-filter" options={{ '': 'Never', 30: 'In 30 days', 90: 'In 90 days', 365: 'In a year' }} value={form.expires_days} onChange={(e) => setForm({ ...form, expires_days: e.target.value })} />
                <Check label="Read-only" checked={form.read_only} onChange={(e) => setForm({ ...form, read_only: e.target.checked })} />
                <div className="list-filter-buttons"><button className="primary">Create</button></div>
            </form>
            {error && <div className="flash danger">{error}</div>}
            {data && (
                <DataTable
                    rows={data.rows}
                    rowKey={(r) => r.id}
                    emptyText="No app passwords."
                    columns={[
                        { header: 'Name', cell: (r) => <div className="list-cell-stack"><span>{r.name}</span><span className="list-subline mono">{r.prefix}…</span></div> },
                        { header: 'Access', cell: (r) => (r.read_only ? <Badge>read-only</Badge> : <Badge tone="warning">full</Badge>) },
                        { header: 'Last used', cell: (r) => (r.last_used_at ? `${r.last_used_at} from ${r.last_used_ip}` : 'never') },
                        { header: 'Expires', cell: (r) => (r.expired ? <Badge tone="danger">expired</Badge> : r.expires_at ?? 'never') },
                        { header: 'Actions', noExport: true, cell: (r) => <button type="button" className="link danger-text" onClick={() => void revoke(r)}>Revoke</button> },
                    ]}
                />
            )}
        </Panel>
    );
}

export default function Profile() {
    const { auth } = useShared();
    const toast = useToast();
    const [form, setForm] = useState({ current_password: '', new_password: '', repeat: '' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const user = auth.user!;

    return (
        <AppLayout title="My profile">
            <Panel title="Account">
                <div className="health-grid">
                    <HealthItem label="Username" value={user.username} />
                    <HealthItem label="Role" value={user.role} />
                    <HealthItem label="Name" value={user.name || '-'} />
                    <HealthItem label="Email" value={user.email || '-'} />
                </div>
            </Panel>
            <Panel title="Change password">
                <ErrorSummary errors={errors} />
                <form
                    className="form-grid"
                    onSubmit={async (event) => {
                        event.preventDefault();
                        if (form.new_password !== form.repeat) {
                            setErrors({ repeat: 'The new passwords differ.' });
                            return;
                        }
                        setBusy(true);
                        try {
                            await post('/api/auth/password', { current_password: form.current_password, new_password: form.new_password });
                            setForm({ current_password: '', new_password: '', repeat: '' });
                            setErrors({});
                            toast('Password changed. Other sessions were signed out.');
                        } catch (e) {
                            const ae = e as ApiError;
                            setErrors(Object.keys(ae.errors).length ? ae.errors : { current_password: ae.message });
                        } finally {
                            setBusy(false);
                        }
                    }}
                >
                    <Field label="Current password" name="current_password" type="password" required autoComplete="current-password" className="span2" value={form.current_password} error={errors.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} />
                    <Field label="New password" name="new_password" type="password" required autoComplete="new-password" hint="At least 12 characters." value={form.new_password} error={errors.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} />
                    <Field label="Repeat new password" name="repeat" type="password" required autoComplete="new-password" value={form.repeat} error={errors.repeat} onChange={(e) => setForm({ ...form, repeat: e.target.value })} />
                    <FormActions><button className="primary" disabled={busy}>Change password</button></FormActions>
                </form>
            </Panel>
            {user.auth_source !== 'oidc' && <TwoFactorPanel />}
            <AppPasswords />
        </AppLayout>
    );
}
