// RadiusOne's sign-in page (resources/js/pages/auth/Login.tsx), posting to the DNSOne API.
import { useEffect, useState } from 'react';
import Icon from '@/components/Icon';
import { AuthCard, AuthLayout } from '@/layouts/AuthLayout';
import { ApiError, get, post } from '@/lib/api';
import type { Flash } from '@/lib/types';
import type { Me } from '@/main';

type Challenge = { two_factor_required: true; ticket: string };

/** Second sign-in step: a code from the authenticator app, or a one-time recovery code. */
function SecondFactor({ ticket, onSignedIn, onRestart }: { ticket: string; onSignedIn: (me: Me) => void; onRestart: (message: string) => void }) {
    const [code, setCode] = useState('');
    const [busy, setBusy] = useState(false);
    const [flash, setFlash] = useState<Flash | null>(null);
    return (
        <AuthCard
            heading="Two-factor sign-in"
            lead="Enter the 6-digit code from your authenticator app, or one of your recovery codes."
            flash={flash}
            onSubmit={async (event) => {
                event.preventDefault();
                setBusy(true);
                try {
                    onSignedIn(await post<Me>('/api/auth/login/verify', { ticket, code }));
                } catch (e) {
                    const ae = e as ApiError;
                    if (ae.errors.ticket) onRestart(ae.message);
                    else setFlash({ type: 'danger', message: ae.message });
                    setCode('');
                } finally {
                    setBusy(false);
                }
            }}
        >
            <label className="login-field">
                Code
                <span className="login-input">
                    <Icon name="lock" />
                    <input name="code" autoComplete="one-time-code" inputMode="text" placeholder="123456" required autoFocus spellCheck={false}
                        aria-describedby={flash ? 'page-feedback' : undefined} value={code} onChange={(e) => setCode(e.target.value)} />
                </span>
            </label>
            <button className="primary login-submit" disabled={busy}>Verify <span aria-hidden="true">&rarr;</span></button>
            <p className="login-help"><button type="button" className="link" onClick={() => onRestart('')}>Use another account</button></p>
        </AuthCard>
    );
}

/** A refused single sign-on comes back as /?sso_error=…: show it once, then drop it from the address bar. */
function ssoError(): Flash | null {
    const message = new URLSearchParams(window.location.search).get('sso_error');
    if (!message) return null;
    window.history.replaceState(null, '', window.location.pathname);
    return { type: 'danger', message };
}

export default function Login({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [visible, setVisible] = useState(false);
    const [busy, setBusy] = useState(false);
    const [flash, setFlash] = useState<Flash | null>(ssoError);
    const [ticket, setTicket] = useState<string | null>(null);
    const [sso, setSso] = useState<{ enabled: boolean; label: string } | null>(null);
    useEffect(() => {
        get<{ enabled: boolean; label: string }>('/api/auth/oidc').then(setSso, () => setSso(null));
    }, []);
    const described = flash ? 'page-feedback' : undefined;

    if (ticket) {
        return (
            <AuthLayout title="Login">
                <SecondFactor ticket={ticket} onSignedIn={onSignedIn} onRestart={(message) => {
                    setTicket(null);
                    setPassword('');
                    setFlash(message ? { type: 'warning', message } : null);
                }} />
            </AuthLayout>
        );
    }

    return (
        <AuthLayout title="Login">
            <AuthCard
                heading="Welcome back"
                lead="Sign in with your operator credentials."
                flash={flash}
                onSubmit={async (event) => {
                    event.preventDefault();
                    setBusy(true);
                    try {
                        const result = await post<Me | Challenge>('/api/auth/login', { username, password });
                        if ('two_factor_required' in result) {
                            setFlash(null);
                            setTicket(result.ticket);
                        } else {
                            onSignedIn(result);
                        }
                    } catch (e) {
                        setFlash({ type: 'danger', message: (e as ApiError).message });
                        setPassword('');
                    } finally {
                        setBusy(false);
                    }
                }}
            >
                <label className="login-field">
                    Username
                    <span className="login-input">
                        <Icon name="user" />
                        <input name="username" autoComplete="username" placeholder="Enter your username" required autoFocus={!flash} aria-describedby={described} value={username} onChange={(e) => setUsername(e.target.value)} />
                    </span>
                </label>
                <label className="login-field" htmlFor="login-password">Password</label>
                <div className="login-input">
                    <Icon name="lock" />
                    <input id="login-password" type={visible ? 'text' : 'password'} name="password" autoComplete="current-password" placeholder="Enter your password" required aria-describedby={described} value={password} onChange={(e) => setPassword(e.target.value)} />
                    <button type="button" className="password-toggle" aria-controls="login-password" aria-pressed={visible} onClick={() => setVisible(!visible)}>
                        {visible ? 'Hide' : 'Show'}
                    </button>
                </div>
                <button className="primary login-submit" disabled={busy}>Sign in <span aria-hidden="true">&rarr;</span></button>
                {sso?.enabled && (
                    <>
                        <p className="login-divider" aria-hidden="true"><span>or</span></p>
                        {/* A full-page navigation: the API redirects to Keycloak and back. */}
                        <a className="button login-submit login-sso" href="/api/auth/oidc/login">{sso.label}</a>
                    </>
                )}
                <p className="login-help">Need access? Contact your workspace administrator.</p>
            </AuthCard>
        </AuthLayout>
    );
}
