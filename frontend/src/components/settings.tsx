import { Link } from '@inertiajs/react';
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import Icon from './Icon';
import { revealCurrent } from './tabs';

// Settings-style building blocks (legacy settingsSheet, settingsRows, settingsDestination, profile fields).

export function Sheet({ title, icon = 'settings', meta, className = '', children }: {
    title: string;
    /** Not shown: headers are kept to the title (details live in Documentation). */
    description?: string;
    icon?: string;
    meta?: ReactNode;
    className?: string;
    children: ReactNode;
}) {
    return (
        <section className={`settings-sheet ${className}`.trim()}>
            <div className="settings-sheet-head">
                <div className="settings-sheet-title">
                    <span className="account-section-icon"><Icon name={icon} /></span>
                    <div>
                        <h2>{title}</h2>
                    </div>
                </div>
                {meta && <div className="settings-sheet-meta">{meta}</div>}
            </div>
            {children}
        </section>
    );
}

export function SettingsRows({ rows }: { rows: [string, ReactNode][] }) {
    return (
        <div className="settings-list settings-sheet-list">
            {rows.map(([label, value]) => (
                <div key={label}><span>{label}</span><strong>{value}</strong></div>
            ))}
        </div>
    );
}

export function RoleGrid({ roles, compact = false }: { roles: { role: string; description: string }[]; compact?: boolean }) {
    return (
        <div className={`role-access-grid${compact ? ' compact-role-grid' : ''}`}>
            {roles.map((r) => (
                <div className="role-access-card" key={r.role}><span>{r.role}</span><p>{r.description}</p></div>
            ))}
        </div>
    );
}

/** Password input with a Show/Hide toggle (legacy profilePasswordField). */
export function PasswordField({ label, name, autoComplete, hint, value, onChange, error }: {
    label: string;
    name: string;
    autoComplete: string;
    hint?: string;
    value: string;
    onChange: (value: string) => void;
    error?: string;
}) {
    const id = `${name}-${useId().replace(/:/g, '')}`;
    const [shown, setShown] = useState(false);
    const described = [hint ? `${id}-help` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined;
    return (
        <div className="account-password-field">
            <label htmlFor={id} id={`${id}-label`}>{label}</label>
            <div className="account-password-control">
                <input
                    id={id}
                    type={shown ? 'text' : 'password'}
                    name={name}
                    required
                    autoComplete={autoComplete}
                    minLength={autoComplete === 'new-password' ? 10 : undefined}
                    value={value}
                    onChange={(event) => onChange(event.target.value)}
                    aria-describedby={described}
                    aria-invalid={error ? true : undefined}
                />
                <button type="button" aria-controls={id} aria-label={`Toggle ${label.toLowerCase()} visibility`} aria-pressed={shown} onClick={() => setShown(!shown)}>
                    {shown ? 'Hide' : 'Show'}
                </button>
            </div>
            {hint && <small id={`${id}-help`}>{hint}</small>}
            {error && <small id={`${id}-error`} className="field-error">{error}</small>}
        </div>
    );
}

const SECTIONS: [key: string, label: string, href: string, icon: string, hint: string][] = [
    ['overview', 'Overview', '/settings', 'settings', 'Runtime and shortcuts'],
    ['users', 'Users', '/settings?tab=users', 'clients', 'Roles and 2FA'],
    ['notifications', 'Notifications', '/settings?tab=notifications', 'mail', 'Gateways, templates, history'],
    ['branding', 'Branding', '/settings?tab=branding', 'image', 'Workspace identity'],
    ['documents', 'Invoices & receipts', '/settings?tab=documents', 'billing', 'PDF wording and company details'],
    ['regional', 'Regional', '/settings?tab=regional', 'calendar', 'Time zone and currency'],
    ['backups', 'Backups', '/settings?tab=backups', 'server', 'Encrypted remote copies'],
    ['retention', 'Data retention', '/settings?tab=retention', 'logs', 'Session and login records'],
];

/** Settings section navigation (legacy settingsLinkNav). */
export function SettingsLinkNav({ active }: { active: string }) {
    const nav = useRef<HTMLElement>(null);
    useEffect(() => revealCurrent(nav.current), [active]);
    return (
        <nav className="settings-nav" aria-label="Settings sections" ref={nav}>
            {SECTIONS.map(([key, label, href, icon, hint]) => (
                <Link key={key} href={href} title={hint} className={key === active ? 'active' : undefined} aria-current={key === active ? 'page' : undefined} preserveScroll>
                    <Icon name={icon} />{label}
                </Link>
            ))}
        </nav>
    );
}
