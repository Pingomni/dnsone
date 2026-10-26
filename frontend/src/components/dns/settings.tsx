// DNSOne's settings navigation: RadiusOne's SettingsLinkNav and Overview destination card
// (components/settings.tsx, settings/OverviewTab.tsx) with DNSOne's sections. Same markup and classes.
import { Link } from '@inertiajs/react';
import { useEffect, useRef, type ReactNode } from 'react';
import Icon from '@/components/Icon';
import { revealCurrent } from '@/components/tabs';
import { useCan } from '@/lib/auth';

/** Add a section here, then render it in pages/settings/Settings.tsx. */
export const SECTIONS: [key: string, label: string, href: string, icon: string, hint: string, permission: string][] = [
    ['overview', 'Overview', '/settings', 'settings', 'System information and shortcuts', 'system.manage'],
    ['users', 'Users', '/settings?tab=users', 'clients', 'Operators and roles', 'users.manage'],
    ['dns-server', 'DNS server', '/settings?tab=dns-server', 'signal', 'Customer networks, NAT addresses, rate limits', 'system.manage'],
    ['privacy', 'Privacy', '/settings?tab=privacy', 'lock', 'What the query log keeps, and for how long', 'system.manage'],
    ['alerts', 'Alerts', '/settings?tab=alerts', 'activity', 'Email, webhook and Telegram alerts; Prometheus', 'system.manage'],
    ['export', 'Query log export', '/settings?tab=export', 'logs', 'Syslog to a SIEM, dnstap', 'system.manage'],
    ['sso', 'Single sign-on', '/settings?tab=sso', 'lock', 'Sign in with Google, Entra ID, Okta or any OpenID Connect provider', 'users.manage'],
    ['backup', 'Backup', '/settings?tab=backup', 'refresh', 'Download and restore settings, lists and rules', 'system.manage'],
    ['cluster', 'Cluster', '/settings?tab=cluster', 'server', 'Nodes and BIND secondaries', 'system.manage'],
    ['firewall', 'Firewall', '/settings?tab=firewall', 'shield', 'The server\'s firewall (nftables), applied with a safety rollback', 'firewall.manage'],
];

export function SettingsLinkNav({ active }: { active: string }) {
    const can = useCan();
    const nav = useRef<HTMLElement>(null);
    useEffect(() => revealCurrent(nav.current), [active]);
    return (
        <nav className="settings-nav" aria-label="Settings sections" ref={nav}>
            {SECTIONS.filter(([, , , , , permission]) => can(permission)).map(([key, label, href, icon, hint]) => (
                <Link key={key} href={href} title={hint} className={key === active ? 'active' : undefined} aria-current={key === active ? 'page' : undefined} preserveScroll>
                    <Icon name={icon} />{label}
                </Link>
            ))}
        </nav>
    );
}

export function Destination({ title, href, icon, status }: { title: string; href: string; icon: string; status: ReactNode }) {
    return (
        <Link className="settings-destination" href={href}>
            <span className="account-section-icon"><Icon name={icon} /></span>
            <h3>{title}</h3>
            <span className="settings-destination-status">{status}</span>
            <span className="settings-destination-action">Configure <span aria-hidden="true">→</span></span>
        </Link>
    );
}
