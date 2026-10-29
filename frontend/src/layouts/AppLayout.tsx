// DNSOne's shell: RadiusOne's AppLayout (resources/js/layouts/AppLayout.tsx) with DNSOne's navigation,
// brand mark and zone search. Markup and class names are unchanged so app.css styles it identically.
import { Head, Link, router, usePage } from '@inertiajs/react';
import { Fragment, useEffect, useRef, useState, type ReactNode } from 'react';
import Icon from '@/components/Icon';
import { FlashMessage } from '@/components/ui';
import { post } from '@/lib/api';
import { useCan, useShared } from '@/lib/auth';
import { useServerClock } from '@/lib/clock';
import { currentLicense, has } from '@/lib/edition';
import { lockPage, watchClicks } from '@/lib/scroll';

// Each label appears once: items are listed in group order.
// Pro pages are in the navigation while the licence has their feature.
const PRO_NAV: Record<string, string> = { '/legal': 'legal', '/protection': 'protection', '/customers': 'quota' };

const NAV: [href: string, label: string, permission: string, icon: string, group: string][] = [
    ['/', 'Dashboard', 'dashboard.view', 'dashboard', 'DNS'],
    ['/zones', 'Zones', 'zones.view', 'server', 'DNS'],
    ['/templates', 'Zone templates', 'templates.manage', 'book', 'DNS'],
    ['/queries', 'Query log', 'queries.view', 'search', 'DNS'],
    ['/blocking', 'Ad-blocking', 'rpz.view', 'shield', 'DNS'],
    ['/groups', 'Client groups', 'rpz.view', 'clients', 'DNS'],
    ['/legal', 'Court orders', 'legal.view', 'lock', 'DNS'],
    ['/protection', 'Protection', 'protection.view', 'activity', 'DNS'],
    ['/customers', 'Customers', 'users.customers', 'clients', 'Workspace'],
    ['/audit', 'Audit log', 'audit.view', 'logs', 'Workspace'],
    ['/settings', 'Settings', 'system.manage', 'settings', 'Workspace'],
    // Everyone, customers included.
    ['/help', 'Help', '', 'book', 'Workspace'],
];

const CONTEXTS: Record<string, string> = {
    '': 'Workspace / Overview',
    zones: 'DNS / Authoritative',
    queries: 'DNS / Resolver',
    blocking: 'DNS / Resolver',
    groups: 'DNS / Resolver',
    legal: 'DNS / Resolver',
    protection: 'DNS / Security',
    templates: 'DNS / Authoritative',
    customers: 'Workspace / Customers',
    audit: 'Workspace / Activity',
    settings: 'Workspace / Administration',
    profile: 'Workspace / My account',
    help: 'Workspace / Help',
};

export function BrandLogo({ className = 'brand-logo' }: { className?: string }) {
    return <span className={`mark ${className}`}><BrandMark /></span>;
}

/** The DNSOne mark, the Tree, from the PingOmni family (Monitor's Pulse, RadiusOne's Key): a ring open where the line
 * leaves, one stroke, the teal ping at (57,32). A name is looked up; one path comes out as the answer. */
export function BrandMark() {
    return (
        <svg className="po-mark" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
            <path d="M12.02 23.23A20 20 0 0 1 47.98 23.23M47.98 40.77A20 20 0 0 1 12.02 40.77M4 32H57M18 32L26 24H36M18 32L26 40H36" fill="none" stroke="currentColor" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
            <circle className="po-mark-dot" cx="57" cy="32" r="5.5" />
        </svg>
    );
}

function ThemeToggle() {
    const [dark, setDark] = useState(false);
    useEffect(() => {
        const root = document.documentElement;
        setDark(root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches);
    }, []);
    return (
        <button
            type="button"
            className="theme-toggle"
            aria-pressed={dark}
            title="Switch between light and dark theme"
            onClick={() => {
                const next = dark ? 'light' : 'dark';
                document.documentElement.dataset.theme = next;
                // public/theme.js applies it before first paint on the next load.
                document.cookie = `dnsone_theme=${next}; path=/; max-age=31536000; SameSite=Lax; Secure`;
                setDark(!dark);
            }}
        >
            <Icon name="moon" />
            <span>Dark theme</span>
        </button>
    );
}

function useMobileNav() {
    const [mobile, setMobile] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 980px)').matches);
    const [open, setOpen] = useState(false);
    useEffect(() => {
        const media = window.matchMedia('(max-width: 980px)');
        const sync = () => {
            setMobile(media.matches);
            setOpen(false);
        };
        media.addEventListener('change', sync);
        return () => media.removeEventListener('change', sync);
    }, []);
    useEffect(() => {
        document.body.classList.toggle('nav-open', open);
    }, [open]);
    useEffect(() => router.on('navigate', () => setOpen(false)), []);
    return { mobile, open, setOpen };
}

/** An expired DNSOne Pro licence, or one ending within two weeks: for whoever can renew it. */
function LicenseNotice() {
    const can = useCan();
    const lic = currentLicense();
    if (!can('system.manage') || lic.state === 'none') return null;
    if (lic.state === 'expired') {
        return <div className="flash warning" role="status">Your DNSOne Pro licence expired on {lic.expires}. The Pro features keep running as they were, so DNS answers do not change, but they cannot be changed until you renew it: <Link href="/settings?tab=license">Settings → License</Link>.</div>;
    }
    if (lic.days_left != null && lic.days_left <= 14) {
        return <div className="flash info" role="status">Your DNSOne Pro licence ends on {lic.expires} ({lic.days_left} days). <Link href="/settings?tab=license">Settings → License</Link>.</div>;
    }
    return null;
}

/** Workspace shell: sidebar, topbar and page feedback. */
export default function AppLayout({ title, children }: { title: string; children: ReactNode }) {
    const { auth, flash, clock, appName, appVersion } = useShared();
    const time = useServerClock();
    const can = useCan();
    const { url } = usePage();
    const path = url.split('?')[0];
    const search = path === '/zones' ? new URLSearchParams(url.split('?')[1] ?? '').get('q') ?? '' : '';
    const { mobile, open, setOpen } = useMobileNav();
    const sidebar = useRef<HTMLElement>(null);
    const toggle = useRef<HTMLButtonElement>(null);
    const feedback = useRef<HTMLDivElement>(null);

    useEffect(() => watchClicks(), []);
    // DNSOne was updated while this page was open: its code is the old version's until a reload.
    const [updated, setUpdated] = useState<string | null>(null);
    useEffect(() => {
        const onUpdated = (event: Event) => setUpdated((event as CustomEvent<string>).detail);
        window.addEventListener('dnsone:updated', onUpdated);
        return () => window.removeEventListener('dnsone:updated', onUpdated);
    }, []);
    useEffect(() => {
        lockPage(mobile && open);
        return () => lockPage(false);
    }, [mobile, open]);

    useEffect(() => {
        if (flash && (flash.type === 'danger' || flash.type === 'warning')) feedback.current?.querySelector<HTMLElement>('[data-feedback-focus]')?.focus();
    }, [flash]);

    // Mobile navigation behaves as a modal dialog: focus trap, Escape closes, focus returns.
    useEffect(() => {
        if (!open) return;
        const controls = () => [...(sidebar.current?.querySelectorAll<HTMLElement>('a[href], button:not(:disabled)') ?? [])].filter((c) => c.getClientRects().length);
        controls()[0]?.focus();
        const onKey = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                setOpen(false);
                toggle.current?.focus();
            } else if (event.key === 'Tab') {
                const list = controls();
                if (!list.length) return;
                if (event.shiftKey && document.activeElement === list[0]) {
                    event.preventDefault();
                    list[list.length - 1].focus();
                } else if (!event.shiftKey && document.activeElement === list[list.length - 1]) {
                    event.preventDefault();
                    list[0].focus();
                }
            }
        };
        document.addEventListener('keydown', onKey);
        return () => document.removeEventListener('keydown', onKey);
    }, [open, setOpen]);

    const section = path.replace(/^\/+/, '').split('/')[0];
    let group = '';

    return (
        <>
            <Head title={`${title} - ${appName}`} />
            <a className="skip-link" href="#workspace-content">Skip to content</a>
            <aside
                className="sidebar"
                id="app-sidebar"
                aria-label="Main navigation"
                ref={sidebar}
                inert={mobile && !open ? true : undefined}
                aria-hidden={mobile && !open ? true : undefined}
                role={open ? 'dialog' : undefined}
                aria-modal={open ? true : undefined}
            >
                <button type="button" className="nav-close" onClick={() => { setOpen(false); toggle.current?.focus(); }}>Close navigation</button>
                <div className="brand">
                    <BrandLogo />
                    <div><strong>{appName}</strong><small>DNS management</small></div>
                </div>
                <nav aria-label="Primary">
                    {NAV.filter(([href, , permission]) => (!PRO_NAV[href] || has(PRO_NAV[href])) && (!permission || can(permission))).map(([href, label, , icon, navGroup]) => {
                        const active = path === href || (href !== '/' && path.startsWith(`${href}/`));
                        const heading = navGroup !== group ? <span className="nav-group-label">{navGroup}</span> : null;
                        group = navGroup;
                        return (
                            <Fragment key={href}>
                                {heading}
                                <Link className={active ? 'active' : ''} href={href} aria-current={active ? 'page' : undefined}>
                                    <Icon name={icon} />
                                    <span>{label}</span>
                                </Link>
                            </Fragment>
                        );
                    })}
                </nav>
                {appVersion && <div className="sidebar-version">DNSOne v{appVersion}</div>}
            </aside>
            <button type="button" className="nav-backdrop" tabIndex={-1} aria-hidden="true" hidden={!open} onClick={() => setOpen(false)} />
            <main className="main" inert={open ? true : undefined}>
                <header className="topbar">
                    <div className="page-title">
                        <button
                            ref={toggle}
                            type="button"
                            className="mobile-nav-toggle"
                            aria-label="Open main navigation"
                            aria-controls="app-sidebar"
                            aria-expanded={open}
                            onClick={() => setOpen(!open)}
                        >
                            <Icon name="menu" />
                            <span>Menu</span>
                        </button>
                        <div>
                            <span className="workspace-eyebrow">{CONTEXTS[section] ?? 'Workspace'}</span>
                            <h1>{title}</h1>
                        </div>
                    </div>
                    {can('zones.view') && (
                        <form
                            className="topbar-search"
                            action="/zones"
                            role="search"
                            onSubmit={(event) => {
                                event.preventDefault();
                                const q = new FormData(event.currentTarget).get('q');
                                router.get('/zones', q ? { q: String(q) } : {});
                            }}
                        >
                            <label className="sr-only" htmlFor="topbar-search-input">Search zones</label>
                            <input key={search} id="topbar-search-input" type="search" name="q" placeholder="Search zones" autoComplete="off" defaultValue={search} />
                        </form>
                    )}
                    <div className="operator">
                        <span className="topbar-clock" title="All times are shown in this timezone">{time} {clock.timezone}</span>
                        <ThemeToggle />
                        <Link className="operator-id" href="/profile" title="My profile">
                            <Icon name="user" />
                            {auth.user?.username}
                        </Link>
                        <button type="button" className="logout-button" onClick={() => void post<{ redirect?: string | null }>('/api/auth/logout').then((r) => window.location.assign(r.redirect || '/'), () => window.location.assign('/'))}>
                            <Icon name="logout" />
                            <span>Logout</span>
                        </button>
                    </div>
                </header>
                <div className="workspace-content" id="workspace-content" tabIndex={-1} ref={feedback}>
                    {updated && (
                        <div className="flash warning update-reload" role="status">
                            <span>DNSOne {updated} is installed. Reload to use the new version of the console.</span>
                            <button type="button" className="button" onClick={() => window.location.reload()}>Reload</button>
                        </div>
                    )}
                    <LicenseNotice />
                    {flash && <FlashMessage flash={flash} />}
                    {children}
                </div>
            </main>
        </>
    );
}
