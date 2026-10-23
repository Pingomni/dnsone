import { StrictMode, useCallback, useEffect, useMemo, useState, type ComponentType } from 'react';
import { createRoot } from 'react-dom/client';
import { bindRouter, emit, PageProvider, router, type Page } from '@inertiajs/react';
import { ConfirmProvider } from '@/components/confirm';
import { ToastProvider } from '@/components/dns/feedback';
import { Empty } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { api, get, onSessionExpired, setCsrf } from '@/lib/api';
import type { SharedProps } from '@/lib/types';
import Audit from '@/pages/Audit';
import Blocking from '@/pages/Blocking';
import Dashboard from '@/pages/Dashboard';
import Groups from '@/pages/Groups';
import Login from '@/pages/Login';
import Profile from '@/pages/Profile';
import Queries from '@/pages/Queries';
import Settings from '@/pages/settings/Settings';
import ZoneCreate from '@/pages/zones/Create';
import ZoneEditor from '@/pages/zones/Editor';
import ZoneImport from '@/pages/zones/Import';
import Zones from '@/pages/zones/Index';
import './app.css';
import './dnsone.css';

export type Me = {
    user: { id: number; username: string; name: string; email: string; role: string; auth_source: string; has_password: boolean; two_factor_enabled: boolean };
    permissions: string[];
    csrf: string;
    appVersion: string;
    clock: { now: number; timezone: string };
    node: string;
};

type Route = { pattern: RegExp; component: ComponentType<{ params: string[] }>; permission: string; title: string };

const ROUTES: Route[] = [
    { pattern: /^\/$/, component: Dashboard, permission: 'dashboard.view', title: 'Dashboard' },
    { pattern: /^\/zones$/, component: Zones, permission: 'zones.view', title: 'Zones' },
    { pattern: /^\/zones\/new$/, component: ZoneCreate, permission: 'zones.manage', title: 'New zone' },
    { pattern: /^\/zones\/import$/, component: ZoneImport, permission: 'zones.manage', title: 'Import a zone' },
    { pattern: /^\/zones\/(\d+)$/, component: ZoneEditor, permission: 'zones.view', title: 'Zone' },
    { pattern: /^\/queries$/, component: Queries, permission: 'queries.view', title: 'Query log' },
    { pattern: /^\/groups$/, component: Groups, permission: 'rpz.view', title: 'Client groups' },
    { pattern: /^\/blocking$/, component: Blocking, permission: 'rpz.view', title: 'Ad-blocking' },
    { pattern: /^\/audit$/, component: Audit, permission: 'audit.view', title: 'Audit log' },
    { pattern: /^\/settings$/, component: Settings, permission: '', title: 'Settings' },
    { pattern: /^\/profile$/, component: Profile, permission: '', title: 'My profile' },
];

function currentUrl(): string {
    // Users and roles moved under Settings; keep old links working.
    if (window.location.pathname === '/users') window.history.replaceState(null, '', '/settings?tab=users');
    return `${window.location.pathname}${window.location.search}`;
}

function shared(me: Me): SharedProps {
    return {
        appName: 'DNSOne',
        appVersion: me.appVersion,
        auth: { user: me.user, permissions: me.permissions },
        flash: null,
        logo: null,
        clock: { time: '', now: me.clock.now, timezone: me.clock.timezone },
        currency: '',
        errors: {},
    };
}

function Root() {
    const [me, setMe] = useState<Me | null | undefined>(undefined);
    const [url, setUrl] = useState(currentUrl);

    const signedIn = useCallback((next: Me) => {
        setCsrf(next.csrf);
        setMe(next);
    }, []);

    useEffect(() => {
        get<Me>('/api/auth/me').then(signedIn).catch(() => setMe(null));
        onSessionExpired(() => setMe(null));
    }, [signedIn]);

    useEffect(() => {
        bindRouter(
            (target, options = {}) => {
                if (target === currentUrl()) {
                    emit('reload');
                    return;
                }
                if (options.replace) window.history.replaceState(null, '', target);
                else window.history.pushState(null, '', target);
                setUrl(currentUrl());
                emit('navigate');
                if (!options.preserveScroll) window.scrollTo(0, 0);
            },
            async (method, target, data) => {
                await api(method, target, data ?? {});
                router.reload();
            },
        );
        const onPop = () => {
            setUrl(currentUrl());
            emit('navigate');
        };
        window.addEventListener('popstate', onPop);
        return () => window.removeEventListener('popstate', onPop);
    }, []);

    const props = useMemo(() => (me ? shared(me) : null), [me]);

    if (me === undefined) return null;
    if (me === null || !props) return <Login onSignedIn={signedIn} />;

    const path = url.split('?')[0];
    const page: Page = { component: path, props, url };
    const route = ROUTES.find((r) => r.pattern.test(path));
    let content;
    if (!route) {
        content = <AppLayout title="Not found"><Empty>This page does not exist. Use the navigation on the left.</Empty></AppLayout>;
    } else if (route.permission && !me.permissions.includes(route.permission)) {
        content = <AppLayout title={route.title}><Empty>Your role cannot open this page. Ask an administrator if you need access.</Empty></AppLayout>;
    } else {
        const Component = route.component;
        content = <Component key={path} params={route.pattern.exec(path)!.slice(1)} />;
    }
    return <PageProvider page={page}>{content}</PageProvider>;
}

createRoot(document.getElementById('app')!).render(
    <StrictMode>
        <ToastProvider>
            <ConfirmProvider>
                <Root />
            </ConfirmProvider>
        </ToastProvider>
    </StrictMode>,
);
