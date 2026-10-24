// Settings, laid out like RadiusOne's (resources/js/pages/settings/Settings.tsx): section navigation
// beside the selected section. New sections: add them to SECTIONS (components/dns/settings.tsx) and here.
import { usePage } from '@inertiajs/react';
import { SECTIONS, SettingsLinkNav } from '@/components/dns/settings';
import { Empty } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { searchOf } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { AlertsTab } from './AlertsTab';
import { ExportTab, SsoTab } from './MoreTabs';
import { OverviewTab } from './OverviewTab';
import { BackupTab, ClusterTab, DnsServerTab, PrivacyTab } from './ServerTabs';
import { UsersTab } from './UsersTab';

export default function Settings() {
    const can = useCan();
    const { url } = usePage();
    const allowed = SECTIONS.filter(([, , , , , permission]) => can(permission)).map(([key]) => key);
    const requested = searchOf(url).get('tab') ?? 'overview';
    const tab = allowed.includes(requested) ? requested : allowed[0];

    return (
        <AppLayout title="Settings">
            <div className="settings-console">
                <SettingsLinkNav active={tab} />
                <div className="settings-menu-body">
                    {tab === 'overview' && <OverviewTab />}
                    {tab === 'users' && <UsersTab />}
                    {tab === 'dns-server' && <DnsServerTab />}
                    {tab === 'privacy' && <PrivacyTab />}
                    {tab === 'alerts' && <AlertsTab />}
                    {tab === 'export' && <ExportTab />}
                    {tab === 'sso' && <SsoTab />}
                    {tab === 'backup' && <BackupTab />}
                    {tab === 'cluster' && <ClusterTab />}
                    {!tab && <Empty>Your role has no settings to manage.</Empty>}
                </div>
            </div>
        </AppLayout>
    );
}
