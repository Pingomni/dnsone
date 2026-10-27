// Settings, laid out like RadiusOne's (resources/js/pages/settings/Settings.tsx): section navigation
// beside the selected section. New sections: add them to SECTIONS (components/dns/settings.tsx) and here.
import { usePage } from '@inertiajs/react';
import { available, SECTIONS, SettingsLinkNav } from '@/components/dns/settings';
import { Empty } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { searchOf } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { has, proScreen } from '@/lib/edition';
import { AlertsTab } from './AlertsTab';
import { LicenseTab } from './LicenseTab';
import { OverviewTab } from './OverviewTab';
import { BackupTab, DnsServerTab, PrivacyTab } from './ServerTabs';
import { UsersTab } from './UsersTab';

// The Pro tabs (src/pro/), where the build has them.
const ExportTab = proScreen('MoreTabs', 'ExportTab');
const SsoTab = proScreen('MoreTabs', 'SsoTab');
const ClusterTab = proScreen('ClusterTab', 'ClusterTab');
const JoinOnlyTab = proScreen('ClusterTab', 'JoinOnlyTab');
const FirewallTab = proScreen('FirewallTab', 'FirewallTab');

export default function Settings() {
    const can = useCan();
    const { url } = usePage();
    const allowed = SECTIONS.filter(([key, , , , , permission]) => available(key) && can(permission)).map(([key]) => key);
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
                    {tab === 'export' && ExportTab && <ExportTab />}
                    {tab === 'sso' && SsoTab && <SsoTab />}
                    {tab === 'backup' && <BackupTab />}
                    {tab === 'cluster' && (has('cluster') ? ClusterTab && <ClusterTab /> : JoinOnlyTab && <JoinOnlyTab />)}
                    {tab === 'firewall' && FirewallTab && <FirewallTab />}
                    {tab === 'license' && <LicenseTab />}
                    {!tab && <Empty>Your role has no settings to manage.</Empty>}
                </div>
            </div>
        </AppLayout>
    );
}
