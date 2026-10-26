// Help: docs/USER-GUIDE.md, bundled into the console at build time (so it matches this version and works
// without internet), shown with RadiusOne's guide component (components/guide.tsx, copied by
// tools/sync-radiusone.sh), so it looks like RadiusOne's Documentation. The same guide is published on
// pingomni.com/docs/dnsone/.
import Guide from '@/components/guide';
import AppLayout from '@/layouts/AppLayout';
import { useShared } from '@/lib/auth';
import guide from '../../../docs/USER-GUIDE.md?raw';

const REPO_DOCS = 'https://github.com/Pingomni/dnsone/blob/main/docs/';

// Section icons, by the section's heading without its number.
const ICONS: Record<string, string> = {
    'what-dnsone-does': 'book',
    'signing-in-and-your-account': 'user',
    'who-can-do-what': 'lock',
    dashboard: 'dashboard',
    'zones-authoritative-dns': 'server',
    'the-resolver-for-your-customers': 'signal',
    'ad-blocking-and-client-groups': 'shield',
    'court-ordered-blocking-pro': 'logs',
    'query-log': 'search',
    'protection-attacks-pro': 'activity',
    'customers-resellers-and-quotas-pro': 'clients',
    settings: 'settings',
    'audit-log': 'reports',
    'automation-api-dynamic-dns-certbot': 'refresh',
    'good-to-know': 'message',
};

export default function Help() {
    const { appVersion } = useShared();
    return (
        <AppLayout title="Help">
            <Guide
                markdown={guide}
                title="DNSOne user guide"
                product="DNSOne"
                version={appVersion}
                icons={ICONS}
                docsBase={REPO_DOCS}
                searchPlaceholder="e.g. DNSSEC, blocklist, rate limit"
            />
        </AppLayout>
    );
}
