import { Destination } from '@/components/dns/settings';
import { SettingsRows, Sheet } from '@/components/settings';
import { Badge, Empty } from '@/components/ui';
import { useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';

type Overview = { usersSummary: { enabled: number; total: number }; zonesSummary: { active: number; disabled: number }; rpzEntries: number; rows: [string, string][] };

export function OverviewTab() {
    const can = useCan();
    const { data, error } = useApi<Overview>('/api/settings/overview');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    return (
        <>
            <div className="settings-destinations">
                {can('users.manage') && <Destination title="Users & access" href="/settings?tab=users" icon="clients" status={<Badge tone="success">{data.usersSummary.enabled} enabled</Badge>} />}
                <Destination title="Zones" href="/zones" icon="server" status={<Badge>{data.zonesSummary.active} active</Badge>} />
                <Destination title="Ad-blocking" href="/blocking?tab=policy" icon="shield" status={<Badge>{data.rpzEntries.toLocaleString()} blocked names</Badge>} />
            </div>
            <Sheet title="System information" icon="server" meta={<Badge tone="success">running</Badge>}>
                <SettingsRows rows={data.rows} />
            </Sheet>
        </>
    );
}
