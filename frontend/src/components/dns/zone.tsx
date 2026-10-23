import { Badge } from '@/components/ui';

export type ZoneRow = {
    id: number; name: string; description: string; serial: number; default_ttl: number; soa_mname: string; soa_rname: string;
    soa_refresh: number; soa_retry: number; soa_expire: number; soa_minimum: number; status: 'active' | 'disabled';
    dnssec: 'off' | 'on' | 'insecure';
    publish_state: 'pending' | 'published' | 'error'; pending: boolean; published_serial: number | null; published_at: string | null;
    last_error: string | null; record_count: number | null; created_at: string; updated_at: string;
};

/** DNSSEC signing state, shown beside the publish state when the zone is (or was) signed. */
export function DnssecState({ zone }: { zone: Pick<ZoneRow, 'dnssec'> }) {
    if (zone.dnssec === 'on') return <Badge tone="success">DNSSEC</Badge>;
    if (zone.dnssec === 'insecure') return <Badge tone="warning">DNSSEC being removed</Badge>;
    return null;
}

/** Publish state: plain "published" is the normal case; anything else is a badge. */
export function PublishState({ zone }: { zone: Pick<ZoneRow, 'status' | 'publish_state' | 'pending'> }) {
    if (zone.status === 'disabled') return <Badge>disabled</Badge>;
    if (zone.publish_state === 'error') return <Badge tone="danger">publish failed</Badge>;
    if (zone.publish_state === 'pending' || zone.pending) return <Badge tone="info">publishing</Badge>;
    return <Badge tone="success">published</Badge>;
}
