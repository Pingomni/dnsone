import { useEffect, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { Destination } from '@/components/dns/settings';
import { SettingsRows, Sheet } from '@/components/settings';
import { Badge, Empty, FormActions } from '@/components/ui';
import { get, post, useApi, type ApiError } from '@/lib/api';
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
            <SoftwareUpdate />
        </>
    );
}

type Release = { tag: string; version: string; notes: string; url: string; published_at: string | null };
type Update = {
    installed: string;
    latest: Release | null;
    error: string | null;
    available: boolean;
    can_install: boolean;
    requested: boolean;
    progress: { state: 'none' | 'running' | 'done' | 'failed'; from: string | null; to: string | null; started: string | null; finished: string | null; log: string };
};

/** Settings → Overview → Software update: the latest release on GitHub, installed by dnsone-update (root). */
function SoftwareUpdate() {
    const ask = useConfirm();
    const { data, setData, error } = useApi<Update>('/api/settings/update');
    const [busy, setBusy] = useState(false);
    const [message, setMessage] = useState<string | null>(null);
    const [watching, setWatching] = useState(false);
    const installing = Boolean(data && (data.requested || data.progress.state === 'running'));

    // While an install runs, the API restarts: keep asking, and ignore the moments it does not answer.
    useEffect(() => {
        if (!installing && !watching) return;
        const timer = window.setInterval(async () => {
            try {
                const next = await get<Update>('/api/settings/update');
                setData(next);
                if (!next.requested && next.progress.state !== 'running') setWatching(false);
            } catch { /* the API is restarting */ }
        }, 3000);
        return () => window.clearInterval(timer);
    }, [installing, watching, setData]);

    if (error) return <Sheet title="Software update" icon="refresh"><Empty tone="danger">{error.message}</Empty></Sheet>;
    if (!data) return <Sheet title="Software update" icon="refresh"><Empty>Loading…</Empty></Sheet>;

    const check = async () => {
        setBusy(true);
        setMessage(null);
        try {
            setData(await get<Update>('/api/settings/update?refresh=1'));
        } catch (e) {
            setMessage((e as ApiError).message);
        } finally {
            setBusy(false);
        }
    };
    const install = async () => {
        const version = data.latest?.version;
        const ok = await ask({
            title: `Install DNSOne ${version}?`,
            message: 'The server downloads the release, backs up the database and the installation, installs it and checks it. '
                + 'The console restarts and is unavailable for a minute or two; DNS keeps answering. If anything fails, the current version is put back.',
            confirmLabel: 'Install update',
        });
        if (!ok) return;
        setBusy(true);
        setMessage(null);
        try {
            await post('/api/settings/update');
            setData({ ...data, requested: true });
            setWatching(true);
        } catch (e) {
            setMessage((e as ApiError).message);
        } finally {
            setBusy(false);
        }
    };

    const { progress, latest } = data;
    const finishedHere = progress.state === 'done' && progress.to === data.installed && progress.from !== data.installed;
    const showLog = installing || progress.state === 'failed' || (finishedHere && Boolean(progress.log));
    let state;
    if (installing) state = <Badge tone="warning">installing</Badge>;
    else if (data.available) state = <Badge tone="warning">update available</Badge>;
    else if (latest) state = <Badge tone="success">up to date</Badge>;

    return (
        <Sheet title="Software update" icon="refresh" meta={state}>
            <div className="update-sheet">
                <p>Installed: <strong>DNSOne {data.installed}</strong></p>
                {installing && <p>Installing DNSOne {progress.to ?? latest?.version}… The console restarts during the update; this page follows it.</p>}
                {!installing && data.available && latest && (
                    <p><strong>DNSOne {latest.version} is available</strong>{latest.published_at && ` (released ${latest.published_at.slice(0, 10)})`}.</p>
                )}
                {!installing && !data.available && latest && <p className="success-text">DNSOne is up to date (the latest release is {latest.version}).</p>}
                {data.error && <p className="danger-text">{data.error}</p>}
                {!installing && progress.state === 'failed' && (
                    <p className="danger-text">The update to {progress.to} failed{progress.finished && ` on ${progress.finished.slice(0, 16).replace('T', ' ')}`}; DNSOne {data.installed} runs. Its log is below.</p>
                )}
                {!installing && finishedHere && (
                    <p className="success-text">Updated from {progress.from} to {progress.to}. <button type="button" className="link" onClick={() => window.location.reload()}>Reload the console</button> to load the new version.</p>
                )}
                {data.available && !data.can_install && (
                    <p className="hint">Installing from the console is not set up on this server. Run <code>sudo dnsone-update</code> once on it (that also installs this update).</p>
                )}
                {message && <p className="danger-text" role="alert">{message}</p>}
                {showLog ? <pre aria-label="Update log">{progress.log || 'Waiting for the update to start…'}</pre>
                    : data.available && latest?.notes && <pre aria-label={`What is new in ${latest.version}`}>{latest.notes}</pre>}
                <FormActions>
                    {data.available && data.can_install && !installing && (
                        <button type="button" className="primary" disabled={busy} onClick={() => void install()}>Install DNSOne {latest?.version}</button>
                    )}
                    <button type="button" disabled={busy || installing} onClick={() => void check()}>Check for updates</button>
                    {latest && <a className="button" href={latest.url} target="_blank" rel="noopener noreferrer">Release notes</a>}
                </FormActions>
            </div>
        </Sheet>
    );
}
