// Settings → Firewall (1.5): DNSOne's nftables table. Edits are a draft; Apply puts them live, and the
// console confirms it can still reach the server, or the previous rules come back after a minute.
import { useEffect, useRef, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { Sheet } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select, TextArea } from '@/components/ui';
import { ApiError, del, get, patch, post, put, useApi } from '@/lib/api';

type Config = { enabled: boolean; management_networks: string[]; dns: boolean; dot: boolean; doh: boolean };
type Rule = { id: number; position: number; action: 'accept' | 'drop' | 'reject'; protocol: string; source: string; ports: string; comment: string; enabled: boolean;
    created_by: string; created_at: string; expires_at: string | null; expired: boolean };
type Status = { state: string; id?: string; message?: string; at?: string; deadline?: number; ufw_active?: boolean; enabled?: boolean };
type Firewall = {
    config: Config; rules: Rule[]; secondaries: string[]; active: { id: string; by: string; at: string; enabled: boolean } | null; pending: boolean;
    status: Status; preview: string; warnings: string[]; client_ip: string; can_apply: boolean; confirm_seconds: number;
};

const lines = (text: string) => text.split('\n').map((l) => l.split('#')[0].trim()).filter(Boolean);
const STATE: Record<string, [string, string]> = {
    none: ['never applied', ''], applying: ['applying…', 'info'], confirming: ['confirming…', 'info'], applied: ['in force', 'success'],
    disabled: ['off', ''], rolled_back: ['rolled back', 'danger'], failed: ['failed', 'danger'],
};

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

/** Applies the draft and confirms it from this browser; resolves with the final status. Shared with Protection. */
export async function applyFirewall(onStatus: (s: Status) => void): Promise<Status> {
    const { id } = await post<{ id: string }>('/api/firewall/apply');
    const deadline = Date.now() + 120_000;
    let confirmed = false;
    while (Date.now() < deadline) {
        await new Promise((r) => window.setTimeout(r, 1000));
        let st: Status;
        try {
            st = await get<Status>('/api/firewall/status');
        } catch {
            continue;
        }
        onStatus(st);
        if (st.id !== id) continue;
        if (st.state === 'confirming' && !confirmed) {
            // Reaching the server with this request is the proof the new rules let the console through.
            await post('/api/firewall/confirm', { id });
            confirmed = true;
        } else if (['applied', 'disabled', 'rolled_back', 'failed'].includes(st.state)) {
            return st;
        }
    }
    return { state: 'failed', message: 'No answer from the server for two minutes. If it is unreachable, the previous rules come back within a minute.' };
}

function RuleDialog({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
    const [form, setForm] = useState({ action: 'drop', protocol: 'tcp', source: '', ports: '', comment: '', minutes: '0' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const portless = form.protocol === 'icmp' || form.protocol === 'any';
    return (
        <FormDialog open title="New firewall rule" submitLabel="Add rule" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                await post('/api/firewall/rules', { ...form, ports: portless ? '' : form.ports, minutes: Number(form.minutes) || 0 });
                onAdded();
            } catch (e) {
                setErrors(errorsOf(e, 'source'));
            } finally {
                setBusy(false);
            }
        }}>
            <ErrorSummary errors={errors} />
            <div className="form-grid">
                <Select label="Action" name="action" value={form.action} error={errors.action}
                    options={[{ value: 'accept', label: 'Accept' }, { value: 'drop', label: 'Drop (silently)' }, { value: 'reject', label: 'Reject (tell the sender)' }]}
                    onChange={(e) => setForm({ ...form, action: e.target.value })} />
                <Select label="Protocol" name="protocol" value={form.protocol} error={errors.protocol}
                    options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'tcp+udp', label: 'TCP and UDP' }, { value: 'icmp', label: 'ICMP (not the essential types)' }, { value: 'any', label: 'Everything' }]}
                    onChange={(e) => setForm({ ...form, protocol: e.target.value })} />
                <Field label="Source" name="source" spellCheck={false} placeholder="198.51.100.0/24 (empty: anyone)" value={form.source} error={errors.source}
                    onChange={(e) => setForm({ ...form, source: e.target.value })} />
                {!portless && <Field label="Ports" name="ports" spellCheck={false} placeholder="3306 or 80,443 or 1000-2000 (empty: all)" value={form.ports} error={errors.ports}
                    onChange={(e) => setForm({ ...form, ports: e.target.value })} />}
                <Field label="Comment" name="comment" value={form.comment} onChange={(e) => setForm({ ...form, comment: e.target.value })} />
                <Select label="For" name="minutes" value={form.minutes}
                    options={[{ value: '0', label: 'Permanently' }, { value: '60', label: '1 hour' }, { value: '1440', label: '1 day' }, { value: '10080', label: '1 week' }]}
                    onChange={(e) => setForm({ ...form, minutes: e.target.value })} />
            </div>
        </FormDialog>
    );
}

export function FirewallTab() {
    const toast = useToast();
    const ask = useConfirm();
    const { data, setData, error, reload } = useApi<Firewall>('/api/firewall');
    const [form, setForm] = useState<{ enabled: boolean; mgmt: string; dns: boolean; dot: boolean; doh: boolean } | null>(null);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [adding, setAdding] = useState(false);
    const [applying, setApplying] = useState<Status | null>(null);
    const loaded = useRef(false);
    useEffect(() => {
        if (data && !loaded.current) {
            loaded.current = true;
            setForm({ enabled: data.config.enabled, mgmt: data.config.management_networks.join('\n'), dns: data.config.dns, dot: data.config.dot, doh: data.config.doh });
        }
    }, [data]);
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data || !form) return <Empty>Loading…</Empty>;

    const saveConfig = async () => {
        try {
            setData(await put<Firewall>('/api/firewall/config', { enabled: form.enabled, management_networks: lines(form.mgmt), dns: form.dns, dot: form.dot, doh: form.doh }));
            setErrors({});
            toast('Saved as a draft: Apply puts it in force.');
        } catch (e) {
            setErrors(errorsOf(e, 'management_networks'));
        }
    };
    const apply = async () => {
        const ok = await ask({
            title: data.config.enabled ? 'Apply the firewall?' : 'Turn DNSOne\'s firewall off?',
            message: data.config.enabled
                ? `The rules below go in force on this server now (and on the other nodes within a minute). This page then confirms it can still reach the server; if it cannot within ${data.confirm_seconds} seconds, the previous rules come back by themselves.`
                : 'DNSOne removes its nftables table: only other firewalls (ufw, the provider\'s) still filter traffic.',
            confirmLabel: 'Apply',
        });
        if (!ok) return;
        setApplying({ state: 'applying' });
        try {
            const final = await applyFirewall(setApplying);
            toast(final.message ?? final.state, final.state === 'applied' || final.state === 'disabled' ? undefined : 'danger');
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        } finally {
            setApplying(null);
            void reload();
        }
    };
    const toggle = async (r: Rule) => {
        try {
            const next = await patch<Rule>(`/api/firewall/rules/${r.id}`, { enabled: !r.enabled });
            setData({ ...data, rules: data.rules.map((x) => (x.id === r.id ? next : x)), pending: true });
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const move = async (r: Rule, by: -1 | 1) => {
        try {
            await patch(`/api/firewall/rules/${r.id}`, { move: by });
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const remove = async (r: Rule) => {
        if (!(await ask({ title: 'Delete this rule?', message: 'It stops applying at the next Apply.', confirmLabel: 'Delete' }))) return;
        try {
            await del(`/api/firewall/rules/${r.id}`);
            void reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };
    const [label, tone] = STATE[data.status.state] ?? [data.status.state, ''];
    return (
        <>
            <Sheet title="Firewall" icon="shield" meta={<><Badge tone={tone}>{label}</Badge> {data.pending && <Badge tone="warning">changes not applied</Badge>}</>}>
                {!data.can_apply && <div className="flash warning panel-text">Applying is not set up on this server: run <code>sudo bash /opt/dnsone/ops/dnsone-postinstall</code> once.</div>}
                {data.warnings.map((w) => <div key={w} className="flash warning panel-text">{w}</div>)}
                <ErrorSummary errors={errors} />
                <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void saveConfig(); }}>
                    <div className="span2">
                        <Check label="DNSOne manages this server's firewall: everything not allowed below is dropped" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                    </div>
                    <TextArea label="Management networks" name="management_networks" rows={4} spellCheck={false} value={form.mgmt}
                        error={Object.entries(errors).find(([k]) => k.startsWith('management_networks'))?.[1]}
                        hint={`One per line. SSH and the console (22, 80, 443) are always open to them, whatever the rules say. You are at ${data.client_ip}.`}
                        onChange={(e) => setForm({ ...form, mgmt: e.target.value })} />
                    <fieldset className="span2 group-picks">
                        <legend>Open to everyone</legend>
                        <Check label="DNS (53, UDP and TCP)" checked={form.dns} onChange={(e) => setForm({ ...form, dns: e.target.checked })} />
                        <Check label="DNS over TLS (853)" checked={form.dot} onChange={(e) => setForm({ ...form, dot: e.target.checked })} />
                        <Check label="DNS over HTTPS (443)" checked={form.doh} onChange={(e) => setForm({ ...form, doh: e.target.checked })} />
                    </fieldset>
                    <p className="span2 hint">Always allowed: replies to the server's own connections, loopback, the ICMP that IPv4 and IPv6 need, ping (rate-limited){data.secondaries.length ? `, and zone transfers to the cluster's secondaries (${data.secondaries.join(', ')}, port 5301)` : ''}.</p>
                    <FormActions><button type="submit">Save draft</button></FormActions>
                </form>
            </Sheet>
            <Sheet title="Rules" icon="lock" meta={<button type="button" onClick={() => setAdding(true)}><Icon name="plus" />New rule</button>} className="firewall-rules">
                <p className="hint panel-text">Checked in order, after SSH and the console from the management networks and before the services above: the first rule that matches decides.</p>
                <DataTable
                    rows={data.rules}
                    rowKey={(r) => r.id}
                    emptyText="No rules: only the management networks and the services above get in."
                    columns={[
                        { header: '#', cell: (r) => r.position },
                        { header: 'Action', cell: (r) => <Badge tone={r.action === 'accept' ? 'success' : 'danger'}>{r.action}</Badge> },
                        { header: 'Protocol', cell: (r) => r.protocol },
                        { header: 'Source', cell: (r) => <span className="mono">{r.source || 'anyone'}</span> },
                        { header: 'Ports', cell: (r) => <span className="mono">{r.ports || (r.protocol === 'icmp' || r.protocol === 'any' ? '-' : 'all')}</span> },
                        { header: 'Comment', cell: (r) => <div className="list-cell-stack"><span>{r.comment || '-'}</span><span className="list-subline">{r.created_by}{r.expires_at ? `, until ${r.expires_at}` : ''}</span></div> },
                        { header: 'State', cell: (r) => (r.expired ? <Badge>expired</Badge> : r.enabled ? <Badge tone="success">on</Badge> : <Badge>off</Badge>) },
                        { header: 'Actions', noExport: true, cell: (r) => (
                            <>
                                <button type="button" className="link" onClick={() => void move(r, -1)} aria-label="Move up">↑</button>{' '}
                                <button type="button" className="link" onClick={() => void move(r, 1)} aria-label="Move down">↓</button>{' '}
                                <button type="button" className="link" onClick={() => void toggle(r)}>{r.enabled ? 'Turn off' : 'Turn on'}</button>{' '}
                                <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button>
                            </>
                        ) },
                    ]}
                />
            </Sheet>
            <Sheet title="Apply" icon="refresh" meta={data.active ? <span className="list-subline">last applied {data.active.at} by {data.active.by}</span> : null}>
                <div className="apply-state panel-text">
                    {applying ? <><Badge tone="info">{STATE[applying.state]?.[0] ?? applying.state}</Badge> <span>{applying.message ?? 'Asking the server to apply…'}</span></>
                        : data.status.message ? <span className={data.status.state === 'rolled_back' || data.status.state === 'failed' ? 'danger-text' : undefined}>{data.status.message}</span> : null}
                </div>
                <div className="inline-actions panel-text">
                    <button type="button" className="primary" disabled={Boolean(applying) || !data.can_apply} onClick={() => void apply()}>Apply{data.pending ? ' changes' : ' again'}</button>
                </div>
                <details className="panel-text"><summary>The nftables rules (draft)</summary><pre className="zone-preview">{data.preview}</pre></details>
            </Sheet>
            {adding && <RuleDialog onClose={() => setAdding(false)} onAdded={() => { setAdding(false); toast('Rule added to the draft: Apply puts it in force.'); void reload(); }} />}
        </>
    );
}
