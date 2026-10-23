// Settings → Alerts: where problems are sent (email, webhook, Telegram), and what is open now.
import { useState } from 'react';
import { useToast } from '@/components/dns/feedback';
import { SettingsRows, Sheet } from '@/components/settings';
import { DataTable } from '@/components/table';
import { Badge, Check, Empty, ErrorSummary, Field, FormActions, Select } from '@/components/ui';
import { ApiError, post, put, useApi } from '@/lib/api';

type Config = {
    enabled: boolean; for_minutes: number; repeat_hours: number; warnings: boolean;
    email: { enabled: boolean; to: string[]; from: string; smtp_host: string; smtp_port: number; smtp_security: string; smtp_user: string; smtp_password: string; smtp_password_set: boolean };
    webhook: { enabled: boolean; url: string };
    telegram: { enabled: boolean; bot_token: string; bot_token_set: boolean; chat_id: string };
};
type Alert = { key: string; severity: 'error' | 'warning'; title: string; detail: string; since: string; notified_at: string | null; node: string };
type NodeState = { node: string; checked_at: string | null; last_delivery: { at: string; results: Record<string, string> } | null };
type Data = { config: Config; active: Alert[]; nodes: NodeState[] };

const SECURITY = [{ value: 'starttls', label: 'STARTTLS (port 587)' }, { value: 'tls', label: 'TLS (port 465)' }, { value: 'none', label: 'None (port 25, trusted relay only)' }];

export function AlertsTab() {
    const { data, setData, error } = useApi<Data>('/api/settings/alerts');
    if (error) return <Empty tone="danger">{error.message}</Empty>;
    if (!data) return <Empty>Loading…</Empty>;
    return (
        <>
            <AlertsForm key={JSON.stringify(data.config)} config={data.config} onSaved={setData} />
            <Sheet title="Open problems" icon="activity" meta={<Badge tone={data.active.length ? 'warning' : 'success'}>{data.active.length || 'none'}</Badge>}>
                <DataTable
                    rows={data.active}
                    rowKey={(r) => `${r.node}/${r.key}`}
                    emptyText="Nothing is wrong right now."
                    columns={[
                        { header: 'Problem', cell: (r) => <div className="list-cell-stack"><span><Badge tone={r.severity === 'error' ? 'danger' : 'warning'}>{r.severity}</Badge> {r.title}</span><span className="list-subline">{r.detail}</span></div> },
                        { header: 'Node', cell: (r) => r.node },
                        { header: 'Since (UTC)', cell: (r) => <span className="mono">{r.since.replace('T', ' ')}</span> },
                        { header: 'Notified', cell: (r) => (r.notified_at ? <span className="mono">{r.notified_at.replace('T', ' ')}</span> : <span className="list-subline">not yet</span>) },
                    ]}
                />
                <div className="panel-text">
                    <SettingsRows rows={data.nodes.map((n) => [n.node, `checked ${n.checked_at?.replace('T', ' ') ?? 'never'} UTC${n.last_delivery ? `; last sent ${n.last_delivery.at.replace('T', ' ')}: ${Object.entries(n.last_delivery.results).map(([k, v]) => `${k} ${v}`).join(', ')}` : ''}`])} />
                </div>
            </Sheet>
            <Sheet title="Prometheus" icon="reports">
                <p className="hint panel-text">Every node serves its metrics at <code>/api/metrics</code> (health checks, zones, DNSSEC, RPZ, blocklists, DNS counters, certificate expiry, cluster sync). Scrape it with a read-only app password from My profile → App passwords:</p>
                <pre className="zone-preview">{`- job_name: dnsone\n  scheme: https\n  metrics_path: /api/metrics\n  authorization:\n    type: Bearer\n    credentials: dnsone_…\n  static_configs:\n    - targets: ['${window.location.host}']`}</pre>
            </Sheet>
        </>
    );
}

function AlertsForm({ config, onSaved }: { config: Config; onSaved: (d: Data) => void }) {
    const toast = useToast();
    const [form, setForm] = useState({ ...config, to: config.email.to.join(', ') });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const email = (patch: Partial<Config['email']>) => setForm({ ...form, email: { ...form.email, ...patch } });
    const body = () => ({ ...form, email: { ...form.email, to: form.to.split(/[,\s]+/).filter(Boolean) } });

    const save = async () => {
        setBusy(true);
        try {
            onSaved(await put<Data>('/api/settings/alerts', body()));
            setErrors({});
            toast('Alert settings saved. Problems are checked every minute.');
            return true;
        } catch (e) {
            const err = e as ApiError;
            setErrors(Object.keys(err.errors).length ? err.errors : { enabled: err.message });
            return false;
        } finally {
            setBusy(false);
        }
    };
    const test = async () => {
        if (!(await save())) return;
        try {
            const { results } = await post<{ results: Record<string, string> }>('/api/settings/alerts/test');
            const failed = Object.entries(results).filter(([, v]) => v !== 'ok');
            toast(failed.length ? `Test alert: ${failed.map(([k, v]) => `${k} ${v}`).join('; ')}` : `Test alert sent (${Object.keys(results).join(', ')}).`, failed.length ? 'danger' : undefined);
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <Sheet title="Alerts" icon="activity" meta={<Badge tone={config.enabled ? 'success' : ''}>{config.enabled ? 'on' : 'off'}</Badge>}>
            <ErrorSummary errors={errors} />
            <form className="form-grid" onSubmit={(e) => { e.preventDefault(); void save(); }}>
                <div className="span2">
                    <Check label="Send alerts when a service fails, a zone does not publish, a blocklist download fails, the DoT/DoH certificate is about to expire, a node stops syncing or a query flood is blocked" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                    <Check label="Also warnings (not only errors)" checked={form.warnings} onChange={(e) => setForm({ ...form, warnings: e.target.checked })} />
                </div>
                <Field label="Send after (minutes)" name="for_minutes" type="number" min={1} max={60} value={form.for_minutes} error={errors.for_minutes} hint="A problem must last this long: reloads and one slow probe stay quiet." onChange={(e) => setForm({ ...form, for_minutes: Number(e.target.value) })} />
                <Field label="Remind every (hours)" name="repeat_hours" type="number" min={0} max={168} value={form.repeat_hours} error={errors.repeat_hours} hint="While it lasts; 0 sends it once. A message follows when it is resolved." onChange={(e) => setForm({ ...form, repeat_hours: Number(e.target.value) })} />

                <h3 className="span2 form-section-title">Email</h3>
                <div className="span2"><Check label="Send by email" checked={form.email.enabled} onChange={(e) => email({ enabled: e.target.checked })} /></div>
                <Field label="To" name="email.to" placeholder="noc@isp.example, oncall@isp.example" value={form.to} error={errors['email.to']} onChange={(e) => setForm({ ...form, to: e.target.value })} />
                <Field label="From" name="email.from" type="email" placeholder="dnsone@isp.example" value={form.email.from} error={errors['email.from']} onChange={(e) => email({ from: e.target.value })} />
                <Field label="SMTP server" name="email.smtp_host" spellCheck={false} placeholder="smtp.isp.example" value={form.email.smtp_host} error={errors['email.smtp_host']} onChange={(e) => email({ smtp_host: e.target.value })} />
                <Field label="Port" name="email.smtp_port" type="number" min={1} max={65535} value={form.email.smtp_port} error={errors['email.smtp_port']} onChange={(e) => email({ smtp_port: Number(e.target.value) })} />
                <Select label="Encryption" name="email.smtp_security" options={SECURITY} value={form.email.smtp_security} onChange={(e) => email({ smtp_security: e.target.value })} />
                <Field label="User (optional)" name="email.smtp_user" autoComplete="off" value={form.email.smtp_user} onChange={(e) => email({ smtp_user: e.target.value })} />
                <Field label="Password" name="email.smtp_password" type="password" autoComplete="new-password" placeholder={config.email.smtp_password_set ? 'unchanged' : ''} value={form.email.smtp_password} onChange={(e) => email({ smtp_password: e.target.value })} />

                <h3 className="span2 form-section-title">Webhook</h3>
                <div className="span2"><Check label="Post to a webhook (Slack, Mattermost, Rocket.Chat, Teams, or your own: JSON with a text field and the alerts)" checked={form.webhook.enabled} onChange={(e) => setForm({ ...form, webhook: { ...form.webhook, enabled: e.target.checked } })} /></div>
                <Field label="URL" name="webhook.url" className="span2" spellCheck={false} placeholder="https://hooks.slack.com/services/…" value={form.webhook.url} error={errors['webhook.url']} onChange={(e) => setForm({ ...form, webhook: { ...form.webhook, url: e.target.value } })} />

                <h3 className="span2 form-section-title">Telegram</h3>
                <div className="span2"><Check label="Send to a Telegram chat" checked={form.telegram.enabled} onChange={(e) => setForm({ ...form, telegram: { ...form.telegram, enabled: e.target.checked } })} /></div>
                <Field label="Bot token" name="telegram.bot_token" type="password" autoComplete="off" placeholder={config.telegram.bot_token_set ? 'unchanged' : 'from @BotFather'} value={form.telegram.bot_token} error={errors['telegram.bot_token']} onChange={(e) => setForm({ ...form, telegram: { ...form.telegram, bot_token: e.target.value } })} />
                <Field label="Chat id" name="telegram.chat_id" spellCheck={false} placeholder="-1001234567890" value={form.telegram.chat_id} error={errors['telegram.chat_id']} onChange={(e) => setForm({ ...form, telegram: { ...form.telegram, chat_id: e.target.value } })} />

                <FormActions>
                    <button type="button" disabled={busy} onClick={() => void test()}>Save and send a test</button>
                    <button className="primary" disabled={busy}>Save</button>
                </FormActions>
            </form>
        </Sheet>
    );
}
