import { emit, Link, router, usePage } from '@inertiajs/react';
import { useEffect, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable, Pagination } from '@/components/table';
import { Tabs } from '@/components/tabs';
import { Badge, Check, Empty, Field, FormActions, HealthItem, ListPanel, Panel, Select, TextArea } from '@/components/ui';
import AppLayout from '@/layouts/AppLayout';
import { ApiError, del, get, patch, post, put, searchOf, useApi } from '@/lib/api';
import { useCan } from '@/lib/auth';
import { query } from '@/lib/format';
import type { Paginated } from '@/lib/types';

type Rule = { id: number; pattern: string; match_type: 'exact' | 'regex'; action: string; target: string | null; group_id: number | null; group: string | null; source: string; enabled: boolean; comment: string; created_by: string; updated_at: string };
type List = { id: number; name: string; url: string; format: string; kind: 'block' | 'allow'; enabled: boolean; last_updated: string | null; last_checked: string | null; last_status: string; last_error: string | null; domain_count: number; groups: { id: number; name: string }[] };
type Policy = { action: 'nxdomain' | 'nodata' | 'null_ip' | 'walled_garden'; walled_garden_target: string; block_subdomains: boolean };
type State = { serial: number; state: string; built_at: string | null; entries: number; error: string | null; pending: boolean; seconds?: number };
type Pause = { all: string | null; groups: { id: number; name: string; until: string }[] };
type Status = { state: State; policy: Policy; pause: Pause };
type Group = { id: number; name: string; built_in: boolean; blocking: boolean };
type Lookup = {
    domain: string; blocked: boolean; allowed: boolean; group: { id: number; name: string; blocking: boolean };
    rules: { id: number; pattern: string; action: string; enabled: boolean }[]; blocklists: { blocklist: string; match: string }[]; allowlists: { blocklist: string; match: string }[];
    legal: { id: number; pattern: string; authority: string; reference: string } | null; safe_search: string | null;
};

const ACTIONS: Record<string, string> = { block: 'Block (default policy)', allow: 'Allow (whitelist)', nxdomain: 'Block with NXDOMAIN', nodata: 'Block with empty answer', redirect: 'Redirect to…' };
const ACTION_TONE: Record<string, string> = { allow: 'success', block: 'danger', nxdomain: 'danger', nodata: 'danger', redirect: 'warning' };
const REGEX_ACTIONS: Record<string, string> = { block: 'Block (default policy)', allow: 'Allow (whitelist)' };
const LIST_TONE: Record<string, string> = { ok: 'success', not_modified: 'success', error: 'danger', never: 'warning' };
const ANSWERS: Record<Policy['action'], string> = {
    nxdomain: 'NXDOMAIN: the name does not exist',
    nodata: 'NODATA: the name exists but has no records',
    null_ip: 'Null IP: 0.0.0.0 and :: (clients give up at once)',
    walled_garden: 'Walled garden: send clients to a block page',
};

/** Client groups, for choosing where a rule or list applies. */
function useGroups() {
    return useApi<{ rows: Group[] }>('/api/groups').data?.rows ?? [];
}

function groupOptions(groups: Group[], everyone = 'Every group') {
    return [{ value: '', label: everyone }, ...groups.map((g) => ({ value: String(g.id), label: g.built_in ? `${g.name} (clients in no group)` : g.name }))];
}

/** An enable/disable toggle: a native checkbox with role=switch, saved optimistically. */
function Toggle({ checked, label, disabled, onChange }: { checked: boolean; label: string; disabled?: boolean; onChange: (on: boolean) => void }) {
    return <label className="check"><input type="checkbox" role="switch" checked={checked} disabled={disabled} aria-label={label} onChange={(e) => onChange(e.target.checked)} /> {checked ? 'On' : 'Off'}</label>;
}

function StatusPanel({ status, canManage, onBuilt }: { status: Status; canManage: boolean; onBuilt: () => void }) {
    const toast = useToast();
    const [busy, setBusy] = useState(false);
    const s = status.state;
    const tone = s.state === 'ok' ? 'success' : s.state === 'error' ? 'danger' : 'warning';
    return (
        <Panel
            title="Response policy zone"
            actions={canManage ? (
                <button type="button" disabled={busy} onClick={async () => {
                    setBusy(true);
                    try {
                        const r = await post<{ message: string }>('/api/rpz/build');
                        toast(r.message);
                    } catch (e) {
                        toast((e as ApiError).message, 'danger');
                    } finally {
                        setBusy(false);
                        onBuilt();
                    }
                }}><Icon name="refresh" />{busy ? 'Rebuilding…' : 'Rebuild now'}</button>
            ) : undefined}
        >
            <div className="health-grid">
                <HealthItem label="State" value={s.pending ? 'changes pending' : s.state === 'ok' ? 'loaded' : s.state} tone={s.pending ? 'info' : tone} />
                <HealthItem label="Blocked names (triggers)" value={(s.entries ?? 0).toLocaleString()} />
                <HealthItem label="Serial loaded in the Recursor" value={<span className="mono">{s.serial || '–'}</span>} />
                <HealthItem label="Last build" value={s.built_at ? `${s.built_at.replace('T', ' ')} UTC${s.seconds !== undefined ? `, ${s.seconds} s` : ''}` : 'never'} />
                <HealthItem label="Default response" value={{ nxdomain: 'NXDOMAIN (does not exist)', nodata: 'Empty answer (NODATA)', null_ip: 'Null IP (0.0.0.0 / ::)', walled_garden: `Walled garden: ${status.policy.walled_garden_target}` }[status.policy.action]} />
                <HealthItem label="Subdomains of blocked names" value={status.policy.block_subdomains ? 'blocked too' : 'not blocked'} />
            </div>
            {s.state === 'error' && s.error && <div className="flash danger"><pre className="publish-error">{s.error}</pre></div>}
        </Panel>
    );
}

const PAUSES: [number, string][] = [[5, '5 minutes'], [15, '15 minutes'], [60, '1 hour'], [240, '4 hours'], [0, 'Until resumed']];

function until(value: string) {
    return value === 'forever' ? 'until resumed' : `until ${value.slice(0, 16)}`;
}

/** Pause blocking for everyone or one group (e.g. while a customer tests a site); it resumes by itself. */
function PausePanel({ pause, canManage, onChanged }: { pause: Pause; canManage: boolean; onChanged: () => void }) {
    const toast = useToast();
    const groups = useGroups();
    const [group, setGroup] = useState('');
    const [minutes, setMinutes] = useState('5');
    const [busy, setBusy] = useState(false);
    const call = async (work: () => Promise<unknown>, done: string) => {
        setBusy(true);
        try {
            await work();
            toast(done);
            onChanged();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        } finally {
            setBusy(false);
        }
    };
    const paused = pause.all !== null || pause.groups.length > 0;
    return (
        <Panel title="Pause blocking" actions={paused ? <Badge tone="warning">paused</Badge> : <Badge tone="success">blocking</Badge>}>
            {paused && (
                <ul className="pause-list">
                    {pause.all && <li><strong>Everyone</strong> {until(pause.all)} {canManage && <button type="button" className="link" disabled={busy} onClick={() => void call(() => del('/api/rpz/pause'), 'Blocking resumed for everyone.')}>Resume</button>}</li>}
                    {pause.groups.map((g) => (
                        <li key={g.id}><strong>{g.name}</strong> {until(g.until)} {canManage && <button type="button" className="link" disabled={busy} onClick={() => void call(() => del(`/api/rpz/pause?group_id=${g.id}`), `Blocking resumed for ${g.name}.`)}>Resume</button>}</li>
                    ))}
                </ul>
            )}
            {canManage && (
                <form className="toolbar list-filterbar" onSubmit={(e) => {
                    e.preventDefault();
                    const name = group ? groups.find((g) => String(g.id) === group)?.name : 'everyone';
                    void call(() => post('/api/rpz/pause', { minutes: Number(minutes), group_id: group ? Number(group) : null }), `Blocking paused for ${name}. It takes effect at once.`);
                }}>
                    <label className="list-filter"><span>For</span>
                        <select value={group} onChange={(e) => setGroup(e.target.value)}>
                            {groupOptions(groups, 'Everyone').map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                        </select>
                    </label>
                    <label className="list-filter"><span>How long</span>
                        <select value={minutes} onChange={(e) => setMinutes(e.target.value)}>
                            {PAUSES.map(([m, label]) => <option key={m} value={m}>{label}</option>)}
                        </select>
                    </label>
                    <div className="list-filter-buttons"><button disabled={busy}>Pause</button></div>
                </form>
            )}
            {!paused && !canManage && <p className="hint">Blocking is on for everyone.</p>}
        </Panel>
    );
}

function RuleForm({ onAdded }: { onAdded: () => void }) {
    const toast = useToast();
    const groups = useGroups();
    const [form, setForm] = useState({ pattern: '', match_type: 'exact', action: 'block', target: '', comment: '', group_id: '' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const regex = form.match_type === 'regex';
    return (
        <form className="form-grid compact-form" onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
                const rule = await post<Rule>('/api/rpz/rules', { ...form, target: form.action === 'redirect' ? form.target : null, group_id: form.group_id ? Number(form.group_id) : null });
                toast(`${rule.action === 'allow' ? 'Allowed' : 'Blocked'} ${rule.pattern}${rule.group ? ` for ${rule.group}` : ''}. It takes effect within seconds.`);
                setForm({ ...form, pattern: '', comment: '' });
                setErrors({});
                onAdded();
            } catch (err) {
                const ae = err as ApiError;
                setErrors(Object.keys(ae.errors).length ? ae.errors : { pattern: ae.message });
            } finally {
                setBusy(false);
            }
        }}>
            <Select label="Match" name="match_type" options={{ exact: 'A domain', regex: 'A regular expression' }} value={form.match_type} onChange={(e) => setForm({ ...form, match_type: e.target.value, action: e.target.value === 'regex' && !(form.action in REGEX_ACTIONS) ? 'block' : form.action })} />
            <Field
                label={regex ? 'Regular expression' : 'Domain'}
                name="pattern"
                required
                autoComplete="off"
                spellCheck={false}
                placeholder={regex ? '^ads?[0-9]*\\. or (^|\\.)doubleclick\\.net$' : 'ads.example.com or *.example.com'}
                hint={regex
                    ? 'POSIX extended syntax, case-insensitive, matched anywhere in the name (no final dot): use ^ and $ to anchor, [0-9] for digits.'
                    : 'Names below it are covered too while the block policy blocks subdomains. *.example.com covers only the names below.'}
                value={form.pattern}
                error={errors.pattern}
                onChange={(e) => setForm({ ...form, pattern: e.target.value })}
            />
            <Select label="Action" name="action" options={regex ? REGEX_ACTIONS : ACTIONS} value={form.action} error={errors.action} onChange={(e) => setForm({ ...form, action: e.target.value })} />
            <Select label="Applies to" name="group_id" options={groupOptions(groups)} value={form.group_id} error={errors.group_id} hint="A group's own rule wins over a rule for every group." onChange={(e) => setForm({ ...form, group_id: e.target.value })} />
            {form.action === 'redirect' && <Field label="Redirect to" name="target" required placeholder="192.0.2.80 or block.example.net" value={form.target} error={errors.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />}
            <Field label="Comment" name="comment" autoComplete="off" value={form.comment} error={errors.comment} onChange={(e) => setForm({ ...form, comment: e.target.value })} />
            <FormActions className="form-actions"><button className="primary" disabled={busy}>Add rule</button></FormActions>
        </form>
    );
}

function ImportDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
    const toast = useToast();
    const [text, setText] = useState('');
    const [action, setAction] = useState('block');
    const [group, setGroup] = useState('');
    const groups = useGroups();
    const [busy, setBusy] = useState(false);
    return (
        <FormDialog open={open} title="Import domains" submitLabel="Import" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                const r = await post<{ added: number; existing: number; invalid_count: number; invalid: string[] }>('/api/rpz/rules/import', { action, text, group_id: group ? Number(group) : null });
                toast(`${r.added} rule(s) added, ${r.existing} already present${r.invalid_count ? `, ${r.invalid_count} invalid skipped (${r.invalid.slice(0, 3).join(', ')}…)` : ''}.`, r.invalid_count ? 'warning' : 'success');
                setText('');
                onDone();
                onClose();
            } catch (e) {
                toast((e as ApiError).message, 'danger');
            } finally {
                setBusy(false);
            }
        }}>
            <div className="form-grid">
                <Select label="Add as" options={{ block: 'Block', allow: 'Allow (whitelist)' }} value={action} onChange={(e) => setAction(e.target.value)} />
                <Select label="Applies to" options={groupOptions(groups)} value={group} onChange={(e) => setGroup(e.target.value)} />
                <TextArea label="Domains, one per line" rows={10} spellCheck={false} placeholder={'ads.example.com\n*.tracker.example.net'} hint="Lines starting with # are ignored. Up to 50,000 at a time." value={text} onChange={(e) => setText(e.target.value)} />
            </div>
        </FormDialog>
    );
}

function Rules({ canManage }: { canManage: boolean }) {
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const params = searchOf(url);
    const filters = { tab: 'rules', q: params.get('q') ?? '', action: params.get('action') ?? '', enabled: params.get('enabled') ?? '', match_type: params.get('match_type') ?? '', group: params.get('group') ?? '' };
    const groups = useGroups();
    const { data, setData, reload } = useApi<Paginated<Rule>>(`/api/rpz/rules${query({ ...filters, tab: '', page: params.get('page') ?? '' })}`);
    const [q, setQ] = useState(filters.q);
    const [importing, setImporting] = useState(false);
    const replace = (rule: Rule) => data && setData({ ...data, rows: data.rows.map((r) => (r.id === rule.id ? rule : r)) });

    const toggle = async (r: Rule, enabled: boolean) => {
        replace({ ...r, enabled });
        try {
            replace(await patch<Rule>(`/api/rpz/rules/${r.id}`, { enabled }));
            toast(`${r.pattern} ${enabled ? 'enabled' : 'disabled'}.`);
            emit('rpz-changed');
        } catch (e) {
            replace(r);
            toast((e as ApiError).message, 'danger');
        }
    };
    const remove = async (r: Rule) => {
        if (!(await ask({ title: `Delete rule for ${r.pattern}?`, message: r.action === 'allow' ? 'The domain is no longer whitelisted; blocklists apply to it again.' : 'The domain is no longer blocked by this rule.', confirmLabel: 'Delete rule' })) || !data) return;
        const previous = data;
        setData({ ...data, rows: data.rows.filter((x) => x.id !== r.id), total: data.total - 1 });
        try {
            await del(`/api/rpz/rules/${r.id}`);
            toast(`Rule for ${r.pattern} deleted.`);
            emit('rpz-changed');
        } catch (e) {
            setData(previous);
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <>
            {canManage && <Panel title="Block or allow a domain"><RuleForm onAdded={() => { void reload(); emit('rpz-changed'); }} /></Panel>}
            <ListPanel
                title="Rules"
                description={data ? `${data.total} matching ${data.total === 1 ? 'rule' : 'rules'}. Allow rules override every blocklist; a group's rules override those for every group.` : 'Loading…'}
                tools={canManage ? <button type="button" onClick={() => setImporting(true)}>Import list</button> : undefined}
            >
                <form className="toolbar list-filterbar" role="search" onSubmit={(e) => { e.preventDefault(); router.get('/blocking', { ...filters, q }, { preserveScroll: true }); }}>
                    <label className="list-search"><span>Search rules</span><input type="search" placeholder="Domain or comment" value={q} onChange={(e) => setQ(e.target.value)} /></label>
                    <label className="list-filter"><span>Action</span>
                        <select value={filters.action} onChange={(e) => router.get('/blocking', { ...filters, q, action: e.target.value }, { preserveScroll: true })}>
                            <option value="">All actions</option>
                            {Object.entries(ACTIONS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                        </select>
                    </label>
                    <label className="list-filter"><span>Type</span>
                        <select value={filters.match_type} onChange={(e) => router.get('/blocking', { ...filters, q, match_type: e.target.value }, { preserveScroll: true })}>
                            <option value="">Domains and regexes</option><option value="exact">Domains</option><option value="regex">Regular expressions</option>
                        </select>
                    </label>
                    <label className="list-filter"><span>Group</span>
                        <select value={filters.group} onChange={(e) => router.get('/blocking', { ...filters, q, group: e.target.value }, { preserveScroll: true })}>
                            <option value="">Any</option><option value="all">Every group</option>
                            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                        </select>
                    </label>
                    <label className="list-filter"><span>State</span>
                        <select value={filters.enabled} onChange={(e) => router.get('/blocking', { ...filters, q, enabled: e.target.value }, { preserveScroll: true })}>
                            <option value="">On and off</option><option value="1">On</option><option value="0">Off</option>
                        </select>
                    </label>
                    <div className="list-filter-buttons"><button>Filter</button></div>
                </form>
                {data && (
                    <>
                        <DataTable
                            rows={data.rows}
                            rowKey={(r) => r.id}
                            serverPaginated
                            emptyText="No rules match."
                            columns={[
                                { header: 'Domain or pattern', cell: (r) => <div className="list-cell-stack"><span className="mono">{r.pattern} {r.match_type === 'regex' && <Badge tone="info">regex</Badge>}</span>{r.comment && <span className="list-subline">{r.comment}</span>}</div> },
                                { header: 'Group', cell: (r) => r.group ?? 'Every group' },
                                { header: 'Action', cell: (r) => <><Badge tone={ACTION_TONE[r.action]}>{r.action}</Badge>{r.target && <> <span className="mono">{r.target}</span></>}</> },
                                { header: 'Enabled', cell: (r) => <Toggle checked={r.enabled} disabled={!canManage} label={`Rule ${r.pattern}`} onChange={(on) => void toggle(r, on)} /> },
                                { header: 'Source', cell: (r) => r.source },
                                { header: 'Added by', cell: (r) => r.created_by },
                                { header: 'Changed', cell: (r) => <span className="mono">{r.updated_at}</span> },
                                ...(canManage ? [{ header: 'Actions', noExport: true, cell: (r: Rule) => <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button> }] : []),
                            ]}
                        />
                        <Pagination result={data} path="/blocking" query={filters} noun="rules" />
                    </>
                )}
            </ListPanel>
            <ImportDialog open={importing} onClose={() => setImporting(false)} onDone={() => { void reload(); emit('rpz-changed'); }} />
        </>
    );
}

function BlocklistDialog({ list, onClose, onSaved }: { list: List | 'new' | null; onClose: () => void; onSaved: () => void }) {
    const toast = useToast();
    const editing = list && list !== 'new' ? list : null;
    const groups = useGroups();
    const [form, setForm] = useState({ name: editing?.name ?? '', url: editing?.url ?? '', format: editing?.format ?? 'auto', kind: editing?.kind ?? 'block', enabled: editing?.enabled ?? true });
    const [chosen, setChosen] = useState<number[] | null>(editing ? editing.groups.map((g) => g.id) : null);
    const selected = chosen ?? groups.filter((g) => g.built_in).map((g) => g.id);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <FormDialog open={list !== null} title={editing ? `Edit ${editing.name}` : 'Add a list'} submitLabel={editing ? 'Save' : 'Add and download'} busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                const { kind: _kind, ...changes } = form;
                if (editing) await patch(`/api/rpz/blocklists/${editing.id}`, { ...changes, group_ids: selected });
                else await post('/api/rpz/blocklists', { ...form, group_ids: selected });
                toast(editing ? `${form.name} saved.` : `${form.name} added. Downloading it and rebuilding the RPZ…`);
                onSaved();
                onClose();
            } catch (e) {
                const ae = e as ApiError;
                setErrors(Object.keys(ae.errors).length ? ae.errors : { url: ae.message });
            } finally {
                setBusy(false);
            }
        }}>
            <div className="form-grid">
                <Field label="Name" name="name" required value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Select label="Format" name="format" options={{ auto: 'Detect automatically', hosts: 'Hosts file (0.0.0.0 domain)', domains: 'One domain per line', adblock: 'Adblock (||domain^)' }} value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })} />
                <Field label="URL" name="url" className="span2" type="url" required spellCheck={false} placeholder="https://…/hosts.txt" value={form.url} error={errors.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
                <Select label="Kind" name="kind" disabled={Boolean(editing)} options={{ block: 'Blocklist: block these names', allow: 'Allowlist: never block these names' }} value={form.kind} hint={editing ? 'Fixed once added.' : undefined} onChange={(e) => setForm({ ...form, kind: e.target.value as List['kind'] })} />
                <fieldset className="span2 group-picks">
                    <legend>Used by</legend>
                    {groups.map((g) => (
                        <Check key={g.id} label={g.built_in ? `${g.name} (clients in no group)` : g.name} checked={selected.includes(g.id)}
                            onChange={(e) => setChosen(e.target.checked ? [...selected, g.id] : selected.filter((id) => id !== g.id))} />
                    ))}
                    {errors.group_ids && <small className="field-error">{errors.group_ids}</small>}
                </fieldset>
                <div className="span2"><Check label="Use this list" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /></div>
            </div>
        </FormDialog>
    );
}

function Blocklists({ canManage }: { canManage: boolean }) {
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const params = searchOf(url);
    const { data, setData, reload } = useApi<Paginated<List>>(`/api/rpz/blocklists${query({ page: params.get('page') ?? '' })}`);
    const [dialog, setDialog] = useState<List | 'new' | null>(null);
    const [refreshing, setRefreshing] = useState<number | null>(null);
    const replace = (l: List) => data && setData({ ...data, rows: data.rows.map((r) => (r.id === l.id ? l : r)) });

    const toggle = async (l: List, enabled: boolean) => {
        replace({ ...l, enabled });
        try {
            replace(await patch<List>(`/api/rpz/blocklists/${l.id}`, { enabled }));
            toast(`${l.name} ${enabled ? 'enabled' : 'disabled'}. Rebuilding the RPZ…`);
            emit('rpz-changed');
        } catch (e) {
            replace(l);
            toast((e as ApiError).message, 'danger');
        }
    };
    const refresh = async (l: List) => {
        setRefreshing(l.id);
        try {
            const r = await post<List & { message: string }>(`/api/rpz/blocklists/${l.id}/refresh`);
            replace(r);
            toast(`${l.name}: ${r.message}.`);
            emit('rpz-changed');
        } catch (e) {
            toast(`${l.name}: ${(e as ApiError).message}`, 'danger');
            void reload();
        } finally {
            setRefreshing(null);
        }
    };
    const remove = async (l: List) => {
        if (!(await ask({ title: `Delete ${l.name}?`, message: `Its ${l.domain_count.toLocaleString()} domains are no longer blocked.`, confirmLabel: 'Delete blocklist' })) || !data) return;
        const previous = data;
        setData({ ...data, rows: data.rows.filter((x) => x.id !== l.id), total: data.total - 1 });
        try {
            await del(`/api/rpz/blocklists/${l.id}`);
            toast(`${l.name} deleted.`);
            emit('rpz-changed');
        } catch (e) {
            setData(previous);
            toast((e as ApiError).message, 'danger');
        }
    };

    return (
        <ListPanel
            title="Blocklists and allowlists"
            description="Downloaded on the dnsone-rpz timer (every 6 hours). Each list applies to the groups that use it; allowlists override blocklists and block rules."
            tools={canManage ? <button type="button" className="primary" onClick={() => setDialog('new')}><Icon name="plus" />Add a list</button> : undefined}
        >
            {data && (
                <>
                    <DataTable
                        rows={data.rows}
                        rowKey={(r) => r.id}
                        serverPaginated
                        emptyText="No lists yet. Add one, for example a hosts-format blocklist."
                        columns={[
                            { header: 'Name', cell: (r) => <div className="list-cell-stack"><span>{r.name} {r.kind === 'allow' && <Badge tone="success">allowlist</Badge>}</span><span className="list-subline cell-truncate" title={r.url}>{r.url}</span></div> },
                            { header: 'Used by', cell: (r) => (r.groups.length ? r.groups.map((g) => g.name).join(', ') : <Badge tone="warning">no group</Badge>) },
                            { header: 'Enabled', cell: (r) => <Toggle checked={r.enabled} disabled={!canManage} label={`Blocklist ${r.name}`} onChange={(on) => void toggle(r, on)} /> },
                            { header: 'Domains', cell: (r) => r.domain_count.toLocaleString() },
                            { header: 'Status', cell: (r) => <span title={r.last_error ?? undefined}><Badge tone={LIST_TONE[r.last_status]}>{r.last_status.replace('_', ' ')}</Badge>{r.last_error && <span className="list-subline"> {r.last_error.slice(0, 80)}</span>}</span> },
                            { header: 'Updated', cell: (r) => <span className="mono">{r.last_updated ?? '-'}</span> },
                            { header: 'Checked', cell: (r) => <span className="mono">{r.last_checked ?? '-'}</span> },
                            ...(canManage ? [{
                                header: 'Actions', noExport: true, cell: (r: List) => (
                                    <div className="inline-actions">
                                        <button type="button" className="link" disabled={refreshing === r.id} onClick={() => void refresh(r)}>{refreshing === r.id ? 'Downloading…' : 'Refresh'}</button>
                                        <button type="button" className="link" onClick={() => setDialog(r)}>Edit</button>
                                        <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button>
                                    </div>
                                ),
                            }] : []),
                        ]}
                    />
                    <Pagination result={data} path="/blocking" query={{ tab: 'blocklists' }} noun="blocklists" />
                </>
            )}
            {dialog !== null && <BlocklistDialog list={dialog} onClose={() => setDialog(null)} onSaved={() => { void reload(); emit('rpz-changed'); window.setTimeout(() => { void reload(); emit('rpz-changed'); }, 4000); }} />}
        </ListPanel>
    );
}

function PolicyForm({ policy, canManage, onSaved }: { policy: Policy; canManage: boolean; onSaved: () => void }) {
    const toast = useToast();
    const [form, setForm] = useState(policy);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <form className="form-grid" onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
                await put('/api/rpz/policy', form);
                setErrors({});
                toast('Block policy saved. Rebuilding the RPZ…');
                onSaved();
            } catch (err) {
                const ae = err as ApiError;
                setErrors(Object.keys(ae.errors).length ? ae.errors : { action: ae.message });
            } finally {
                setBusy(false);
            }
        }}>
            <Select label="Answer for blocked names" name="action" disabled={!canManage} options={ANSWERS} value={form.action} error={errors.action} onChange={(e) => setForm({ ...form, action: e.target.value as Policy['action'] })} />
            {form.action === 'walled_garden' && <Field label="Block page" name="walled_garden_target" required disabled={!canManage} placeholder="192.0.2.80 or blocked.example.net" hint="An IP address is returned as A/AAAA; a host name as CNAME." value={form.walled_garden_target} error={errors.walled_garden_target} onChange={(e) => setForm({ ...form, walled_garden_target: e.target.value })} />}
            <div className="span2"><Check label="Also block every subdomain of a blocked name, from lists and rules (ads.example.com blocks x.ads.example.com)" disabled={!canManage} checked={form.block_subdomains} onChange={(e) => setForm({ ...form, block_subdomains: e.target.checked })} /></div>
            <p className="span2 hint">Rules with their own action (NXDOMAIN, empty answer, redirect) keep it. Regex rules answer with this policy. Allow rules always win. Clients see changes within a minute.</p>
            {canManage && <FormActions><button className="primary" disabled={busy}>Save policy</button></FormActions>}
        </form>
    );
}

function DomainCheck() {
    const groups = useGroups();
    const [group, setGroup] = useState('');
    const [domain, setDomain] = useState('');
    const [result, setResult] = useState<Lookup | null>(null);
    const [error, setError] = useState('');
    return (
        <>
            <form className="inline-form" onSubmit={async (e) => {
                e.preventDefault();
                try {
                    setResult(await get<Lookup>(`/api/rpz/lookup${query({ domain, group_id: group })}`));
                    setError('');
                } catch (err) {
                    setResult(null);
                    setError((err as ApiError).message);
                }
            }}>
                <Field label="Domain" required spellCheck={false} placeholder="ads.example.com" value={domain} error={error || undefined} onChange={(e) => setDomain(e.target.value)} />
                <Select label="For clients in" options={groupOptions(groups, 'Default')} value={group} onChange={(e) => setGroup(e.target.value)} />
                <button className="primary">Check</button>
            </form>
            {result && (
                <div className="check-result">
                    <p>
                        <strong className="mono">{result.domain}</strong>{' '}
                        {result.legal ? <Badge tone="warning">blocked by court order</Badge> : result.allowed ? <Badge tone="success">allowed by a rule</Badge> : result.blocked ? <Badge tone="danger">blocked</Badge> : <Badge>not blocked</Badge>}
                        {' '}<span className="hint">for {result.group.name}{result.group.blocking ? '' : ' (blocking is off for this group)'}</span>
                    </p>
                    {result.legal && <p className="hint">Court order {result.legal.reference} ({result.legal.authority}) blocks {result.legal.pattern} for every client: no rule, allowlist or pause lifts it. <Link href={`/legal?q=${encodeURIComponent(result.legal.reference)}`}>Court orders</Link></p>}
                    {result.safe_search && <p className="hint">Safe Search: this group's clients are sent to {result.safe_search}.</p>}
                    {result.rules.length > 0 && <p className="hint">Rules: {result.rules.map((r) => `${r.pattern} (${r.action}${r.enabled ? '' : ', off'})`).join('; ')}</p>}
                    {result.blocklists.length > 0 && <p className="hint">Listed in: {result.blocklists.map((b) => `${b.blocklist} as ${b.match}`).join('; ')}</p>}
                    {result.allowlists.length > 0 && <p className="hint">Allowed by the allowlist {result.allowlists.map((b) => b.blocklist).join(', ')}</p>}
                    {!result.rules.length && !result.blocklists.length && !result.allowlists.length && <p className="hint">No rule or enabled list of this group matches this name.</p>}
                </div>
            )}
        </>
    );
}

export default function Blocking() {
    const can = useCan();
    const canManage = can('rpz.manage');
    const status = useApi<Status>('/api/rpz/status');
    // Changes rebuild the RPZ in the background: follow it until the Recursor has the new serial.
    const pending = Boolean(status.data?.state.pending);
    useEffect(() => {
        if (!pending) return;
        const timer = window.setTimeout(() => void status.reload(), 2000);
        return () => window.clearTimeout(timer);
    }, [pending, status]);
    useEffect(() => router.on('rpz-changed', () => void status.reload()), [status]);
    return (
        <AppLayout title="Ad-blocking">
            {status.data ? <StatusPanel status={status.data} canManage={canManage} onBuilt={() => void status.reload()} /> : <Empty>Loading…</Empty>}
            {status.data && <PausePanel pause={status.data.pause} canManage={canManage} onChanged={() => void status.reload()} />}
            <Tabs
                label="Ad-blocking"
                tabs={[
                    { key: 'rules', title: 'Rules', icon: 'shield', content: <Rules canManage={canManage} /> },
                    { key: 'blocklists', title: 'Lists', icon: 'services', content: <Blocklists canManage={canManage} /> },
                    { key: 'policy', title: 'Block policy', icon: 'settings', content: <Panel title="Block policy">{status.data ? <PolicyForm key={JSON.stringify(status.data.policy)} policy={status.data.policy} canManage={canManage} onSaved={() => emit('rpz-changed')} /> : null}</Panel> },
                    { key: 'check', title: 'Check a domain', icon: 'search', content: <Panel title="Is this domain blocked?"><DomainCheck /></Panel> },
                ]}
            />
        </AppLayout>
    );
}
