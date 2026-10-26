// Settings → Users (administrators), and Customers (resellers: their own customer accounts only).
import { usePage } from '@inertiajs/react';
import { useEffect, useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable, Pagination } from '@/components/table';
import { Sheet } from '@/components/settings';
import { Badge, Check, Empty, Field, Select } from '@/components/ui';
import { ApiError, del, get, patch, post, put, searchOf, useApi } from '@/lib/api';
import { FEATURES } from '@/lib/edition';
import { query, randomPassword } from '@/lib/format';
import type { Paginated } from '@/lib/types';

type Operator = {
    id: number; username: string; name: string; email: string; role: string; role_id: number; zone_scope: 'all' | 'assigned'; zones: number | null; parent_id: number | null;
    enabled: boolean; auth_source: string; sso_linked: boolean; last_login_at: string | null; locked: boolean; self: boolean; two_factor_enabled: boolean;
    max_zones: number | null; max_records: number | null; api_rate: number | null;
};
type Limits = { max_zones: string; max_records: string; api_rate: string };
const limit = (v: string) => (v.trim() === '' ? null : Number(v));
type Role = { id: number; name: string; description: string; permissions: string[]; zone_scope: 'all' | 'assigned'; built_in: boolean; users: number };
type Roles = { roles: Role[]; permissions: Record<string, string>; zone_permissions: string[] };
type ZoneRef = { id: number; name: string };
type Users = Paginated<Operator> & { summary: { enabled: number; total: number }; resellers?: { id: number; username: string }[] };

function errorsOf(e: unknown, fallback: string): Record<string, string> {
    const ae = e as ApiError;
    return Object.keys(ae.errors).length ? ae.errors : { [fallback]: ae.message };
}

/** Zones given to a customer: search the caller's zones, tick the ones to give. */
function ZonePicker({ value, onChange }: { value: ZoneRef[]; onChange: (zones: ZoneRef[]) => void }) {
    const [q, setQ] = useState('');
    const [found, setFound] = useState<ZoneRef[]>([]);
    useEffect(() => {
        const timer = window.setTimeout(() => {
            get<Paginated<ZoneRef>>(`/api/zones${query({ q, size: 20 })}`).then((r) => setFound(r.rows), () => setFound([]));
        }, 200);
        return () => window.clearTimeout(timer);
    }, [q]);
    const has = (z: ZoneRef) => value.some((v) => v.id === z.id);
    return (
        <fieldset className="span2 group-picks">
            <legend>Zones ({value.length})</legend>
            {value.map((z) => <Check key={z.id} checked label={<span className="mono">{z.name}</span>} onChange={() => onChange(value.filter((v) => v.id !== z.id))} />)}
            <label className="list-search"><span>Find a zone to add</span><input type="search" spellCheck={false} placeholder="example.com" value={q} onChange={(e) => setQ(e.target.value)} /></label>
            {found.filter((z) => !has(z)).slice(0, 10).map((z) => <Check key={z.id} checked={false} label={<span className="mono">{z.name}</span>} onChange={() => onChange([...value, z])} />)}
        </fieldset>
    );
}

function UserDialog({ user, roles, reseller, resellers, onClose, onSaved }: {
    user: Operator | 'new'; roles: Role[]; reseller: boolean; resellers: { id: number; username: string }[]; onClose: () => void; onSaved: () => void;
}) {
    const toast = useToast();
    const editing = user !== 'new' ? user : null;
    const fallbackRole = roles.find((r) => r.name === (reseller ? 'customer' : 'operator')) ?? roles[0];
    const [form, setForm] = useState({
        username: editing?.username ?? '', name: editing?.name ?? '', email: editing?.email ?? '', role_id: String(editing?.role_id ?? fallbackRole?.id ?? ''),
        password: '', enabled: editing?.enabled ?? true, reset_two_factor: false, auth_source: editing?.auth_source ?? 'local', parent_id: String(editing?.parent_id ?? ''),
    });
    const [limits, setLimits] = useState<Limits>({
        max_zones: editing?.max_zones == null ? '' : String(editing.max_zones), max_records: editing?.max_records == null ? '' : String(editing.max_records),
        api_rate: editing?.api_rate == null ? '' : String(editing.api_rate),
    });
    const [zones, setZones] = useState<ZoneRef[]>([]);
    const [zonesLoaded, setZonesLoaded] = useState(!editing);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const role = roles.find((r) => String(r.id) === form.role_id);
    const assigned = role?.zone_scope === 'assigned';
    useEffect(() => {
        if (!editing) return;
        get<{ rows: ZoneRef[] }>(`/api/users/${editing.id}/zones`).then((r) => { setZones(r.rows); setZonesLoaded(true); }, () => setZonesLoaded(true));
    }, [editing]);
    const local = form.auth_source === 'local';
    return (
        <FormDialog open title={editing ? `Edit ${editing.username}` : reseller ? 'New customer' : 'New user'} submitLabel={editing ? 'Save' : 'Create'} busy={busy || !zonesLoaded} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                const parent = !reseller && assigned && form.parent_id ? Number(form.parent_id) : null;
                const zoneIds = assigned ? zones.map((z) => z.id) : [];
                const quotas = assigned ? { max_zones: limit(limits.max_zones), max_records: limit(limits.max_records), api_rate: limit(limits.api_rate) } : {};
                if (editing) {
                    await patch(`/api/users/${editing.id}`, {
                        name: form.name, email: form.email, role_id: Number(form.role_id), enabled: form.enabled, reset_two_factor: form.reset_two_factor,
                        password: local && form.password ? form.password : null,
                        ...(reseller ? {} : parent ? { parent_id: parent } : { clear_parent: Boolean(editing.parent_id) }),
                        ...(editing.self ? {} : quotas),
                    });
                    if (assigned || editing.zones) await put(`/api/users/${editing.id}/zones`, { zone_ids: zoneIds });
                } else {
                    await post('/api/users', { ...form, role_id: Number(form.role_id), parent_id: parent, zone_ids: zoneIds, password: local ? form.password : '', ...quotas });
                }
                toast(editing ? `${form.username} saved.` : `${form.username} created.`);
                onSaved();
                onClose();
            } catch (e) {
                setErrors(errorsOf(e, 'username'));
            } finally {
                setBusy(false);
            }
        }}>
            <div className="form-grid">
                <Field label="Username" name="username" required disabled={Boolean(editing)} autoComplete="off" value={form.username} error={errors.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
                <Select label="Role" name="role_id" options={roles.map((r) => ({ value: String(r.id), label: r.name }))} value={form.role_id} error={errors.role_id}
                    hint={role?.description} onChange={(e) => setForm({ ...form, role_id: e.target.value })} />
                <Field label="Full name" name="name" value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Field label="Email" name="email" type="email" required={!local} value={form.email} error={errors.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
                {!editing && !reseller && FEATURES.oidc && (
                    <Select label="Signs in with" name="auth_source" className="span2" value={form.auth_source}
                        hint={local ? undefined : 'Invited: the first single sign-on with this email (verified by the provider) links the account.'}
                        options={[{ value: 'local', label: 'A DNSOne password' }, { value: 'oidc', label: 'Single sign-on (Settings → Single sign-on)' }]}
                        onChange={(e) => setForm({ ...form, auth_source: e.target.value })} />
                )}
                {local ? (
                    <>
                        <Field label={editing ? 'New password' : 'Password'} name="password" className="span2" required={!editing} autoComplete="new-password"
                            hint={editing ? 'Leave empty to keep it. Setting one signs the user out everywhere.' : 'At least 12 characters. Share it securely.'}
                            value={form.password} error={errors.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                        <div className="span2 inline-actions"><button type="button" onClick={() => setForm({ ...form, password: randomPassword(18) })}>Generate password</button></div>
                    </>
                ) : editing && <p className="span2 hint">Signs in with single sign-on{editing.sso_linked ? '' : ' (not linked yet: waiting for the first sign-in)'}.</p>}
                {FEATURES.quota && !reseller && assigned && resellers.length > 0 && (
                    <Select label="Reseller" name="parent_id" placeholder="None (managed by administrators)" options={resellers.filter((r) => r.id !== editing?.id).map((r) => ({ value: String(r.id), label: r.username }))}
                        value={form.parent_id} error={errors.parent_id} hint="The reseller can manage this customer and give it its own zones." onChange={(e) => setForm({ ...form, parent_id: e.target.value })} />
                )}
                {assigned && zonesLoaded && <ZonePicker value={zones} onChange={setZones} />}
                {FEATURES.quota && assigned && !editing?.self && (
                    <fieldset className="span2 form-grid quota-fields">
                        <legend>Limits <span className="list-subline">empty: {reseller ? 'yours' : 'no limit'}</span></legend>
                        <Field label="Zones it may hold" name="max_zones" type="number" min={0} value={limits.max_zones} error={errors.max_zones}
                            onChange={(e) => setLimits({ ...limits, max_zones: e.target.value })} />
                        <Field label="Records per zone" name="max_records" type="number" min={0} value={limits.max_records} error={errors.max_records}
                            hint="Checked when the account adds records." onChange={(e) => setLimits({ ...limits, max_records: e.target.value })} />
                        <Field label="API requests per minute" name="api_rate" type="number" min={0} value={limits.api_rate} error={errors.api_rate}
                            hint="Console and app passwords together; over it, requests get 429." onChange={(e) => setLimits({ ...limits, api_rate: e.target.value })} />
                    </fieldset>
                )}
                {!assigned && role && <p className="span2 hint">{role.name} covers every zone.</p>}
                <div className="span2 inline-actions">
                    {!editing?.self && <Check label="Can sign in" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />}
                    {editing?.two_factor_enabled && <Check label="Turn off two-factor sign-in (lost phone)" checked={form.reset_two_factor} onChange={(e) => setForm({ ...form, reset_two_factor: e.target.checked })} />}
                </div>
            </div>
        </FormDialog>
    );
}

function RoleDialog({ role, roles, onClose, onSaved }: { role: Role | 'new'; roles: Roles; onClose: () => void; onSaved: () => void }) {
    const toast = useToast();
    const editing = role !== 'new' ? role : null;
    const [form, setForm] = useState({ name: editing?.name ?? '', description: editing?.description ?? '', permissions: editing?.permissions ?? ['zones.view'], zone_scope: editing?.zone_scope ?? 'all' });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const locked = Boolean(editing?.built_in);
    const allowed = (p: string) => form.zone_scope === 'all' || roles.zone_permissions.includes(p);
    const toggle = (p: string, on: boolean) => setForm({ ...form, permissions: on ? [...form.permissions, p] : form.permissions.filter((x) => x !== p) });
    return (
        <FormDialog open title={editing ? `Role ${editing.name}` : 'New role'} submitLabel="Save role" busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                const body = { ...form, permissions: form.permissions.filter(allowed) };
                if (editing) await patch(`/api/roles/${editing.id}`, locked ? { description: form.description } : body);
                else await post('/api/roles', body);
                toast(`Role ${form.name} saved.`);
                onSaved();
                onClose();
            } catch (e) {
                setErrors(errorsOf(e, 'name'));
            } finally {
                setBusy(false);
            }
        }}>
            {locked && <p className="hint">Built-in roles keep their permissions; create a new role for different access.</p>}
            <div className="form-grid">
                <Field label="Name" name="name" required disabled={Boolean(editing)} spellCheck={false} placeholder="noc, support, reseller-gold" value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Select label="Zones" name="zone_scope" disabled={locked} value={form.zone_scope} error={errors.zone_scope}
                    options={[{ value: 'all', label: 'Every zone' }, { value: 'assigned', label: 'Only the zones given to the user (customers, resellers)' }]}
                    onChange={(e) => setForm({ ...form, zone_scope: e.target.value as Role['zone_scope'] })} />
                <Field label="Description" name="description" className="span2" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                <fieldset className="span2 group-picks">
                    <legend>Permissions</legend>
                    {Object.entries(roles.permissions).map(([p, label]) => (
                        <Check key={p} disabled={locked || !allowed(p)} checked={form.permissions.includes(p) && allowed(p)} onChange={(e) => toggle(p, e.target.checked)}
                            label={<>{label} <span className="list-subline mono">{p}</span></>} />
                    ))}
                    {errors.permissions && <small className="field-error">{errors.permissions}</small>}
                </fieldset>
            </div>
        </FormDialog>
    );
}

export function UsersTab({ reseller = false }: { reseller?: boolean }) {
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const params = searchOf(url);
    const { data, setData, reload } = useApi<Users>(`/api/users${query({ page: params.get('page') ?? '' })}`);
    const roles = useApi<Roles>('/api/roles');
    const [dialog, setDialog] = useState<Operator | 'new' | null>(null);
    const [roleDialog, setRoleDialog] = useState<Role | 'new' | null>(null);

    const remove = async (u: Operator) => {
        if (!(await ask({ title: `Delete ${u.username}?`, message: `${u.username} can no longer sign in. Their audit history is kept.`, confirmLabel: 'Delete', typeToConfirm: u.username })) || !data) return;
        const previous = data;
        setData({ ...data, rows: data.rows.filter((x) => x.id !== u.id), total: data.total - 1 });
        try {
            await del(`/api/users/${u.id}`);
            toast(`${u.username} deleted.`);
        } catch (e) {
            setData(previous);
            toast((e as ApiError).message, 'danger');
        }
    };
    const removeRole = async (r: Role) => {
        if (!(await ask({ title: `Delete role ${r.name}?`, message: 'Only a role nobody has can be deleted.', confirmLabel: 'Delete role' }))) return;
        try {
            await del(`/api/roles/${r.id}`);
            void roles.reload();
        } catch (e) {
            toast((e as ApiError).message, 'danger');
        }
    };

    if (!data) return <Empty>Loading…</Empty>;
    const resellerNames = Object.fromEntries((data.resellers ?? []).map((r) => [r.id, r.username]));
    return (
        <>
            <Sheet
                title={reseller ? 'My customers' : 'Workspace users'}
                icon="clients"
                className="settings-users-card"
                meta={<>
                    <Badge tone={data.summary.enabled > 0 ? 'success' : 'warning'}>{data.summary.enabled}/{data.summary.total} enabled</Badge>
                    <button type="button" className="primary" onClick={() => setDialog('new')} disabled={!roles.data}><Icon name="plus" />{reseller ? 'New customer' : 'New user'}</button>
                </>}
            >
                {reseller && <p className="hint panel-text">Customers manage the records of the zones you give them, and nothing else. You can give them only your own zones.</p>}
                <DataTable
                    rows={data.rows}
                    rowKey={(r) => r.id}
                    serverPaginated
                    exportRows
                    emptyText={reseller ? 'No customers yet.' : 'No users.'}
                    columns={[
                        { header: 'Name', cell: (r) => <div className="list-cell-stack"><span>{r.name || r.username}</span><span className="list-subline">{r.email}</span></div> },
                        { header: 'Username', cell: (r) => r.username },
                        { header: 'Role', cell: (r) => <div className="list-cell-stack"><Badge>{r.role}</Badge>{r.parent_id && resellerNames[r.parent_id] && <span className="list-subline">of {resellerNames[r.parent_id]}</span>}</div> },
                        { header: 'Zones', cell: (r) => (r.zone_scope === 'all' ? 'all' : (
                            <div className="list-cell-stack">
                                <span>{r.zones ?? 0}{r.max_zones != null ? ` of ${r.max_zones}` : ''}</span>
                                {(r.max_records != null || r.api_rate != null) && <span className="list-subline">{[r.max_records != null && `${r.max_records} records/zone`, r.api_rate != null && `${r.api_rate} req/min`].filter(Boolean).join(', ')}</span>}
                            </div>
                        )) },
                        { header: 'Status', cell: (r) => (r.locked ? <Badge tone="warning">locked out</Badge> : r.enabled ? <Badge tone="success">enabled</Badge> : <Badge tone="danger">disabled</Badge>) },
                        { header: 'Sign-in', cell: (r) => (r.auth_source === 'local' ? <>password {r.two_factor_enabled ? <Badge tone="success">2FA</Badge> : null}</> : <>single sign-on {r.sso_linked ? null : <Badge tone="info">invited</Badge>}</>) },
                        { header: 'Last login', cell: (r) => r.last_login_at ?? '-' },
                        {
                            header: 'Actions',
                            noExport: true,
                            cell: (r) => (
                                <>
                                    <button type="button" className="link" onClick={() => setDialog(r)}>Edit</button>{' '}
                                    {r.self ? <span className="muted-action">You</span> : <button type="button" className="link danger-text" onClick={() => void remove(r)}>Delete</button>}
                                </>
                            ),
                        },
                    ]}
                />
                {data.pages > 1 && <Pagination result={data} path={reseller ? '/customers' : '/settings'} query={reseller ? {} : { tab: 'users' }} noun="users" />}
            </Sheet>
            {!reseller && roles.data && (
                <Sheet title="Roles" icon="lock" meta={<button type="button" onClick={() => setRoleDialog('new')}><Icon name="plus" />New role</button>}>
                    <DataTable
                        rows={roles.data.roles}
                        rowKey={(r) => r.id}
                        columns={[
                            { header: 'Role', cell: (r) => <div className="list-cell-stack"><span>{r.name} {r.built_in && <Badge>built-in</Badge>}</span><span className="list-subline">{r.description}</span></div> },
                            { header: 'Zones', cell: (r) => (r.zone_scope === 'all' ? 'every zone' : 'own zones only') },
                            { header: 'Permissions', cell: (r) => <span className="list-subline">{r.permissions.join(', ')}</span> },
                            { header: 'Users', cell: (r) => r.users },
                            { header: 'Actions', noExport: true, cell: (r) => (
                                <>
                                    <button type="button" className="link" onClick={() => setRoleDialog(r)}>{r.built_in ? 'View' : 'Edit'}</button>{' '}
                                    {!r.built_in && <button type="button" className="link danger-text" onClick={() => void removeRole(r)}>Delete</button>}
                                </>
                            ) },
                        ]}
                    />
                </Sheet>
            )}
            {dialog !== null && roles.data && (
                <UserDialog user={dialog} roles={roles.data.roles} reseller={reseller} resellers={data.resellers ?? []} onClose={() => setDialog(null)} onSaved={() => void reload()} />
            )}
            {roleDialog !== null && roles.data && <RoleDialog role={roleDialog} roles={roles.data} onClose={() => setRoleDialog(null)} onSaved={() => void roles.reload()} />}
        </>
    );
}
