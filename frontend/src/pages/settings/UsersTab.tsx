import { usePage } from '@inertiajs/react';
import { useState } from 'react';
import { useConfirm } from '@/components/confirm';
import { FormDialog, useToast } from '@/components/dns/feedback';
import Icon from '@/components/Icon';
import { DataTable, Pagination } from '@/components/table';
import { RoleGrid, Sheet } from '@/components/settings';
import { Badge, Check, Empty, Field, Select } from '@/components/ui';
import { ApiError, del, patch, post, searchOf, useApi } from '@/lib/api';
import { query, randomPassword } from '@/lib/format';
import type { Paginated } from '@/lib/types';

type Operator = { id: number; username: string; name: string; email: string; role: string; role_id: number; enabled: boolean; auth_source: string; last_login_at: string | null; locked: boolean; self: boolean; two_factor_enabled: boolean };
type Role = { id: number; name: string; description: string; permissions: string[]; built_in: boolean; users: number };
type Roles = { roles: Role[]; permissions: Record<string, string> };

function UserDialog({ user, roles, onClose, onSaved }: { user: Operator | 'new' | null; roles: Role[]; onClose: () => void; onSaved: () => void }) {
    const toast = useToast();
    const editing = user && user !== 'new' ? user : null;
    const [form, setForm] = useState({ username: editing?.username ?? '', name: editing?.name ?? '', email: editing?.email ?? '', role_id: String(editing?.role_id ?? roles.find((r) => r.name === 'operator')?.id ?? ''), password: '', enabled: editing?.enabled ?? true, reset_two_factor: false });
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    return (
        <FormDialog open={user !== null} title={editing ? `Edit ${editing.username}` : 'New user'} submitLabel={editing ? 'Save user' : 'Create user'} busy={busy} onClose={onClose} onSubmit={async () => {
            setBusy(true);
            try {
                const payload = { ...form, role_id: Number(form.role_id) };
                if (editing) {
                    const { username: _u, ...changes } = payload;
                    await patch(`/api/users/${editing.id}`, { ...changes, password: form.password || null });
                } else {
                    await post('/api/users', payload);
                }
                toast(editing ? `${form.username} saved.` : `${form.username} created.`);
                onSaved();
                onClose();
            } catch (e) {
                const ae = e as ApiError;
                setErrors(Object.keys(ae.errors).length ? ae.errors : { username: ae.message });
            } finally {
                setBusy(false);
            }
        }}>
            <div className="form-grid">
                <Field label="Username" name="username" required disabled={Boolean(editing)} autoComplete="off" value={form.username} error={errors.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
                <Select label="Role" name="role_id" options={roles.map((r) => ({ value: String(r.id), label: r.name }))} value={form.role_id} error={errors.role_id} onChange={(e) => setForm({ ...form, role_id: e.target.value })} />
                <Field label="Full name" name="name" value={form.name} error={errors.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Field label="Email" name="email" type="email" value={form.email} error={errors.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
                <Field
                    label={editing ? 'New password' : 'Password'}
                    name="password"
                    className="span2"
                    required={!editing}
                    autoComplete="new-password"
                    hint={editing ? 'Leave empty to keep it. Setting one signs the user out everywhere.' : 'At least 12 characters. Share it securely.'}
                    value={form.password}
                    error={errors.password}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                />
                <div className="span2 inline-actions">
                    <button type="button" onClick={() => setForm({ ...form, password: randomPassword(18) })}>Generate password</button>
                    {!editing?.self && <Check label="Can sign in" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />}
                    {editing?.two_factor_enabled && <Check label="Turn off two-factor sign-in (lost phone)" checked={form.reset_two_factor} onChange={(e) => setForm({ ...form, reset_two_factor: e.target.checked })} />}
                </div>
            </div>
        </FormDialog>
    );
}

export function UsersTab() {
    const ask = useConfirm();
    const toast = useToast();
    const { url } = usePage();
    const params = searchOf(url);
    const { data, setData, reload } = useApi<Paginated<Operator> & { summary: { enabled: number; total: number } }>(`/api/users${query({ page: params.get('page') ?? '' })}`);
    const roles = useApi<Roles>('/api/roles');
    const [dialog, setDialog] = useState<Operator | 'new' | null>(null);

    const remove = async (u: Operator) => {
        if (!(await ask({ title: `Delete operator ${u.username}?`, message: `${u.username} can no longer sign in. Their audit history is kept.`, confirmLabel: 'Delete', typeToConfirm: u.username })) || !data) return;
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

    if (!data) return <Empty>Loading…</Empty>;
    return (
        <>
            <Sheet
                title="Workspace users"
                icon="clients"
                className="settings-users-card"
                meta={<>
                    <Badge tone={data.summary.enabled > 0 ? 'success' : 'warning'}>{data.summary.enabled}/{data.summary.total} enabled</Badge>
                    <button type="button" className="primary" onClick={() => setDialog('new')}><Icon name="plus" />New user</button>
                </>}
            >
                <DataTable
                    rows={data.rows}
                    rowKey={(r) => r.id}
                    serverPaginated
                    exportRows
                    columns={[
                        { header: 'Name', cell: (r) => r.name },
                        { header: 'Email', cell: (r) => r.email },
                        { header: 'Username', cell: (r) => r.username },
                        { header: 'Role', cell: (r) => <Badge>{r.role}</Badge> },
                        { header: 'Status', cell: (r) => (r.locked ? <Badge tone="warning">locked out</Badge> : r.enabled ? <Badge tone="success">enabled</Badge> : <Badge tone="danger">disabled</Badge>) },
                        { header: 'Sign-in', cell: (r) => (r.auth_source === 'local' ? <>password {r.two_factor_enabled ? <Badge tone="success">2FA</Badge> : null}</> : 'single sign-on') },
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
                {data.pages > 1 && <Pagination result={data} path="/settings" query={{ tab: 'users' }} noun="users" />}
            </Sheet>
            {roles.data && (
                <Sheet title="Role access" icon="lock">
                    <RoleGrid
                        roles={roles.data.roles.map((r) => ({
                            role: `${r.name} · ${r.users} ${r.users === 1 ? 'user' : 'users'}`,
                            description: r.description,
                        }))}
                    />
                </Sheet>
            )}
            {dialog !== null && roles.data && <UserDialog user={dialog} roles={roles.data.roles} onClose={() => setDialog(null)} onSaved={() => void reload()} />}
        </>
    );
}
