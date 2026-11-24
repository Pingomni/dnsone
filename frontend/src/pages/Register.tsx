// "Register this server": the whole console once an unregistered server's grace has ended (the server's registration.py).
// Its API then answers only signing in and out and the licence, so this screen is all an operator can use: why, the
// server's ID, where to get the free key, and the same key field as Settings → License. DNS keeps answering throughout.
import { useState } from 'react';
import { FlashMessage } from '@/components/ui';
import { AuthLayout } from '@/layouts/AuthLayout';
import { BrandLogo } from '@/layouts/AppLayout';
import { post, useApi } from '@/lib/api';
import type { Registration } from '@/lib/edition';
import type { Flash } from '@/lib/types';
import { LicenseKeyForm, REGISTER_URL, type License } from '@/pages/settings/LicenseTab';

type Props = {
    registration: Registration;
    /** May this operator install a licence (system.manage)? Others are asked to find an administrator. */
    canManage: boolean;
    /** A key was stored: the console reads its session again, and opens if the server is now registered. */
    onInstalled: () => Promise<Registration>;
};

export default function Register({ registration, canManage, onInstalled }: Props) {
    const renew = registration.reason === 'expired';
    const { data } = useApi<License>(canManage ? '/api/settings/license' : null);
    const [flash, setFlash] = useState<Flash | null>(null);
    const url = registration.url || REGISTER_URL;
    const signOut = () => void post<{ redirect?: string | null }>('/api/auth/logout').then((r) => window.location.assign(r.redirect || '/'), () => window.location.assign('/'));

    const installed = async (lic: License) => {
        const next = await onInstalled().catch(() => registration);
        // Signed by PingOmni but not registering: a key that expired more than 30 days ago.
        if (next.state === 'locked') {
            setFlash({ type: 'warning', message: `This licence expired on ${lic.expires}. Renew your free licence at account.pingomni.com, then paste the new key.` });
        }
    };

    return (
        <AuthLayout title={renew ? 'Renew your licence' : 'Register this server'}>
            <div className="login-card register-card">
                <div className="login-card-head">
                    <div className="login-brand"><BrandLogo /><strong>DNSOne</strong></div>
                    <h1>{renew ? 'Renew your free licence' : 'Register this server'}</h1>
                    <p>{renew ? 'Renew your free licence at account.pingomni.com.' : 'Get a free DNSOne licence at account.pingomni.com.'}</p>
                </div>
                {flash && <FlashMessage flash={flash} />}
                <p className="register-why">
                    {renew
                        ? `This server's licence expired${data?.expires ? ` on ${data.expires}` : ''}, more than 30 days ago. `
                        : `Every DNSOne server, DNSOne Community included, is registered with a licence key from its PingOmni account. This one is not, and its 30 days of grace ended on ${registration.grace_ends ?? 'an earlier day'}. `}
                    The DNSOne Community licence is free, valid for a year and renewed for free. DNS keeps answering exactly as before: only this console waits for the key.
                </p>
                {canManage ? (
                    <>
                        <div className="register-server-id">
                            <span>This server's ID</span>
                            <code>{data?.server_id ?? '…'}</code>
                        </div>
                        <a className="button primary login-submit" href={url} target="_blank" rel="noreferrer">
                            {renew ? 'Renew at account.pingomni.com' : 'Get a free licence at account.pingomni.com'}
                        </a>
                        <LicenseKeyForm replace={false} onInstalled={(lic) => void installed(lic)} />
                    </>
                ) : (
                    <p className="register-why">Ask an administrator of this server to add its licence under Settings → License.</p>
                )}
                <p className="login-help"><button type="button" className="link" onClick={signOut}>Sign out</button></p>
            </div>
        </AuthLayout>
    );
}
