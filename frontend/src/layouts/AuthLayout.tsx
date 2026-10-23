// RadiusOne's AuthLayout (resources/js/layouts/AuthLayout.tsx) with DNSOne's footnote.
import { Head } from '@inertiajs/react';
import { useEffect, useRef, type FormEvent, type ReactNode } from 'react';
import { FlashMessage } from '@/components/ui';
import { BrandLogo } from '@/layouts/AppLayout';
import type { Flash } from '@/lib/types';

/** Centered sign-in shell: one focused card on a soft backdrop. */
export function AuthLayout({ title, children }: { title: string; children: ReactNode }) {
    return (
        <>
            <Head title={`${title} - DNSOne`} />
            <main className="login">
                <div className="login-shell">
                    {children}
                    <p className="login-footnote">DNSOne &middot; Secure operator access</p>
                </div>
            </main>
        </>
    );
}

/** The card form with brand, heading and flash; focuses the error when sign-in fails. */
export function AuthCard({ heading, lead, flash, onSubmit, children }: { heading: string; lead: string; flash: Flash | null; onSubmit: (event: FormEvent<HTMLFormElement>) => void; children: ReactNode }) {
    const card = useRef<HTMLFormElement>(null);
    useEffect(() => {
        if (flash) card.current?.querySelector<HTMLElement>('[data-feedback-focus]')?.focus();
    }, [flash]);
    return (
        <form method="post" className="login-card" onSubmit={onSubmit} ref={card}>
            <div className="login-card-head">
                <div className="login-brand"><BrandLogo /><strong>DNSOne</strong></div>
                <h1>{heading}</h1>
                <p>{lead}</p>
            </div>
            {flash && <FlashMessage flash={flash} />}
            {children}
        </form>
    );
}
