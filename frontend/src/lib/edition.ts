// DNSOne Pro features, from this server's licence (/api/auth/me, Settings → License). The Pro screens are in
// src/pro/; the console shows a feature's pages, tabs and fields only while the licence has it.
import type { ComponentType } from 'react';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const screens = import.meta.glob('../pro/*.tsx', { eager: true }) as Record<string, Record<string, any>>;

/** A Pro screen's export (`default` or a named one). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function proScreen<T = ComponentType<any>>(file: string, name = 'default'): T | undefined {
    return screens[`../pro/${file}.tsx`]?.[name] as T | undefined;
}

// edition: 'community' for the free DNSOne Community licence (no Pro feature), 'pro' for a paid one.
export type License = { state: 'none' | 'valid' | 'expired'; customer: string | null; expires: string | null; days_left?: number | null; edition?: 'community' | 'pro' | null };

/**
 * Whether this server is registered with a PingOmni licence, the free Community one at least (the server's registration.py).
 * In its grace the console shows a banner; locked, only the "Register this server" screen.
 */
export type Registration = {
    state: 'registered' | 'grace' | 'locked'; url: string; edition?: string | null;
    reason?: 'none' | 'invalid' | 'expired'; days_left?: number; grace_ends?: string;
};

let features: string[] = [];
let license: License = { state: 'none', customer: null, expires: null };
let registration: Registration = { state: 'registered', url: '' };

/** Set from /api/auth/me at sign-in, before the console renders. */
export function setEdition(me: { features?: string[]; license?: License; registration?: Registration }) {
    features = me.features ?? [];
    license = me.license ?? license;
    registration = me.registration ?? registration;
}

export const currentRegistration = () => registration;

/** What a licence is called in the console: the free key is "DNSOne Community (registered)". */
export const editionLabel = (edition?: string | null) => (edition === 'community' ? 'DNSOne Community' : 'DNSOne Pro');

/** Is a Pro feature on (the same names as the server's licence: protection, legal, quota, firewall, …)? */
export const has = (feature: string) => features.includes(feature);

export const currentLicense = () => license;
