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

export type License = { state: 'none' | 'valid' | 'expired'; customer: string | null; expires: string | null; days_left?: number | null };

let features: string[] = [];
let license: License = { state: 'none', customer: null, expires: null };

/** Set from /api/auth/me at sign-in, before the console renders. */
export function setEdition(me: { features?: string[]; license?: License }) {
    features = me.features ?? [];
    license = me.license ?? license;
}

/** Is a Pro feature on (the same names as the server's licence: protection, legal, quota, firewall, …)? */
export const has = (feature: string) => features.includes(feature);

export const currentLicense = () => license;
