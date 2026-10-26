// DNSOne Pro or Community. The Pro screens are in src/pro/; DNSOne Community has no such folder
// (tools/export-community.sh leaves it out), so the console shows exactly the features the build has.
import type { ComponentType } from 'react';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const screens = import.meta.glob('../pro/*.tsx', { eager: true }) as Record<string, Record<string, any>>;

/** A Pro screen's export (`default` or a named one), or undefined in DNSOne Community. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function proScreen<T = ComponentType<any>>(file: string, name = 'default'): T | undefined {
    return screens[`../pro/${file}.tsx`]?.[name] as T | undefined;
}

const has = (file: string) => `../pro/${file}.tsx` in screens;

/** The Pro features this build has (the same names as the server's edition.features()). */
export const FEATURES = {
    protection: has('Protection'),
    legal: has('Legal'),
    quota: has('Customers'),
    firewall: has('FirewallTab'),
    logexport: has('MoreTabs'),
    oidc: has('MoreTabs'),
    cluster: has('ClusterTab'),
    transfers: has('Transfers'),
};

export const EDITION = Object.values(FEATURES).every(Boolean) ? 'Pro' : 'Community';
