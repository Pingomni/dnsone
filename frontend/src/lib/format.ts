// Display helpers mirroring app/Http/format.php in the legacy portal.

export function bytes(value: number): string {
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    let n = Math.max(0, Number(value) || 0);
    while (n >= 1024 && i < units.length - 1) {
        n /= 1024;
        i++;
    }
    return `${i === 0 ? n : Math.round(n * 100) / 100} ${units[i]}`;
}

export function seconds(total: number): string {
    const s = Math.max(0, Math.floor(Number(total) || 0));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${String(h).padStart(2, '0')}h ${String(m).padStart(2, '0')}m`;
}

export function money(value: unknown): string {
    return (Number(value) || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

/** Operator wording for an accounting state: online, no recent update, offline, ended. */
export function connectionLabel(state: string): string {
    const labels: Record<string, string> = {
        'fresh accounting': 'online',
        'stale accounting': 'no recent update',
        'no fresh accounting': 'offline',
        closed: 'ended',
    };
    return labels[state] ?? state;
}

export function slugKey(value: string): string {
    return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

/** Query string from an object, skipping empty values. */
export function query(params: Record<string, unknown>): string {
    const search = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
    });
    const text = search.toString();
    return text ? `?${text}` : '';
}

export function randomPassword(length = 16): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
    let password = '';
    crypto.getRandomValues(new Uint32Array(length)).forEach((n) => {
        password += chars[n % chars.length];
    });
    return password;
}
