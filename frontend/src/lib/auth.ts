import { usePage } from '@inertiajs/react';
import type { SharedProps } from './types';

/** Permission check against the role matrix the server shared (App\Support\Auth::permissions). */
export function useCan(): (permission: string) => boolean {
    const { auth } = usePage<SharedProps>().props;
    return (permission) => auth.permissions.includes(permission);
}

export function useShared(): SharedProps {
    return usePage<SharedProps>().props;
}
