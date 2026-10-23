import { router } from '@inertiajs/react';
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';

export interface ConfirmOptions {
    /** Body text: what will happen. */
    message: string;
    title?: string;
    confirmLabel?: string;
    /** Wide-impact actions: the operator types this exact text before Confirm is enabled. */
    typeToConfirm?: string;
}

type Ask = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<Ask>(async (options) => window.confirm(options.message));

/** Confirmation dialog (legacy .confirm-dialog): names the action, optionally requires typing a phrase. */
export function ConfirmProvider({ children }: { children: ReactNode }) {
    const dialog = useRef<HTMLDialogElement>(null);
    const resolver = useRef<((ok: boolean) => void) | null>(null);
    const opener = useRef<Element | null>(null);
    const [options, setOptions] = useState<ConfirmOptions | null>(null);
    const [typed, setTyped] = useState('');

    const ask = useCallback<Ask>((next) => new Promise((resolve) => {
        opener.current = document.activeElement;
        resolver.current = resolve;
        setTyped('');
        setOptions(next);
        requestAnimationFrame(() => {
            dialog.current?.showModal();
            dialog.current?.querySelector<HTMLElement>(next.typeToConfirm ? 'input' : '[value="cancel"]')?.focus();
        });
    }), []);

    const phrase = options?.typeToConfirm ?? '';
    const blocked = phrase !== '' && typed.trim() !== phrase;

    return (
        <ConfirmContext.Provider value={ask}>
            {children}
            <dialog
                ref={dialog}
                className="confirm-dialog"
                aria-labelledby="confirm-dialog-title"
                aria-describedby="confirm-dialog-body"
                onClose={() => {
                    const ok = dialog.current?.returnValue === 'confirm';
                    if (dialog.current) dialog.current.returnValue = '';
                    const done = resolver.current;
                    resolver.current = null;
                    if (!ok && opener.current instanceof HTMLElement && opener.current.isConnected) opener.current.focus();
                    done?.(ok);
                }}
            >
                <form method="dialog">
                    <h2 id="confirm-dialog-title">{options?.title ?? 'Are you sure?'}</h2>
                    <p id="confirm-dialog-body">{options?.message}</p>
                    {phrase !== '' && (
                        <label className="confirm-type">
                            <span>Type <code>{phrase}</code> to confirm</span>
                            <input
                                type="text"
                                autoComplete="off"
                                autoCapitalize="off"
                                spellCheck={false}
                                value={typed}
                                onChange={(event) => setTyped(event.target.value)}
                                onKeyDown={(event) => {
                                    if (event.key !== 'Enter') return;
                                    event.preventDefault(); // implicit submit would pick Cancel first
                                    if (!blocked) dialog.current?.close('confirm');
                                }}
                            />
                        </label>
                    )}
                    <div className="form-actions">
                        <button type="submit" value="cancel">Cancel</button>
                        <button type="submit" value="confirm" className="danger" disabled={blocked}>{options?.confirmLabel ?? 'Confirm'}</button>
                    </div>
                </form>
            </dialog>
        </ConfirmContext.Provider>
    );
}

export function useConfirm(): Ask {
    return useContext(ConfirmContext);
}

type PostProps = {
    action: string;
    label: ReactNode;
    data?: Record<string, unknown>;
    confirm?: ConfirmOptions | string;
    className?: string;
    disabled?: boolean;
    preserveScroll?: boolean;
    title?: string;
};

/** A button that POSTs (with CSRF via Inertia) after an optional confirmation. */
export function PostButton({ action, label, data = {}, confirm, className = 'link danger-text', disabled, preserveScroll = true, title }: PostProps) {
    const ask = useConfirm();
    const [busy, setBusy] = useState(false);
    return (
        <button
            type="button"
            className={className}
            disabled={disabled || busy}
            title={title}
            onClick={async () => {
                if (confirm) {
                    const options = typeof confirm === 'string' ? { message: confirm } : confirm;
                    if (!(await ask(options))) return;
                }
                router.post(action, data as never, {
                    preserveScroll,
                    onStart: () => setBusy(true),
                    onFinish: () => setBusy(false),
                });
            }}
        >
            {label}
        </button>
    );
}

/** Legacy deleteButton(): a guarded destructive POST. */
export function DeleteButton({ action, label = 'Delete', message = 'This action cannot be undone.', typeToConfirm, title }: { action: string; label?: string; message?: string; typeToConfirm?: string; title?: string }) {
    return (
        <PostButton
            action={action}
            label={label}
            confirm={{ message, title: title ?? `${label}?`, confirmLabel: label, typeToConfirm }}
        />
    );
}

/** Plain-browser download link for routes that stream files (CSV, PDF). */
export function DownloadLink({ href, children, className = 'button' }: { href: string; children: ReactNode; className?: string }) {
    return <a className={className} href={href} download>{children}</a>;
}
