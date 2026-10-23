import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';

type Tone = 'success' | 'danger' | 'warning' | 'info';
type Toast = { id: number; tone: Tone; message: string };
type Notify = (message: string, tone?: Tone) => void;

const ToastContext = createContext<Notify>(() => undefined);

/** Toasts: RadiusOne flash messages in a corner; success fades after 4 s, errors stay until closed. */
export function ToastProvider({ children }: { children: ReactNode }) {
    const [toasts, setToasts] = useState<Toast[]>([]);
    const next = useRef(1);
    const close = useCallback((id: number) => setToasts((all) => all.filter((t) => t.id !== id)), []);
    const notify = useCallback<Notify>((message, tone = 'success') => {
        const id = next.current++;
        setToasts((all) => [...all.slice(-3), { id, tone, message }]);
        if (tone === 'success' || tone === 'info') window.setTimeout(() => close(id), 4000);
    }, [close]);
    return (
        <ToastContext.Provider value={notify}>
            {children}
            <div className="toast-region" role="status" aria-live="polite">
                {toasts.map((t) => (
                    <div key={t.id} className={`flash ${t.tone}`}>
                        <span>{t.message}</span>
                        <button type="button" aria-label="Dismiss" onClick={() => close(t.id)}>×</button>
                    </div>
                ))}
            </div>
        </ToastContext.Provider>
    );
}

export function useToast(): Notify {
    return useContext(ToastContext);
}

/** A form in a modal dialog, framed like RadiusOne's confirm dialog. */
export function FormDialog({ open, title, onClose, onSubmit, submitLabel, busy, children }: {
    open: boolean;
    title: string;
    onClose: () => void;
    onSubmit: (event: FormEvent<HTMLFormElement>) => void;
    submitLabel: string;
    busy?: boolean;
    children: ReactNode;
}) {
    const dialog = useRef<HTMLDialogElement>(null);
    useEffect(() => {
        const node = dialog.current;
        if (!node) return;
        if (open && !node.open) {
            node.showModal();
            node.querySelector<HTMLElement>('input, select, textarea')?.focus();
        }
        if (!open && node.open) node.close();
    }, [open]);
    return (
        <dialog ref={dialog} className="confirm-dialog form-dialog" aria-labelledby="form-dialog-title" onClose={onClose} onCancel={onClose}>
            <form
                onSubmit={(event) => {
                    event.preventDefault();
                    onSubmit(event);
                }}
            >
                <h2 id="form-dialog-title">{title}</h2>
                {children}
                <div className="form-actions">
                    <button type="button" onClick={onClose}>Cancel</button>
                    <button type="submit" className="primary" disabled={busy}>{submitLabel}</button>
                </div>
            </form>
        </dialog>
    );
}
