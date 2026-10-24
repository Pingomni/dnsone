// Resellers: their own customer accounts (Settings → Users for administrators).
import AppLayout from '@/layouts/AppLayout';
import { UsersTab } from './settings/UsersTab';

export default function Customers() {
    return (
        <AppLayout title="Customers">
            <div className="settings-menu-body"><UsersTab reseller /></div>
        </AppLayout>
    );
}
