// SPDX-License-Identifier: Elastic-2.0
// DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
// Resellers: their own customer accounts (Settings → Users for administrators).
import AppLayout from '@/layouts/AppLayout';
import { UsersTab } from '@/pages/settings/UsersTab';

export default function Customers() {
    return (
        <AppLayout title="Customers">
            <div className="settings-menu-body"><UsersTab reseller /></div>
        </AppLayout>
    );
}
