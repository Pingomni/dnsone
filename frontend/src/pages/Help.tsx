// Help: the user guide moved to pingomni.com/docs/dnsone/ (lib/docs.ts). The sidebar links there; this page only
// sends old bookmarks of /help on.
import { useEffect } from 'react';
import { DOCS_URL } from '@/lib/docs';

export default function Help() {
    useEffect(() => window.location.replace(DOCS_URL), []);
    return (
        <p className="panel-text">
            The DNSOne user guide is on <a href={DOCS_URL}>pingomni.com/docs/dnsone</a>.
        </p>
    );
}
