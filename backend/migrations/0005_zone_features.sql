-- DNSOne schema, version 0005: more record types and DNSSEC signing for hosted zones.

-- DS (delegations to signed child zones), TLSA (DANE), SSHFP, NAPTR (VoIP/ENUM), HTTPS and SVCB.
-- Their RDATA is stored whole in `value`, in the canonical text form dnspython writes.
ALTER TABLE records
    MODIFY COLUMN type ENUM('A','AAAA','CNAME','MX','TXT','NS','SRV','CAA','PTR','DS','TLSA','SSHFP','NAPTR','HTTPS','SVCB') NOT NULL;

-- off: not signed. on: BIND signs the zone (dnssec-policy "dnsone", inline signing).
-- insecure: was signed; BIND removes the signatures and keys safely (dnssec-policy insecure) and the
-- zone stays in this state, which serves it unsigned, until signing is turned on again.
ALTER TABLE zones
    ADD COLUMN dnssec ENUM('off','on','insecure') NOT NULL DEFAULT 'off' AFTER status;
