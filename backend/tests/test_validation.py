from datetime import date

import pytest

from dnsone import validation as v
from dnsone.models import Record, Zone
from dnsone.rpz import parse_blocklist
from dnsone.zonegen import _txt_rdata, next_serial, render_zone

Z = "example.com"


def err(fn, *args):
    with pytest.raises(v.ValidationError) as exc:
        fn(*args)
    return exc.value


def test_zone_names():
    assert v.zone_name("Example.COM.") == "example.com"
    assert v.zone_name("2.0.192.in-addr.arpa") == "2.0.192.in-addr.arpa"
    assert v.zone_name("bücher.de") == "xn--bcher-kva.de"
    assert err(v.zone_name, "localhost").field == "name"
    assert err(v.zone_name, "bad..name.com")
    assert err(v.zone_name, "-bad.com")
    assert err(v.zone_name, "a" * 64 + ".com")


def test_owner_names():
    assert v.owner_name("", Z) == "@"
    assert v.owner_name("example.com.", Z) == "@"
    assert v.owner_name("www.example.com.", Z) == "www"
    assert v.owner_name("www.example.com", Z) == "www"
    assert v.owner_name("WWW", Z) == "www"
    assert v.owner_name("*.dev", Z) == "*.dev"
    assert v.owner_name("_dmarc", Z) == "_dmarc"
    assert "outside" in err(v.owner_name, "www.other.org.", Z).message
    assert err(v.owner_name, "a.*.b", Z)


def test_targets():
    assert v.absolute_name("@", Z, "value") == "example.com."
    assert v.absolute_name("mail", Z, "value") == "mail.example.com."
    assert v.absolute_name("mail.example.net", Z, "value") == "mail.example.net."
    assert v.absolute_name("mail.example.net.", Z, "value") == "mail.example.net."


def test_records():
    assert v.record(Z, "www", "a", "192.0.2.1", None) == ("www", "A", "192.0.2.1", None)
    assert v.record(Z, "@", "AAAA", "2001:DB8:0:0::1", None)[2] == "2001:db8::1"
    assert err(v.record, Z, "www", "A", "192.0.2.300", None).field == "value"
    assert err(v.record, Z, "www", "A", "2001:db8::1", None).field == "value"
    # BIND check-names: A records need host-name owners.
    assert err(v.record, Z, "_x", "A", "192.0.2.1", None).field == "name"
    assert v.record(Z, "@", "MX", "mail", 10) == ("@", "MX", "mail.example.com.", 10)
    assert err(v.record, Z, "@", "MX", "mail", None).field == "priority"
    assert v.record(Z, "@", "MX", ".", 0)[2] == "."
    assert err(v.record, Z, "@", "MX", ".", 10).field == "priority"
    assert v.record(Z, "_sip._tcp", "SRV", "5 5060 sip", 10) == ("_sip._tcp", "SRV", "5 5060 sip.example.com.", 10)
    assert err(v.record, Z, "sip", "SRV", "5 5060 sip", 10).field == "name"
    assert err(v.record, Z, "_sip._tcp", "SRV", "5 99999 sip", 10).field == "value"
    assert v.record(Z, "@", "CAA", '0 ISSUE "letsencrypt.org"', None)[2] == '0 issue "letsencrypt.org"'
    assert v.record(Z, "@", "CAA", "0 issue letsencrypt.org", None)[2] == '0 issue "letsencrypt.org"'
    assert err(v.record, Z, "@", "CAA", "300 issue x", None).field == "value"
    assert v.record(Z, "@", "TXT", '"v=spf1 -all"', None)[2] == "v=spf1 -all"
    assert err(v.record, Z, "@", "TXT", "a\nb", None).field == "value"
    assert err(v.record, Z, "@", "TXT", "x" * 4001, None)
    assert err(v.record, Z, "www", "LOC", "x", None).field == "type"


def test_cname_rules():
    assert "apex" in err(v.record, Z, "@", "CNAME", "other.net", None).message
    assert err(v.record, Z, "www", "CNAME", "www", None).message.startswith("A CNAME cannot point to itself")
    assert v.record(Z, "www", "CNAME", "@", None)[2] == "example.com."


def test_ttl_and_rpz():
    assert v.ttl(None) is None
    assert v.ttl(300) == 300
    assert err(v.ttl, 59).field == "ttl"
    assert err(v.ttl, 604801)
    assert v.rpz_pattern("Ads.Example.com.") == "ads.example.com"
    assert v.rpz_pattern("*.doubleclick.net") == "*.doubleclick.net"
    assert err(v.rpz_pattern, "localhost")
    assert v.walled_garden_target("192.0.2.80") == "192.0.2.80"
    assert v.walled_garden_target("blocked.example.net.") == "blocked.example.net"
    assert v.mailbox("hostmaster@example.com", Z) == "hostmaster.example.com."
    assert err(v.mailbox, "first.last@example.com", Z).field == "soa_rname"


def test_serial():
    today = date(2026, 10, 22)
    assert next_serial(0, today) == 2026102200
    assert next_serial(2026102200, today) == 2026102201
    assert next_serial(2026102199, today) == 2026102200
    assert next_serial(2026102399, today) == 2026102400


def test_txt_rendering():
    assert _txt_rdata('say "hi" \\ ok') == '"say \\"hi\\" \\\\ ok"'
    long = _txt_rdata("a" * 300)
    assert long == '"' + "a" * 255 + '" "' + "a" * 45 + '"'
    assert _txt_rdata("é") == '"\\195\\169"'


def test_render_zone():
    zone = Zone(name=Z, default_ttl=3600, soa_mname="ns1.example.com.", soa_rname="hostmaster.example.com.", soa_refresh=7200,
                soa_retry=1800, soa_expire=1209600, soa_minimum=300, revision=3)
    records = [
        Record(name="www", type="A", value="192.0.2.1", ttl=300, priority=None, disabled=False),
        Record(name="@", type="NS", value="ns1.example.com.", ttl=None, priority=None, disabled=False),
        Record(name="@", type="MX", value="mail.example.com.", ttl=None, priority=10, disabled=False),
        Record(name="old", type="A", value="192.0.2.9", ttl=None, priority=None, disabled=True),
    ]
    text = render_zone(zone, records, 2026102201)
    assert "$ORIGIN example.com." in text
    assert "2026102201\t; serial" in text
    assert "www\t300\tIN\tA\t192.0.2.1" in text
    assert "@\t\tIN\tMX\t10 mail.example.com." in text
    assert "192.0.2.9" not in text
    assert text.index("IN\tNS") < text.index("IN\tMX") < text.index("www")


def test_parse_blocklist():
    text = """# comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net  other.example.org # inline
0.0.0.0 localhost
::1 ip6-localhost
plain.example.com
||adblock.example.com^
||complex.example.com^$script
not a domain line
bad_tld.example.123
ADS.EXAMPLE.COM
"""
    assert parse_blocklist(text) == {"ads.example.com", "tracker.example.net", "other.example.org", "plain.example.com", "adblock.example.com"}
    assert parse_blocklist(text, "hosts") == {"ads.example.com", "tracker.example.net", "other.example.org"}
    assert parse_blocklist(text, "adblock") == {"adblock.example.com"}
    # A whole TLD only from an AdBlock line (||casino^): a lone word elsewhere is not taken for one.
    tlds = "||casino^\n||xn--6frz82g^\n||co.com^\n||c^\n||123^\ncasino2\n0.0.0.0 bingo\n"
    assert parse_blocklist(tlds) == {"casino", "xn--6frz82g", "co.com"}


def test_regex_pattern():
    assert v.regex_pattern(r" ^ads?[0-9]*\.example\.com$ ") == r"^ads?[0-9]*\.example\.com$"
    for bad in (r"^ads\d+", r"(?i)ads", r"ads.*?", r"(a)\1", "", "x" * 254, "é", ".*", "(", "[a-"):
        with pytest.raises(v.ValidationError):
            v.regex_pattern(bad)


def test_network():
    assert v.network("192.0.2.7") == "192.0.2.7/32"
    assert v.network("192.0.2.77/24") == "192.0.2.0/24"
    assert v.network("2001:DB8::1/48") == "2001:db8::/48"
    with pytest.raises(v.ValidationError):
        v.network("192.0.2.0/33")


def test_totp_and_policy_lua():
    import base64

    from dnsone import runtime, security
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert security.totp_code(secret, 59 // 30) == "287082"  # RFC 6238, truncated to 6 digits
    step = security.totp_match(secret, security.totp_code(secret, 1000), None, now=1000 * 30 + 5)
    assert step == 1000 and security.totp_match(secret, security.totp_code(secret, 1000), 1000, now=1000 * 30 + 5) is None
    assert runtime.lua({"a": [1, "x\"y"], 3: None, 4: True}) == '{\n  ["a"] = {\n    1,\n    "x\\"y",\n  },\n  [4] = true,\n}'


def test_structured_records():
    ds = v.record(Z, "customer", "DS", "12345 13 2 " + "AB" * 32, None)
    assert ds == ("customer", "DS", "12345 13 2 " + "ab" * 32, None)
    assert err(v.record, Z, "@", "DS", "12345 13 2 " + "ab" * 32, None).field == "name"
    assert err(v.record, Z, "customer", "DS", "12345 13 2 abcd", None).field == "value"
    assert v.record(Z, "_443._tcp.www", "TLSA", "3 1 1 " + "cd" * 32, None)[2] == "3 1 1 " + "cd" * 32
    assert err(v.record, Z, "www", "TLSA", "3 1 1 " + "cd" * 32, None).field == "name"
    assert err(v.record, Z, "_443._tcp", "TLSA", "3 1 1 abcd", None).field == "value"
    assert v.record(Z, "host", "SSHFP", "4 2 " + "ef" * 32, None)[2] == "4 2 " + "ef" * 32
    assert err(v.record, Z, "host", "SSHFP", "4 2 abcd", None).field == "value"
    naptr = v.record(Z, "@", "NAPTR", '100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .', None)
    assert naptr[2] == '100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .'
    assert v.record(Z, "@", "NAPTR", '10 0 "s" "SIP+D2U" "" _sip._udp.example.com', None)[2] == '10 0 "s" "SIP+D2U" "" _sip._udp.example.com.'
    assert err(v.record, Z, "@", "NAPTR", '10 0 "u" "E2U+sip" "!a!b!" sip', None).field == "value"
    assert v.record(Z, "@", "HTTPS", "1 . alpn=h2,h3", None)[2] == '1 . alpn="h2,h3"'
    assert v.record(Z, "@", "HTTPS", "1 www", None)[2] == "1 www.example.com."
    assert v.record(Z, "_dns", "SVCB", "1 svc.example.net alpn=h2", None)[2] == '1 svc.example.net. alpn="h2"'
    assert "priority target" in err(v.record, Z, "@", "HTTPS", "junk", None).message


def test_regex_rules_refuse_nested_repetition():
    for bad in ("^([a-z]+)+[0-9]$", "(a*)*b", "^(ab{1,})+$"):
        with pytest.raises(v.ValidationError):
            v.regex_pattern(bad)
    assert v.regex_pattern("^ads?[0-9]*\\.") == "^ads?[0-9]*\\."
    assert v.regex_pattern("(^|\\.)doubleclick\\.net$")


def test_zone_import_counts_generate_ranges_first():
    from dnsone import zoneio
    with pytest.raises(v.ValidationError):
        zoneio.parse_text("$GENERATE 1-100000000 h$ A 192.0.2.1\n", "example.com")
    with pytest.raises(v.ValidationError):
        zoneio.fetch_axfr("example.com", "127.0.0.1", 5301)


def test_addresses_never_carry_an_ipv6_scope_id():
    # Python keeps "%<anything>" in str(); these values are written into nftables, BIND and dnsdist configuration.
    for bad in ('fe80::1%x }\n}\ninclude "passwd"\n#', "fe80::1%eth0"):
        with pytest.raises(v.ValidationError):
            v.network(bad)
        with pytest.raises(ValueError):
            v.plain_ip(bad)
    assert v.network("2001:db8::1") == "2001:db8::1/128"
