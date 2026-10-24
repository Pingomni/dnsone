"""Safe Search per client group: the search engines' own enforcement names, as RPZ CNAME rewrites.

Google, Bing and DuckDuckGo publish a host that always serves filtered results; pointing their search
names at it (a CNAME in the group's Safe Search RPZ zone) turns Safe Search on for every client of the
group, whatever the browser's setting. YouTube's restricted mode works the same way, in two levels.
The Recursor resolves the target and answers with the CNAME and its addresses.
"""

from __future__ import annotations

# Every country domain Google search answers on (https://www.google.com/supported_domains).
GOOGLE_DOMAINS = """
google.com google.ad google.ae google.com.af google.com.ag google.al google.am google.co.ao google.com.ar google.as
google.at google.com.au google.az google.ba google.com.bd google.be google.bf google.bg google.com.bh google.bi google.bj
google.com.bn google.com.bo google.com.br google.bs google.bt google.co.bw google.by google.com.bz google.ca google.cd
google.cf google.cg google.ch google.ci google.co.ck google.cl google.cm google.cn google.com.co google.co.cr google.com.cu
google.cv google.com.cy google.cz google.de google.dj google.dk google.dm google.com.do google.dz google.com.ec google.ee
google.com.eg google.es google.com.et google.fi google.com.fj google.fm google.fr google.ga google.ge google.gg google.com.gh
google.com.gi google.gl google.gm google.gr google.com.gt google.gy google.com.hk google.hn google.hr google.ht google.hu
google.co.id google.ie google.co.il google.im google.co.in google.iq google.is google.it google.je google.com.jm google.jo
google.co.jp google.co.ke google.com.kh google.ki google.kg google.co.kr google.com.kw google.kz google.la google.com.lb
google.li google.lk google.co.ls google.lt google.lu google.lv google.com.ly google.co.ma google.md google.me google.mg
google.mk google.ml google.com.mm google.mn google.com.mt google.mu google.mv google.mw google.com.mx google.com.my
google.co.mz google.com.na google.com.ng google.com.ni google.ne google.nl google.no google.com.np google.nr google.nu
google.co.nz google.com.om google.com.pa google.com.pe google.com.pg google.com.ph google.com.pk google.pl google.pn
google.com.pr google.ps google.pt google.com.py google.com.qa google.ro google.ru google.rw google.com.sa google.com.sb
google.sc google.se google.com.sg google.sh google.si google.sk google.com.sl google.sn google.so google.sm google.sr
google.st google.com.sv google.td google.tg google.co.th google.com.tj google.tl google.tm google.tn google.to google.com.tr
google.tt google.com.tw google.co.tz google.com.ua google.co.ug google.co.uk google.com.uy google.co.uz google.com.vc
google.co.ve google.co.vi google.com.vn google.vu google.ws google.rs google.co.za google.co.zm google.co.zw google.cat
""".split()

GOOGLE_TARGET = "forcesafesearch.google.com"
BING = (["bing.com", "www.bing.com"], "strict.bing.com")
DUCKDUCKGO = (["duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com"], "safe.duckduckgo.com")
YOUTUBE_NAMES = ["www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com", "www.youtube-nocookie.com"]
YOUTUBE_TARGETS = {"strict": "restrict.youtube.com", "moderate": "restrictmoderate.youtube.com"}
YOUTUBE_LEVELS = ("off", "moderate", "strict")


def rewrites(search: bool, youtube: str) -> dict[str, str]:
    """name -> CNAME target for a group's settings."""
    out: dict[str, str] = {}
    if search:
        for domain in GOOGLE_DOMAINS:
            out[domain] = out[f"www.{domain}"] = GOOGLE_TARGET
        for names, target in (BING, DUCKDUCKGO):
            for name in names:
                out[name] = target
    if youtube in YOUTUBE_TARGETS:
        for name in YOUTUBE_NAMES:
            out[name] = YOUTUBE_TARGETS[youtube]
    return out
