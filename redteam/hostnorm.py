"""Host normalization shared by scope checks and config loading.

Single source of truth so an allowlist entry and a runtime target are
compared in the same canonical form:

- case folding
- trailing-dot stripping (FQDN 'example.com.' == 'example.com' in DNS)
- IDN → punycode (so 'münchen.example' and 'xn--mnchen-3ya.example' match)
"""


def normalize_host(host: str) -> str:
    h = host.strip().rstrip(".").lower()
    if not h:
        raise ValueError("empty host")
    if any(ord(c) > 127 for c in h):
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            pass  # leave as-is; comparison will simply not match anything
    return h


def normalize_domain_list(domains: list[str]) -> list[str]:
    out = []
    for d in domains:
        try:
            out.append(normalize_host(str(d)))
        except ValueError:
            out.append(str(d).strip().lower())
    return out
