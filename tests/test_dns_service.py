from services.dns_service import DnsService

def test_service_init():
    s = DnsService(timeout=1.0)
    assert s.timeout == 1.0

def test_all_returns_dict():
    s = DnsService(timeout=1.0)
    r = s.all("this-domain-should-not-exist-webguard.example")
    assert isinstance(r, dict)
    for k in ("A", "AAAA", "MX", "NS", "TXT"):
        assert k in r
