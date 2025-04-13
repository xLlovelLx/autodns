import pytest
from dns_enum.tld_expansion import tld_expand, validate_domains

def test_tld_expand():
    expanded = tld_expand("example", "data/tlds.txt", verbose=True)
    assert len(expanded) > 0

def test_validate_domains():
    domains = ["example.com", "invalid_domain", "-invalid.com"]
    valid_domains = validate_domains(domains)
    assert "example.com" in valid_domains
    assert "-invalid.com" not in valid_domains