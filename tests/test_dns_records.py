import pytest
from dns_enum.dns_records import query_dns_records

def test_query_dns_records():
    results = query_dns_records("example.com", True)
    assert isinstance(results, dict)
    assert "A" in results