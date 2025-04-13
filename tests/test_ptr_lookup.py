import pytest
from dns_enum.ptr_lookup import ptr_lookup, validate_ip_range

def test_ptr_lookup():
    results = ptr_lookup("8.8.8.0/29", verbose=True)
    assert isinstance(results, dict)

def test_validate_ip_range():
    assert validate_ip_range("8.8.8.0/24") is True
    assert validate_ip_range("invalid") is False