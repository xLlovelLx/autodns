import pytest
from dns_enum.osint import osint_enum

def test_osint_enum(capfd):
    osint_enum("example.com", True)
    captured = capfd.readouterr()
    assert "Performing OSINT-based enumeration" in captured.out