import pytest
from dns_enum.zone_transfer import check_zone_transfer

def test_check_zone_transfer(capfd):
    check_zone_transfer("example.com", True)
    captured = capfd.readouterr()
    assert "Checking for DNS zone transfer" in captured.out