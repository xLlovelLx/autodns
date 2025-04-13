import pytest
from dns_enum.brute import brute_force
import asyncio

@pytest.mark.asyncio
async def test_brute_force():
    domain = "example.com"
    wordlist = "data/subdomains.txt"
    resolvers = "data/resolvers.txt"
    await brute_force(domain, wordlist, resolvers, True)