import pytest
from dns_enum.resolvers import load_resolvers, set_custom_resolvers, test_resolvers

def test_load_resolvers():
    resolvers = load_resolvers("data/resolvers.txt")
    assert len(resolvers) > 0
    assert "8.8.8.8" in resolvers

def test_set_custom_resolvers():
    resolver = object()  # Placeholder for a resolver instance
    set_custom_resolvers(resolver, "data/resolvers.txt")
    assert hasattr(resolver, "nameservers")

def test_test_resolvers():
    resolvers = ["8.8.8.8", "1.1.1.1"]
    working_resolvers = test_resolvers(resolvers)
    assert len(working_resolvers) > 0