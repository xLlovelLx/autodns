import pytest
from scripts.utils import validate_file_path, load_file_lines

def test_validate_file_path():
    valid_path = validate_file_path("data/subdomains.txt", "default.txt")
    assert valid_path == "data/subdomains.txt"

def test_load_file_lines():
    lines = load_file_lines("data/subdomains.txt")
    assert len(lines) > 0