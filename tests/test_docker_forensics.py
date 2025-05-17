import os
import pytest
from docker_forensics.utils import normalize_path
from docker_forensics.docker import find_docker_root

def test_normalize_path():
    # Test path normalization
    paths = ["dir1", "dir2", "file.txt"]
    normalized = normalize_path(*paths)
    assert isinstance(normalized, str)
    assert os.sep in normalized

def test_find_docker_root_nonexistent():
    # Test handling of non-existent paths
    with pytest.raises(ValueError):
        find_docker_root("/nonexistent/path")

# Add more tests as needed...
