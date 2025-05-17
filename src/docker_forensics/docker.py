"""
Docker-specific functionality for image extraction and analysis.
"""

import os
import json
import tarfile
from .utils import normalize_path

def find_docker_root(mount_path):
    """Find the Docker root directory in the mounted filesystem."""
    possible_paths = [
        ['var', 'lib', 'docker'],
        ['Docker'],  # Windows Docker root
        ['ProgramData', 'Docker']  # Alternative Windows Docker root
    ]
    
    for path_parts in possible_paths:
        path = os.path.join(mount_path, *path_parts)
        if os.path.exists(path) and os.path.isdir(path):
            return path
    
    raise ValueError(f"Could not find Docker root directory in {mount_path}")

# Rest of the Docker-related functions
# ...existing code...
