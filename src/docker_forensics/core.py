#!/usr/bin/env python3
"""
Core functionality for extracting Docker images from forensic disk images.
"""

import json
import os
import sys
import shutil
import tarfile
from pathlib import Path

from .utils import normalize_path
from .docker import (find_docker_root, find_layer_dir, extract_layer_contents,
                   create_dockerfile, create_manifest, create_docker_tarball)

def extract_image_layers(image_id, mount_path, output_dir):
    """Extract image data from a mounted Docker host filesystem."""
    try:
        print(f"Starting extraction with image_id: {image_id}")
        print(f"Mount path: {mount_path}")
        print(f"Output directory: {output_dir}")
        
        # Find Docker root directory
        docker_root = find_docker_root(mount_path)
        print(f"Found Docker root directory at: {docker_root}")
        
        # Rest of the extraction logic
        # ...existing code...
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
