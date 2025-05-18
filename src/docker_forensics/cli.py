#!/usr/bin/env python3
"""
Command-line interface for the Docker forensics tool.
"""

import argparse
import os
import sys
from docker_forensics.docker import extract_image_layers

def main():
    parser = argparse.ArgumentParser(
        description='Extract Docker image from a mounted Docker host filesystem'
    )
    parser.add_argument(
        'image_id',
        help='Docker image ID (sha256 hash without prefix)'
    )
    parser.add_argument(
        'mount_path',
        help='Path where the E01 is mounted'
    )
    parser.add_argument(
        'output_dir',
        help='Directory to save extracted image data'
    )
    args = parser.parse_args()
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run the extraction
    extract_image_layers(args.image_id, args.mount_path, args.output_dir)

if __name__ == "__main__":
    main()
