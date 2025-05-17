#!/usr/bin/env python3
"""
Core functionality for extracting Docker images from forensic disk images.
"""

import json
import os
import sys
import shutil
from pathlib import Path

from .utils import normalize_path
from .docker import (
    find_docker_root, find_layer_dir, extract_layer_contents,
    create_dockerfile, create_manifest, create_docker_tarball,
    clean_and_parse_json
)

def extract_image_layers(image_id, mount_path, output_dir):
    """Extract image data from a mounted Docker host filesystem."""
    try:
        print(f"\nStarting extraction for image: {image_id}")
        print(f"Mount path: {mount_path}")
        print(f"Output directory: {output_dir}")
        
        # Find Docker root directory
        docker_root = find_docker_root(mount_path)
        print(f"Found Docker root directory at: {docker_root}")
        
        # Create output directory for this image
        image_output_dir = os.path.join(output_dir, f"image_{image_id}")
        os.makedirs(image_output_dir, exist_ok=True)
        
        # Find image metadata file
        image_db_path = os.path.join(docker_root, 'image', 'overlay2', 'imagedb', 'content', 'sha256')
        
        # Find the full image ID by matching prefix
        full_image_id = None
        for filename in os.listdir(image_db_path):
            if filename.startswith(image_id):
                full_image_id = filename
                break
        
        if not full_image_id:
            raise ValueError(f"No image found with ID prefix {image_id}")
        
        print(f"Found full image ID: {full_image_id}")
        image_metadata_path = os.path.join(image_db_path, full_image_id)
        
        # Parse image metadata
        metadata = clean_and_parse_json(image_metadata_path)
        
        # Save image metadata
        metadata_output_path = os.path.join(image_output_dir, 'image_metadata.json')
        with open(metadata_output_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print("Saved image metadata")
        
        # Get layer information
        if 'rootfs' not in metadata or 'diff_ids' not in metadata['rootfs']:
            raise ValueError("Invalid image metadata format - missing layer information")
        
        layer_ids = metadata['rootfs']['diff_ids']
        print(f"\nFound {len(layer_ids)} layers to process")
        
        # Extract each layer
        layer_paths = []
        success_count = 0
        
        for i, layer_id in enumerate(layer_ids):
            print(f"\nProcessing layer {i+1}/{len(layer_ids)}: {layer_id}")
            try:
                # Create layer output directory
                layer_output_dir = os.path.join(image_output_dir, f"layer_{i}")
                os.makedirs(layer_output_dir, exist_ok=True)
                
                # Find and extract layer
                layer_dir = find_layer_dir(docker_root, layer_id)
                layer_tarball = extract_layer_contents(layer_dir, layer_output_dir)
                
                if layer_tarball and os.path.exists(layer_tarball):
                    layer_paths.append(layer_tarball)
                    success_count += 1
                    print(f"Layer {i+1} extracted successfully")
                else:
                    print(f"Warning: Layer {i+1} extraction produced no output")
                
            except Exception as e:
                print(f"Error extracting layer {i+1}: {e}")
                continue
        
        if not layer_paths:
            raise ValueError("No layers were successfully extracted")
        
        print(f"\nSuccessfully extracted {success_count} of {len(layer_ids)} layers")
        
        # Create Dockerfile
        print("\nGenerating Dockerfile...")
        create_dockerfile(metadata, image_output_dir)
        
        # Create manifest
        print("Creating image manifest...")
        manifest_path = create_manifest(full_image_id, layer_paths, image_output_dir)
        
        # Create importable Docker image archive
        print("Creating Docker image archive...")
        archive_path = create_docker_tarball(
            full_image_id, 
            manifest_path, 
            layer_paths, 
            metadata_output_path,
            image_output_dir
        )
        
        print("\nExtraction completed successfully!")
        print(f"Output saved to: {image_output_dir}")
        print("\nTo import the image on another system, run:")
        print(f"docker load -i {os.path.basename(archive_path)}")
        
        return image_output_dir
        
    except Exception as e:
        print(f"Error during extraction: {str(e)}", file=sys.stderr)
        raise
