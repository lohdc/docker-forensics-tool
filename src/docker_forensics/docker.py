"""
Docker-specific functionality for image extraction and analysis.
"""

import os
import sys
import re
import json
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .utils import normalize_path

def find_docker_root(mount_path):
    """Find the Docker root directory in the mounted filesystem."""
    print(f"Checking mount path: {mount_path}")
    
    # Check for [root] directory in forensic mounts
    root_dir = os.path.join(mount_path, '[root]')
    if os.path.exists(root_dir):
        mount_path = root_dir
        print(f"Found [root] directory, adjusting mount path to: {mount_path}")
    
    possible_paths = [
        ['var', 'lib', 'docker'],
        ['Docker'],  # Windows Docker root
        ['ProgramData', 'Docker']  # Alternative Windows Docker root
    ]
    
    for path_parts in possible_paths:
        path = os.path.join(mount_path, *path_parts)
        if os.path.exists(path) and os.path.isdir(path):
            print(f"Found Docker root at: {path}")
            return path
    
    raise ValueError(f"Could not find Docker root directory in {mount_path}")

def clean_and_parse_json(file_path):
    """Clean and parse JSON content from a file."""
    print(f"Reading and parsing JSON from: {file_path}")
    
    with open(file_path, 'rb') as f:
        content_bytes = f.read()
    
    # Try different encodings
    try:
        content = content_bytes.decode('utf-8')
    except UnicodeDecodeError:
        try:
            content = content_bytes.decode('latin1')
        except:
            content = content_bytes.decode('utf-8', errors='replace')
    
    # Remove any UTF-8 BOM
    content = content.lstrip('\ufeff')
    
    # Find the JSON object boundaries
    brace_start = content.find('{')
    brace_end = content.rfind('}')
    
    if brace_start >= 0 and brace_end > brace_start:
        json_content = content[brace_start:brace_end + 1]
        
        # Clean up the content
        json_content = re.sub(r'[^\x20-\x7E\n\t]', '', json_content)  # Remove non-printable chars
        json_content = re.sub(r',\s*([\]}])', r'\1', json_content)     # Remove trailing commas
        json_content = re.sub(r'"\s+', '"', json_content)              # Fix spaces after quotes
        
        try:
            return json.loads(json_content)
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            # Try more aggressive cleaning
            json_content = re.sub(r'\\n', ' ', json_content)
            json_content = re.sub(r'\s+', ' ', json_content)
            return json.loads(json_content)
    
    raise ValueError("Could not find valid JSON content in file")

def extract_layer_contents(layer_path, output_dir):
    """Extract the contents of a layer to a tarball."""
    print(f"\nExtracting layer from: {layer_path}")
    
    # Determine the diff directory
    diff_dir = None
    if os.path.isdir(layer_path):
        if os.path.exists(os.path.join(layer_path, 'diff')):
            diff_dir = os.path.join(layer_path, 'diff')
        else:
            diff_dir = layer_path
    
    if not diff_dir or not os.path.exists(diff_dir):
        raise ValueError(f"Could not find valid content directory in {layer_path}")

    layer_tarball = os.path.join(output_dir, 'layer.tar')
    print(f"Creating layer tarball: {layer_tarball}")
    
    try:
        # Get list of all files and directories
        all_items = []
        for root, dirs, files in os.walk(diff_dir):
            for d in dirs:
                all_items.append(('dir', os.path.join(root, d)))
            for f in files:
                all_items.append(('file', os.path.join(root, f)))

        if not all_items:
            raise ValueError(f"No items found in {diff_dir}")

        print(f"Found {len(all_items)} items to process")
        processed_items = 0
        successful_items = 0
        errors = []

        with tarfile.open(layer_tarball, 'w') as tar:
            for item_type, item_path in all_items:
                try:
                    arcname = os.path.relpath(item_path, diff_dir)
                    print(f"Processing: {arcname}")
                    
                    if os.path.islink(item_path):
                        # Handle symlinks
                        try:
                            link_target = os.readlink(item_path)
                            info = tarfile.TarInfo(arcname)
                            info.type = tarfile.SYMTYPE
                            info.linkname = link_target
                            info.mode = 0o777
                            tar.addfile(info)
                            successful_items += 1
                        except Exception as e:
                            errors.append(f"Error with symlink {arcname}: {str(e)}")
                            continue
                            
                    elif item_type == 'dir':
                        # Handle directories
                        try:
                            info = tarfile.TarInfo(arcname)
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            tar.addfile(info)
                            successful_items += 1
                        except Exception as e:
                            errors.append(f"Error with directory {arcname}: {str(e)}")
                            continue
                            
                    else:
                        # Handle regular files
                        try:
                            if os.path.getsize(item_path) > 0:
                                tar.add(item_path, arcname=arcname)
                            else:
                                info = tarfile.TarInfo(arcname)
                                info.type = tarfile.REGTYPE
                                info.mode = 0o644
                                info.size = 0
                                tar.addfile(info)
                            successful_items += 1
                        except Exception as e:
                            errors.append(f"Error with file {arcname}: {str(e)}")
                            continue
                    
                    processed_items += 1
                    if processed_items % 100 == 0:
                        print(f"Progress: {processed_items}/{len(all_items)} items")
                        
                except Exception as e:
                    errors.append(f"Error processing {item_path}: {str(e)}")
                    continue

        if successful_items > 0:
            print(f"\nLayer extraction complete:")
            print(f"- Total items: {len(all_items)}")
            print(f"- Processed: {processed_items}")
            print(f"- Successful: {successful_items}")
            print(f"- Failed: {len(errors)}")
            
            if errors:
                print("\nErrors encountered:")
                for error in errors[:10]:
                    print(f"  - {error}")
                if len(errors) > 10:
                    print(f"  ... and {len(errors) - 10} more errors")
            
            return layer_tarball
        else:
            raise ValueError("No items were successfully processed")
            
    except Exception as e:
        print(f"Critical error during layer extraction: {str(e)}")
        if os.path.exists(layer_tarball):
            os.remove(layer_tarball)
        raise

def create_dockerfile(metadata, output_dir):
    """Create a Dockerfile based on the image metadata."""
    dockerfile_path = os.path.join(output_dir, 'Dockerfile')
    config = metadata.get('config', {})
    
    with open(dockerfile_path, 'w') as f:
        f.write("FROM scratch\n\n")
        
        # Add environment variables
        env_vars = config.get('Env', [])
        for env in env_vars:
            f.write(f"ENV {env}\n")
        if env_vars:
            f.write("\n")
        
        # Add working directory
        if 'WorkingDir' in config and config['WorkingDir']:
            f.write(f"WORKDIR {config['WorkingDir']}\n\n")
        
        # Add exposed ports
        exposed_ports = config.get('ExposedPorts', {})
        for port in exposed_ports:
            f.write(f"EXPOSE {port}\n")
        if exposed_ports:
            f.write("\n")
        
        # Add volume definitions
        volumes = config.get('Volumes', {})
        for volume in volumes:
            f.write(f"VOLUME {volume}\n")
        if volumes:
            f.write("\n")
        
        # Add user
        if 'User' in config and config['User']:
            f.write(f"USER {config['User']}\n\n")
        
        # Add entrypoint and cmd
        entrypoint = config.get('Entrypoint')
        if entrypoint:
            entrypoint_json = json.dumps(entrypoint)
            f.write(f"ENTRYPOINT {entrypoint_json}\n")
        
        cmd = config.get('Cmd')
        if cmd:
            cmd_json = json.dumps(cmd)
            f.write(f"CMD {cmd_json}\n")
    
    print(f"Created Dockerfile at: {dockerfile_path}")

def create_manifest(image_id, layer_paths, output_dir):
    """Create a Docker image manifest file."""
    print("\nCreating manifest file...")
    
    # Sort layer paths to ensure correct order
    layer_paths.sort(key=lambda x: int(os.path.basename(os.path.dirname(x)).split('_')[1]))
    
    # Convert layer paths to the format Docker expects
    layers = []
    for layer_path in layer_paths:
        layer_dir = os.path.dirname(layer_path)
        layer_name = os.path.basename(layer_dir)
        layers.append(f"{layer_name}/layer.tar")
    
    manifest = [{
        "Config": f"{image_id}.json",
        "RepoTags": ["forensic/recovered:latest"],
        "Layers": layers  # Each layer should be in the format "layer_N/layer.tar"
    }]
    
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Created manifest with {len(layers)} layers")
    print("Layer order in manifest:")
    for layer in layers:
        print(f"  - {layer}")
    
    return manifest_path

def create_docker_tarball(config_name, manifest_path, layer_paths, config_path, output_dir):
    """Create a Docker image tarball that can be imported with docker load."""
    print("\nCreating Docker image archive...")
    
    archive_path = os.path.join(output_dir, "image.tar")
    
    with tarfile.open(archive_path, "w") as tar:
        # Add manifest first (Docker expects this)
        tar.add(manifest_path, arcname="manifest.json")
        
        # Add image config with the exact name referenced in manifest
        tar.add(config_path, arcname=config_name)
        
        # Add each layer maintaining the directory structure
        for layer_path in layer_paths:
            layer_dir = os.path.dirname(layer_path)
            layer_name = os.path.basename(layer_dir)
            tar.add(layer_path, arcname=f"{layer_name}/layer.tar")
    
    print(f"Created Docker image archive: {archive_path}")
    return archive_path

def find_layer_content(docker_root: str, layer_id: str) -> Optional[str]:
    """
    Find a single layer's content directory.
    Returns the path to the layer's diff directory if found, None otherwise.
    """
    print(f"\nSearching for layer: {layer_id}")
    
    # First try exact match
    result = find_layer_by_id(docker_root, layer_id, any_prefix=False)
    if result:
        layer_dir, content_dir = result
        print(f"Found layer content at: {content_dir}")
        return content_dir
    
    # Then try prefix match
    result = find_layer_by_id(docker_root, layer_id, any_prefix=True)
    if result:
        layer_dir, content_dir = result
        print(f"Found layer content by prefix at: {content_dir}")
        return content_dir
        
    print(f"Could not find content for layer: {layer_id}")
    return None

def follow_layer_stack(docker_root: str, layer_id: str) -> List[str]:
    """
    Follow the layer stack from top to bottom using layer chain information.
    Returns a list of layer paths from lowest (base) to highest.
    """
    print(f"\n=== Starting layer stack traversal for {layer_id} ===")
    stack = []
    visited = set()
    current_id = clean_layer_id(layer_id)
    print(f"Initial layer ID (cleaned): {current_id}")
    
    while current_id and current_id not in visited:
        visited.add(current_id)
        print(f"\n=== Following layer: {current_id} ===")
        
        # Clean up any malformed paths that might have gotten into the ID
        original_id = current_id
        current_id = re.sub(r'[\\/].*$', '', current_id)  # Remove anything after a slash or backslash
        current_id = current_id.strip()
        
        if original_id != current_id:
            print(f"Cleaned layer ID from '{original_id}' to '{current_id}'")
        
        # Find current layer directory
        print(f"Searching for layer directory with ID: {current_id}")
        result = find_layer_by_id(docker_root, current_id)
        if not result:
            print(f"Could not find directory for layer: {current_id}")
            print("Dirs in overlay2:")
            overlay2_dir = os.path.join(docker_root, 'overlay2')
            if os.path.exists(overlay2_dir):
                try:
                    print([d for d in os.listdir(overlay2_dir) if os.path.isdir(os.path.join(overlay2_dir, d))][:5])
                except Exception as e:
                    print(f"Error listing overlay2: {e}")
            break
        
        layer_dir, content_dir = result
        stack.append(content_dir)
        print(f"Added layer path to stack: {content_dir}")
        
        # Try to find parent layer using multiple methods
        parent_id = None
        print("\nSearching for parent layer...")
        
        # Method 1: Check parent file in layer database
        clean_id = current_id.replace('sha256:', '')
        layer_db = os.path.join(docker_root, 'image', 'overlay2', 'layerdb', 'sha256', clean_id)
        if os.path.exists(layer_db):
            print(f"Found layer database at: {layer_db}")
            # First try direct parent reference            parent_file = os.path.join(layer_db, 'parent')
            if os.path.exists(parent_file):
                try:
                    with open(parent_file, 'r') as f:
                        parent_id = f.read().strip()
                        print(f"Found parent in database: {parent_id}")
                except Exception as e:
                    print(f"Error reading parent file: {e}")
        
        # Method 2: Check chain-id and follow parent chain
        if not parent_id:
            chain_file = os.path.join(layer_db, 'chain-id')
            if os.path.exists(chain_file):
                try:
                    with open(chain_file, 'r') as f:
                        chain_id = f.read().strip()
                        print(f"Found chain ID: {chain_id}")
                        # Try to find parent chain
                        for entry in os.listdir(os.path.dirname(layer_db)):
                            entry_db = os.path.join(os.path.dirname(layer_db), entry)
                            if os.path.isdir(entry_db):
                                entry_chain = os.path.join(entry_db, 'chain-id')
                                if os.path.exists(entry_chain):
                                    with open(entry_chain, 'r') as f:
                                        entry_chain_id = f.read().strip()
                                        if entry_chain_id == chain_id and entry != clean_id:
                                            parent_id = entry
                                            print(f"Found parent through chain: {parent_id}")
                                            break
                except Exception as e:
                    print(f"Error checking chain ID: {e}")
        
        # Method 3: Check lower file in overlay directory
        if not parent_id:
            lower_file = os.path.join(layer_dir, 'lower')
            if os.path.exists(lower_file):
                try:
                    with open(lower_file, 'r') as f:
                        lower_layers = f.read().strip()
                        if lower_layers:
                            # Format is l1:l2:l3 where each l is a short ID
                            lower_ids = lower_layers.split(':')
                            if lower_ids:
                                parent_id = lower_ids[0]  # Take immediate parent
                                print(f"Found parent in lower file: {parent_id}")
                except Exception as e:
                    print(f"Error reading lower file: {e}")
        
        if parent_id:
            # Clean up parent ID and ensure it's not corrupted
            parent_id = parent_id.replace('sha256:', '').strip()
            parent_id = re.sub(r'[\\/].*$', '', parent_id)  # Remove anything after a slash or backslash
            print(f"Moving to cleaned parent layer: {parent_id}")
            current_id = parent_id
        else:
            print("No parent layer found, reached base layer")
            break
    
    # Reverse stack so base layer is first
    return list(reversed(stack))

def extract_image_layers(image_id: str, mount_path: str, output_dir: str) -> bool:
    """Extract all layers of a Docker image to the output directory."""
    print(f"\nStarting extraction of image: {image_id}")
    print(f"Mount path: {mount_path}")
    print(f"Output directory: {output_dir}")
    
    try:
        # Find Docker root directory
        docker_root = find_docker_root(mount_path)
        print(f"\nFound Docker root at: {docker_root}")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Find and parse image config
        image_path = None
        config_dir = os.path.join(docker_root, 'image', 'overlay2', 'imagedb', 'content', 'sha256')
        if os.path.exists(config_dir):
            # Try both full ID and short ID
            possible_paths = [
                os.path.join(config_dir, image_id),
                os.path.join(config_dir, image_id[:12])
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    image_path = path
                    break
                else:
                    # Try partial matches
                    for filename in os.listdir(config_dir):
                        if filename.startswith(image_id[:12]):
                            image_path = os.path.join(config_dir, filename)
                            break
                    if image_path:
                        break
        
        if not image_path:
            raise ValueError(f"Could not find image config for ID: {image_id}")
        
        # Parse image config and set up metadata
        config = clean_and_parse_json(image_path)
        config_name = os.path.basename(image_path)  # Use the full SHA256 ID as filename
        metadata_path = os.path.join(output_dir, config_name)
        with open(metadata_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Get layer information and process layers
        if 'rootfs' not in config or 'diff_ids' not in config['rootfs']:
            raise ValueError("Invalid image metadata - missing layer information")
            
        layer_ids = config['rootfs']['diff_ids']
        print(f"\nFound {len(layer_ids)} layers to process")
        print("\nLayer IDs from image config:")
        for idx, lid in enumerate(layer_ids):
            print(f"{idx+1}. {lid}")

        # Extract layers
        layer_paths = []
        processed_layers = set()

        for i, layer_id in enumerate(layer_ids):
            clean_id = clean_layer_id(layer_id)
            
            try:
                if clean_id in processed_layers:
                    print(f"Layer {clean_id} already processed, skipping")
                    continue

                # Create output directory for this layer
                layer_dir = os.path.join(output_dir, f"layer_{i:03d}")
                os.makedirs(layer_dir, exist_ok=True)

                # Extract the layer
                layer_path = find_layer_content(docker_root, clean_id)
                if layer_path:
                    print(f"Extracting layer content from: {layer_path}")
                    layer_tarball = extract_layer_contents(layer_path, layer_dir)
                    if layer_tarball and os.path.exists(layer_tarball):
                        layer_paths.append(layer_tarball)
                        processed_layers.add(clean_id)
                else:
                    print(f"Could not find layer {clean_id}, skipping")

            except Exception as e:
                print(f"Error extracting layer {i+1}: {e}")
                continue

        if not layer_paths:
            raise ValueError("No layers were successfully extracted")
            
        print(f"\nSuccessfully extracted {len(layer_paths)} of {len(layer_ids)} layers")

        # Sort layers by their numerical index
        sorted_paths = sorted(layer_paths, key=lambda x: int(os.path.basename(os.path.dirname(x)).split('_')[1]))
        layers_in_manifest = []
        
        for layer_path in sorted_paths:
            layer_dir = os.path.dirname(layer_path)
            layer_name = os.path.basename(layer_dir)
            layers_in_manifest.append(f"{layer_name}/layer.tar")
            
        # Create manifest with exact config name including .json extension
        config_filename = config_name + '.json'  # Add .json extension
        manifest = [{
            'Config': config_filename,  # Use filename with .json extension
            'RepoTags': ['forensic/recovered:latest'],
            'Layers': layers_in_manifest
        }]
        
        manifest_path = os.path.join(output_dir, 'manifest.json')
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Save metadata with .json extension as referenced in manifest
        metadata_filename = os.path.join(output_dir, config_filename)
        if metadata_path != metadata_filename:
            os.rename(metadata_path, metadata_filename)
            metadata_path = metadata_filename
            
        # Create importable archive
        archive_path = create_docker_tarball(
            config_filename,  # Pass filename with .json extension
            manifest_path,
            sorted_paths,
            metadata_path,
            output_dir
        )
        
        print(f"\nExtraction complete. Output saved to: {output_dir}")
        print(f"\nTo import the image, run:")
        print(f"docker load -i {os.path.basename(archive_path)}")
        
        return True

    except Exception as e:
        print(f"\nERROR during extraction: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Helper functions

def find_layer_by_diff_id(docker_root: str, target_diff_id: str) -> Optional[Tuple[str, str]]:
    """Find a layer directory by matching its diff ID against a target."""
    overlay2_dir = os.path.join(docker_root, 'overlay2')
    layer_db_dir = os.path.join(docker_root, 'image', 'overlay2', 'layerdb', 'sha256')
    
    target_diff_id = clean_layer_id(target_diff_id)
    print(f"\n=== Searching for layer with diff ID: {target_diff_id} ===")
    print("\nSearching through layer database with detailed logging...")
    
    # First try to find the layer's cache ID from the layer database
    for entry in os.listdir(layer_db_dir):
        layer_db = os.path.join(layer_db_dir, entry)
        print(f"\nExamining layer database entry: {entry}")
        
        # Check chain ID first
        chain_file = os.path.join(layer_db, 'chain-id')
        if os.path.exists(chain_file):
            try:
                with open(chain_file, 'r') as f:
                    chain_id = f.read().strip()
                    chain_id = clean_layer_id(chain_id)
                    print(f"Chain ID: {chain_id}")
            except Exception as e:
                print(f"Error reading chain ID: {e}")
        
        # Then check diff ID
        diff_file = os.path.join(layer_db, 'diff')
        if os.path.exists(diff_file):
            try:
                with open(diff_file, 'r') as f:
                    diff_id = f.read().strip()
                    diff_id = clean_layer_id(diff_id)
                    print(f"Diff ID: {diff_id}")
                    if diff_id == target_diff_id:
                        print("*** Found matching diff ID ***")
                        # Get cache ID for this layer
                        cache_file = os.path.join(layer_db, 'cache-id')
                        if os.path.exists(cache_file):
                            with open(cache_file, 'r') as f:
                                cache_id = f.read().strip()
                                print(f"Cache ID: {cache_id}")
                                # Look up content in overlay2
                                overlay_dir = os.path.join(overlay2_dir, cache_id)
                                if os.path.exists(overlay_dir):
                                    print(f"Found overlay directory: {overlay_dir}")
                                    content_dir = os.path.join(overlay_dir, 'diff')
                                    if os.path.exists(content_dir):
                                        print(f"Found content at: {content_dir}")
                                        return overlay_dir, content_dir
            except Exception as e:
                print(f"Error reading layer info: {e}")
                continue
    
    if not os.path.exists(layer_db_dir):
        print(f"Layer database not found at: {layer_db_dir}")
        return None
        
    # Search through layer database for matching diff ID
    for entry in os.listdir(layer_db_dir):
        layer_db = os.path.join(layer_db_dir, entry)
        if not os.path.isdir(layer_db):
            continue
            
        diff_file = os.path.join(layer_db, 'diff')
        if not os.path.exists(diff_file):
            continue
            
        try:
            with open(diff_file, 'r') as f:
                diff_id = f.read().strip()
                diff_id = clean_layer_id(diff_id)
                
                print(f"\nComparing diff IDs:")
                print(f"  Target: {target_diff_id}")
                print(f"  Found:  {diff_id}")
                
                if diff_id == target_diff_id:
                    print(f"Found matching diff ID in: {entry}")
                    # Get cache ID to find content
                    cache_file = os.path.join(layer_db, 'cache-id')
                    if os.path.exists(cache_file):
                        with open(cache_file, 'r') as f:
                            cache_id = f.read().strip()
                            print(f"Found cache ID: {cache_id}")
                            # Look for content in overlay2 directory
                            overlay_dir = os.path.join(overlay2_dir, cache_id)
                            if os.path.exists(overlay_dir):
                                content_dir = os.path.join(overlay_dir, 'diff')
                                if os.path.exists(content_dir):
                                    print(f"Found layer content at: {content_dir}")
                                    return overlay_dir, content_dir
                            else:
                                print(f"Overlay directory not found: {overlay_dir}")
                    else:
                        print(f"No cache-id file found in {layer_db}")
        except Exception as e:
            print(f"Error processing layer {entry}: {e}")
            continue
    
    print(f"No matching diff ID found for: {target_diff_id}")
    return None

def find_layer_by_id(docker_root: str, layer_id: str, any_prefix: bool = False) -> Optional[Tuple[str, str]]:
    """
    Find a layer directory by its ID in the overlay2 directory structure.
    
    Args:
        docker_root: Docker root directory path
        layer_id: Layer ID (can be content hash, chain ID, or cache ID)
        any_prefix: Whether to match ID prefixes
        
    Returns:
        Tuple of (layer_dir, content_dir) if found, None otherwise
    """
    clean_id = clean_layer_id(layer_id)
    short_id = clean_id[:12]
    print(f"\n=== Looking for layer: {clean_id} ===")
    print(f"Short ID: {short_id}")
    
    # First try to find layer by diff ID since that's what image config uses
    result = find_layer_by_diff_id(docker_root, clean_id)
    if result:
        return result
        
    # If that fails, try cache ID lookup
    overlay2_dir = os.path.join(docker_root, 'overlay2')
    layer_db_dir = os.path.join(docker_root, 'image', 'overlay2', 'layerdb', 'sha256')
    
    print(f"Checking overlay2 directory: {overlay2_dir}")
    print(f"Checking layer database: {layer_db_dir}")
    
    if not os.path.exists(overlay2_dir):
        print(f"ERROR: Overlay2 directory not found: {overlay2_dir}")
        return None
    
    # Try direct lookup in layer database
    print("\nSearching layer database by ID...")
    layer_db = os.path.join(layer_db_dir, clean_id)
    if os.path.exists(layer_db):
        print(f"Found exact match in database: {clean_id}")
        # Try to find overlay directory
        cache_file = os.path.join(layer_db, 'cache-id')
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cache_id = f.read().strip()
                    print(f"Found cache ID: {cache_id}")
                    overlay_dir = os.path.join(overlay2_dir, cache_id)
                    if os.path.exists(overlay_dir):
                        content_dir = os.path.join(overlay_dir, 'diff')
                        if os.path.exists(content_dir):
                            print(f"Found layer content at: {content_dir}")
                            return overlay_dir, content_dir
            except Exception as e:
                print(f"Error reading cache file: {e}")
    
    # If still not found, try search in overlay2/l symlinks
    l_dir = os.path.join(overlay2_dir, 'l')
    if os.path.exists(l_dir):
        print("\nSearching l/ directory for symlinks...")
        for entry in os.listdir(l_dir):
            try:
                link_target = os.readlink(os.path.join(l_dir, entry))
                print(f"\nFound symlink: {entry} -> {link_target}")
                target_dir = os.path.abspath(os.path.join(l_dir, link_target))
                if entry == clean_id or (any_prefix and entry.startswith(short_id)):
                    print(f"MATCH: Found matching symlink: {entry}")
                    if os.path.exists(target_dir):
                        content_dir = os.path.join(target_dir, 'diff')
                        if os.path.exists(content_dir):
                            print(f"Found layer content at: {content_dir}")
                            return target_dir, content_dir
            except Exception as e:
                print(f"Error with symlink {entry}: {e}")
                continue
    
    print(f"\nCould not find layer: {clean_id}")
    return None

def clean_layer_id(layer_id: str) -> str:
    """Clean up a layer ID by removing any path components and prefixes."""
    # Remove sha256: prefix if present
    clean_id = layer_id.replace('sha256:', '')
    
    # Remove any path components
    clean_id = re.sub(r'[\\/].*$', '', clean_id)
    
    # Remove any trailing garbage
    clean_id = clean_id.split()[0]
    
    return clean_id.strip()
