"""
Docker-specific functionality for image extraction and analysis.
"""

import os
import json
import tarfile
import re
from pathlib import Path
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

def find_layer_dir(docker_root, layer_id):
    """Find the directory containing a specific layer."""
    print(f"\nLooking for layer {layer_id}")
    
    # Clean up layer ID - remove sha256: prefix if present
    clean_id = layer_id.replace('sha256:', '')
    print(f"Cleaned layer ID: {clean_id}")
    
    # Search locations
    locations = {
        'image_db': os.path.join(docker_root, 'image', 'overlay2', 'imagedb', 'content', 'sha256'),
        'layer_db': os.path.join(docker_root, 'image', 'overlay2', 'layerdb', 'sha256'),
        'overlay2': os.path.join(docker_root, 'overlay2'),
        'overlay2_l': os.path.join(docker_root, 'overlay2', 'l')
    }

    # Debug: Print all locations
    print("\nSearching in locations:")
    for name, path in locations.items():
        exists = os.path.exists(path)
        print(f"- {name}: {path} {'(exists)' if exists else '(not found)'}")
    
    # First check the layer database
    layer_path = os.path.join(locations['layer_db'], clean_id)
    print(f"\nChecking layer DB path: {layer_path}")
    
    if os.path.exists(layer_path):
        print(f"Found layer info in layer DB")
        try:
            # Read the cache ID
            cache_id_file = os.path.join(layer_path, 'cache-id')
            if os.path.exists(cache_id_file):
                with open(cache_id_file, 'r') as f:
                    cache_id = f.read().strip()
                print(f"Found cache ID: {cache_id}")
                
                # Look for the layer content
                content_dir = os.path.join(locations['overlay2'], cache_id)
                if os.path.exists(content_dir):
                    print(f"Found layer content at: {content_dir}")
                    return content_dir
            
            # Try diff file if cache-id didn't work
            diff_file = os.path.join(layer_path, 'diff')
            if os.path.exists(diff_file):
                with open(diff_file, 'r') as f:
                    diff_id = f.read().strip()
                print(f"Found diff ID: {diff_id}")
                
                content_dir = os.path.join(locations['overlay2'], diff_id)
                if os.path.exists(content_dir):
                    print(f"Found layer content at: {content_dir}")
                    return content_dir
        except Exception as e:
            print(f"Error reading layer metadata: {e}")

    # Check direct path in overlay2
    direct_path = os.path.join(locations['overlay2'], clean_id)
    print(f"\nChecking direct overlay2 path: {direct_path}")
    if os.path.exists(direct_path):
        print(f"Found layer directly")
        return direct_path

    # Check shortened IDs in overlay2/l directory
    if os.path.exists(locations['overlay2_l']):
        print("\nChecking shortened IDs...")
        try:
            link_count = 0
            for link_name in os.listdir(locations['overlay2_l']):
                link_count += 1
                if link_count % 50 == 0:
                    print(f"Checked {link_count} links...")
                try:
                    # Check both ways - layer ID starts with link name or link name starts with layer ID
                    if clean_id.startswith(link_name) or link_name.startswith(clean_id[:12]):
                        link_path = os.path.join(locations['overlay2_l'], link_name)
                        if os.path.islink(link_path):
                            target = os.readlink(link_path)
                            print(f"Found matching link: {link_name} -> {target}")
                            if not os.path.isabs(target):
                                target = os.path.join(locations['overlay2'], os.path.basename(target))
                            if os.path.exists(target):
                                print(f"Found valid layer through link")
                                return target
                            else:
                                print(f"Link target does not exist: {target}")
                except Exception as e:
                    print(f"Error checking link {link_name}: {e}")
                    continue
            print(f"Checked {link_count} total links")
        except Exception as e:
            print(f"Error reading link directory: {e}")

    # Additional checks for mount namespaces
    mount_file = os.path.join(locations['layer_db'], clean_id, 'mount-id')
    print(f"\nChecking mount ID: {mount_file}")
    if os.path.exists(mount_file):
        try:
            with open(mount_file, 'r') as f:
                mount_id = f.read().strip()
            print(f"Found mount ID: {mount_id}")
            mount_path = os.path.join(locations['overlay2'], mount_id)
            if os.path.exists(mount_path):
                print("Found layer through mount ID")
                return mount_path
            else:
                print(f"Mount ID path does not exist: {mount_path}")
        except Exception as e:
            print(f"Error reading mount ID: {e}")

    # Print available items in overlay2 for debugging
    print(f"\nListing contents of overlay2 directory:")
    try:
        overlay2_items = [d for d in os.listdir(locations['overlay2']) if d != 'l'][:10]
        if overlay2_items:
            print("First 10 items:")
            for item in overlay2_items:
                print(f"- {item}")
            if len(overlay2_items) >= 10:
                print("... (more items)")
        else:
            print("No items found in overlay2 directory")
    except Exception as e:
        print(f"Error listing overlay2 directory: {e}")

    raise ValueError(f"Could not find directory for layer {clean_id}")

def extract_layer_contents(layer_path, output_dir):
    """Extract the contents of a layer to a tarball."""
    print(f"\nExtracting layer from: {layer_path}")
    
    # Check for different layer content locations
    possible_dirs = [
        os.path.join(layer_path, 'diff'),
        layer_path,
        os.path.join(layer_path, 'root'),
        os.path.join(layer_path, 'merged')
    ]
    
    diff_dir = None
    for dir_path in possible_dirs:
        print(f"\nChecking for layer content in: {dir_path}")
        if os.path.exists(dir_path):
            if os.path.isdir(dir_path):
                try:
                    # Verify we can access and list the directory
                    items = os.listdir(dir_path)
                    print(f"Found {len(items)} items")
                    if len(items) > 0:
                        print("Sample items:")
                        for item in items[:5]:
                            item_path = os.path.join(dir_path, item)
                            type_str = 'dir' if os.path.isdir(item_path) else 'file' if os.path.isfile(item_path) else 'link' if os.path.islink(item_path) else 'unknown'
                            print(f"- {item} ({type_str})")
                        if len(items) > 5:
                            print("... (more items)")
                    diff_dir = dir_path
                    print(f"Using content directory: {diff_dir}")
                    break
                except Exception as e:
                    print(f"Cannot access {dir_path}: {e}")
                    continue
            else:
                print(f"Path exists but is not a directory")
        else:
            print("Path does not exist")
    
    if not diff_dir:
        raise ValueError(f"Could not find accessible content in any of these paths:\n" + "\n".join(f"- {p}" for p in possible_dirs))
    
    layer_tarball = os.path.join(output_dir, 'layer.tar')
    print(f"\nCreating layer tarball: {layer_tarball}")
    
    try:
        # Get list of all files and directories first
        all_items = []
        for root, dirs, files in os.walk(diff_dir):
            for d in dirs:
                all_items.append(('dir', os.path.join(root, d)))
            for f in files:
                all_items.append(('file', os.path.join(root, f)))

        total_items = len(all_items)
        if total_items == 0:
            raise ValueError(f"No items found in {diff_dir}")

        print(f"Found {total_items} items to process")
        
        processed_items = 0
        errors = []
        successful_items = 0

        with tarfile.open(layer_tarball, 'w') as tar:
            for item_type, item_path in all_items:
                try:
                    # Calculate the path relative to the diff directory
                    arcname = os.path.relpath(item_path, diff_dir)
                    print(f"\nProcessing: {arcname}")
                    
                    if os.path.islink(item_path):
                        # Handle symbolic links
                        try:
                            link_target = os.readlink(item_path)
                            print(f"  Symlink -> {link_target}")
                            info = tarfile.TarInfo(arcname)
                            info.type = tarfile.SYMTYPE
                            info.linkname = link_target
                            info.mode = 0o777
                            tar.addfile(info)
                            successful_items += 1
                        except Exception as e:
                            print(f"  Error reading symlink: {e}")
                            errors.append(f"Error with symlink {arcname}: {str(e)}")
                            continue
                            
                    elif item_type == 'dir':
                        # Handle directories
                        try:
                            print(f"  Directory")
                            info = tarfile.TarInfo(arcname)
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            tar.addfile(info)
                            successful_items += 1
                        except Exception as e:
                            print(f"  Error adding directory: {e}")
                            errors.append(f"Error with directory {arcname}: {str(e)}")
                            continue
                            
                    else:
                        # Handle regular files
                        try:
                            size = os.path.getsize(item_path)
                            if size > 0:
                                print(f"  File ({size} bytes)")
                                tar.add(item_path, arcname=arcname)
                                successful_items += 1
                            else:
                                print(f"  Empty file")
                                info = tarfile.TarInfo(arcname)
                                info.type = tarfile.REGTYPE
                                info.mode = 0o644
                                info.size = 0
                                tar.addfile(info)
                                successful_items += 1
                        except Exception as e:
                            print(f"  Error adding file: {e}")
                            errors.append(f"Error with file {arcname}: {str(e)}")
                            continue
                    
                    processed_items += 1
                    if processed_items % 100 == 0 or processed_items == total_items:
                        success_rate = (successful_items / processed_items) * 100
                        print(f"Progress: {processed_items}/{total_items} items processed ({success_rate:.1f}% success rate)")
                        
                except Exception as e:
                    error_msg = f"Error processing {item_path}: {str(e)}"
                    print(f"  Error: {error_msg}")
                    errors.append(error_msg)
                    continue
            
        # Final status report
        print(f"\nProcessing complete:")
        print(f"- Total items: {total_items}")
        print(f"- Processed: {processed_items}")
        print(f"- Successful: {successful_items}")
        print(f"- Failed: {len(errors)}")
        
        if errors:
            print(f"\nErrors encountered ({len(errors)} total):")
            for error in errors[:10]:
                print(f"  - {error}")
            if len(errors) > 10:
                print(f"  ... and {len(errors) - 10} more errors")
        
        if successful_items > 0:
            tarball_size = os.path.getsize(layer_tarball)
            print(f"\nCreated layer tarball: {layer_tarball} ({tarball_size} bytes)")
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
    manifest = [{
        'Config': f'{image_id}.json',
        'RepoTags': ['forensic/recovered:latest'],
        'Layers': [os.path.basename(layer) for layer in layer_paths]
    }]
    
    manifest_path = os.path.join(output_dir, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Created manifest at: {manifest_path}")
    return manifest_path

def create_docker_tarball(image_id, manifest_path, layer_paths, metadata_path, output_dir):
    """Create a Docker image tarball that can be imported with docker load."""
    output_path = os.path.join(output_dir, f"{image_id}.tar")
    print(f"Creating Docker image tarball: {output_path}")
    
    with tarfile.open(output_path, 'w') as tar:
        # Add manifest
        tar.add(manifest_path, arcname='manifest.json')
        
        # Add image config
        tar.add(metadata_path, arcname=f'{image_id}.json')
        
        # Add layer tarballs
        for layer_path in layer_paths:
            tar.add(layer_path, arcname=os.path.basename(layer_path))
    
    print(f"Created Docker image tarball at: {output_path}")
    return output_path
