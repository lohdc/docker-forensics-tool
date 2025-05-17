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
    print(f"Looking for layer directory for ID: {layer_id}")
    
    # Clean up layer ID - remove sha256: prefix if present
    layer_id = layer_id.replace('sha256:', '')
    
    # Set up paths
    overlay2_path = os.path.join(docker_root, 'overlay2')
    link_dir = os.path.join(overlay2_path, 'l')
    
    # Try direct mapping first
    layer_dir = os.path.join(overlay2_path, layer_id)
    if os.path.exists(layer_dir):
        print(f"Found layer directory directly: {layer_dir}")
        return layer_dir
    
    # Try looking in the l/ directory for short names
    if os.path.exists(link_dir):
        print("Checking layer links directory...")
        for link_name in os.listdir(link_dir):
            try:
                if layer_id.startswith(link_name) or link_name.startswith(layer_id[:12]):
                    link_path = os.path.join(link_dir, link_name)
                    if os.path.islink(link_path):
                        target = os.readlink(link_path)
                        if not os.path.isabs(target):
                            target = os.path.join(overlay2_path, target)
                        if os.path.exists(target):
                            print(f"Found layer through symlink: {target}")
                            return target
            except Exception as e:
                print(f"Warning: Error checking symlink {link_name}: {e}")
    
    raise ValueError(f"Could not find directory for layer {layer_id}")

def extract_layer_contents(layer_path, output_dir):
    """Extract the contents of a layer to a tarball."""
    diff_dir = os.path.join(layer_path, 'diff')
    if not os.path.exists(diff_dir):
        raise ValueError(f"Layer diff directory not found at {diff_dir}")
    
    layer_tarball = os.path.join(output_dir, 'layer.tar')
    print(f"Creating layer tarball: {layer_tarball}")
    
    try:
        with tarfile.open(layer_tarball, 'w') as tar:
            # Get list of all files and directories first
            all_items = []
            for root, dirs, files in os.walk(diff_dir):
                for d in dirs:
                    all_items.append(('dir', os.path.join(root, d)))
                for f in files:
                    all_items.append(('file', os.path.join(root, f)))

            total_items = len(all_items)
            processed_items = 0
            errors = []

            print(f"Found {total_items} items to process")
            
            for item_type, item_path in all_items:
                try:
                    arcname = os.path.relpath(item_path, diff_dir)
                    
                    if os.path.islink(item_path):
                        # Handle symbolic links
                        link_target = os.readlink(item_path)
                        info = tarfile.TarInfo(arcname)
                        info.type = tarfile.SYMTYPE
                        info.linkname = link_target
                        info.mode = 0o777
                        tar.addfile(info)
                    elif item_type == 'dir':
                        # Handle empty directories
                        if not os.listdir(item_path):
                            info = tarfile.TarInfo(arcname)
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            tar.addfile(info)
                    else:
                        # Handle regular files
                        if os.path.getsize(item_path) > 0:
                            tar.add(item_path, arcname=arcname)
                        else:
                            # Handle empty files
                            info = tarfile.TarInfo(arcname)
                            info.type = tarfile.REGTYPE
                            info.mode = 0o644
                            info.size = 0
                            tar.addfile(info)
                    
                    processed_items += 1
                    if processed_items % 100 == 0 or processed_items == total_items:
                        print(f"Progress: {processed_items}/{total_items} items processed")
                        
                except Exception as e:
                    errors.append(f"Error processing {item_path}: {str(e)}")
                    continue
            
            if errors:
                print(f"\nCompleted with {len(errors)} errors:")
                for error in errors[:10]:
                    print(f"  - {error}")
                if len(errors) > 10:
                    print(f"  ... and {len(errors) - 10} more errors")
    
    except Exception as e:
        print(f"Critical error during layer extraction: {str(e)}")
        if os.path.exists(layer_tarball):
            os.remove(layer_tarball)
        raise
    
    return layer_tarball

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
