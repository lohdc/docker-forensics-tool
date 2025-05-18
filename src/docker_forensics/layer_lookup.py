"""
Utilities for mapping between various Docker layer identifiers.
"""

import os
import json
import glob
from typing import Dict, Optional, List, Set, Tuple

def get_layer_paths(docker_root: str) -> Dict[str, str]:
    """Get standard Docker layer paths."""
    return {
        'overlay2': os.path.join(docker_root, 'overlay2'),
        'overlay2_l': os.path.join(docker_root, 'overlay2', 'l'),
        'layer_db': os.path.join(docker_root, 'image', 'overlay2', 'layerdb', 'sha256')
    }

def read_layer_file(filepath: str) -> Optional[str]:
    """Safely read a layer info file."""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return f.read().strip()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return None

def _recursive_find_layer(overlay2_path: str, layer_id: str, max_depth: int = 3) -> Optional[str]:
    """Recursively search for a layer directory by ID, but limit depth to avoid excessive searching."""
    def _is_match(dir_name: str, target_id: str) -> bool:
        """Check if a directory name matches the target ID."""
        short_target = target_id[:12]
        return dir_name == target_id or dir_name == short_target or dir_name.startswith(short_target)
    
    base_name = os.path.basename(layer_id)
    current_depth = 0
    for root, dirs, _ in os.walk(overlay2_path):
        # Skip deep recursion
        depth = root[len(overlay2_path):].count(os.sep)
        if depth > max_depth:
            del dirs[:]
            continue
            
        # Look for exact or prefix matches
        for dir_name in dirs:
            if _is_match(dir_name, base_name):
                full_path = os.path.join(root, dir_name)
                if os.path.exists(full_path):
                    diff_path = os.path.join(full_path, 'diff')
                    if os.path.exists(diff_path):
                        return diff_path
                    return full_path
    return None

def find_layer_dirs(docker_root: str) -> Dict[str, List[str]]:
    """
    Find all layer directories in the overlay2 directory and map them to their identifiers.
    Returns a dictionary mapping layer IDs (both full and short) to directory paths.
    """
    paths = get_layer_paths(docker_root)
    layer_dirs = {}
    
    if os.path.exists(paths['overlay2']):
        # First scan the overlay2/l directory for symlinks
        if os.path.exists(paths['overlay2_l']):
            for entry in os.listdir(paths['overlay2_l']):
                link_path = os.path.join(paths['overlay2_l'], entry)
                if os.path.islink(link_path):
                    target = os.readlink(link_path)
                    if not os.path.isabs(target):
                        target = os.path.basename(target)
                    full_target = os.path.join(paths['overlay2'], target)
                    
                    # Map both the link name and target
                    if os.path.exists(full_target):
                        if entry not in layer_dirs:
                            layer_dirs[entry] = []
                        layer_dirs[entry].append(full_target)
                        
                        # Also map the target ID
                        if target not in layer_dirs:
                            layer_dirs[target] = []
                        if full_target not in layer_dirs[target]:
                            layer_dirs[target].append(full_target)
        
        # Scan the main overlay2 directory
        for entry in os.listdir(paths['overlay2']):
            dir_path = os.path.join(paths['overlay2'], entry)
            if not os.path.isdir(dir_path):
                continue
                
            # Look for diff directories
            diff_path = os.path.join(dir_path, 'diff')
            if os.path.exists(diff_path):
                if entry not in layer_dirs:
                    layer_dirs[entry] = []
                if dir_path not in layer_dirs[entry]:
                    layer_dirs[entry].append(dir_path)
    
        # Also scan the layerdb to map IDs to directories
        if os.path.exists(paths['layer_db']):
            for entry in os.listdir(paths['layer_db']):
                if len(entry) != 64:
                    continue
                    
                layer_path = os.path.join(paths['layer_db'], entry)
                if not os.path.isdir(layer_path):
                    continue
                
                # Get all possible IDs for this layer
                layer_ids = {entry}  # Start with the SHA256
                
                # Add the shortened version
                layer_ids.add(entry[:12])
                
                # Add cache ID
                cache_id = read_layer_file(os.path.join(layer_path, 'cache-id'))
                if cache_id:
                    layer_ids.add(cache_id)
                    layer_ids.add(cache_id[:12])
                    
                    # Try to find the actual directory
                    cache_dir = os.path.join(paths['overlay2'], cache_id)
                    if os.path.exists(cache_dir):
                        # Add mappings for all IDs
                        for id_value in layer_ids:
                            if id_value not in layer_dirs:
                                layer_dirs[id_value] = []
                            if cache_dir not in layer_dirs[id_value]:
                                layer_dirs[id_value].append(cache_dir)
                
                # Add chain ID
                chain_id = read_layer_file(os.path.join(layer_path, 'chain-id'))
                if chain_id:
                    layer_ids.add(chain_id)
                    layer_ids.add(chain_id[:12])
                    
                    # Try to find the actual directory
                    chain_dir = os.path.join(paths['overlay2'], chain_id)
                    if os.path.exists(chain_dir):
                        # Add mappings for all IDs
                        for id_value in layer_ids:
                            if id_value not in layer_dirs:
                                layer_dirs[id_value] = []
                            if chain_dir not in layer_dirs[id_value]:
                                layer_dirs[id_value].append(chain_dir)
                
                # Add mount ID
                mount_id = read_layer_file(os.path.join(layer_path, 'mount-id'))
                if mount_id:
                    layer_ids.add(mount_id)
                    layer_ids.add(mount_id[:12])
                    
                    # Try to find the actual directory
                    mount_dir = os.path.join(paths['overlay2'], mount_id)
                    if os.path.exists(mount_dir):
                        # Add mappings for all IDs
                        for id_value in layer_ids:
                            if id_value not in layer_dirs:
                                layer_dirs[id_value] = []
                            if mount_dir not in layer_dirs[id_value]:
                                layer_dirs[id_value].append(mount_dir)
    
    return layer_dirs

def resolve_layer_location(docker_root: str, layer_id: str) -> str:
    """
    Resolve the location of a layer by its ID.
    """
    print(f"\nResolving location for layer: {layer_id}")
    paths = get_layer_paths(docker_root)
    
    # Clean up layer ID - remove sha256: prefix if present
    if layer_id.startswith('sha256:'):
        layer_id = layer_id[7:]
    
    print(f"Checking layer paths...")
    for path_type, path in paths.items():
        print(f"Checking {path_type}: {path}")
        if not os.path.exists(path):
            print(f"Path does not exist: {path}")
            continue
            
    # First try direct lookup in overlay2/l
    print("Checking overlay2/l for direct lookup...")
    overlay2_l_path = os.path.join(paths['overlay2_l'], layer_id[:12])
    if os.path.exists(overlay2_l_path):
        if os.path.islink(overlay2_l_path):
            target = os.readlink(overlay2_l_path)
            print(f"Found symlink to: {target}")
            if not os.path.isabs(target):
                target = os.path.join(paths['overlay2'], target)
            if os.path.exists(target):
                print(f"Found layer at: {target}")
                return target
            else:
                print(f"Target does not exist: {target}")
        else:
            print(f"Found non-symlink at {overlay2_l_path}")
            
    # Try recursive search in overlay2 directory
    print("\nTrying recursive search in overlay2...")
    result = _recursive_find_layer(paths['overlay2'], layer_id)
    if result:
        print(f"Found layer through recursive search: {result}")
        return result
        
    # Try checking the layer database
    print("\nChecking layer database...")
    layer_db_dir = os.path.join(paths['layer_db'], layer_id)
    if os.path.exists(layer_db_dir):
        print(f"Found layer info in database: {layer_db_dir}")
        # Read cache ID
        cache_id_path = os.path.join(layer_db_dir, 'cache-id')
        if os.path.exists(cache_id_path):
            with open(cache_id_path, 'r') as f:
                cache_id = f.read().strip()
                print(f"Found cache ID: {cache_id}")
                # Look up cache ID in overlay2
                cache_path = os.path.join(paths['overlay2'], cache_id)
                if os.path.exists(cache_path):
                    print(f"Found layer through cache ID: {cache_path}")
                    return cache_path
    
    raise ValueError(f"Could not resolve layer location for {layer_id}")
