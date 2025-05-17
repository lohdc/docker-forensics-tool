import os
import json
import pytest
from pathlib import Path
from docker_forensics.utils import normalize_path
from docker_forensics.docker import (
    find_docker_root,
    find_layer_dir,
    extract_layer_contents,
    create_dockerfile,
    create_manifest,
    create_docker_tarball
)
from docker_forensics.core import extract_image_layers

def test_normalize_path():
    # Test path normalization
    paths = ["dir1", "dir2", "file.txt"]
    normalized = normalize_path(*paths)
    assert isinstance(normalized, str)
    assert os.sep in normalized
    assert "dir1" in normalized
    assert "dir2" in normalized
    assert "file.txt" in normalized

def test_find_docker_root_with_root_dir(tmp_path):
    # Test finding Docker root with [root] directory
    root_dir = tmp_path / "[root]" / "var" / "lib" / "docker"
    root_dir.parent.parent.parent.mkdir()
    root_dir.parent.parent.mkdir()
    root_dir.parent.mkdir()
    root_dir.mkdir()
    
    docker_root = find_docker_root(str(tmp_path))
    assert docker_root == str(root_dir)

def test_find_docker_root_nonexistent():
    # Test handling of non-existent paths
    with pytest.raises(ValueError):
        find_docker_root("/nonexistent/path")

def test_find_layer_dir(tmp_path):
    # Create mock Docker root structure
    docker_root = tmp_path / "docker"
    image_path = docker_root / "image" / "overlay2" / "imagedb" / "content" / "sha256"
    image_path.mkdir(parents=True)
    
    # Create mock image metadata
    image_id = "test123"
    metadata = {
        "rootfs": {
            "diff_ids": ["sha256:layer1", "sha256:layer2"]
        }
    }
    
    with open(image_path / image_id, 'w') as f:
        json.dump(metadata, f)
    
    layer_info = find_layer_dir(str(docker_root), image_id)
    assert layer_info['metadata'] == metadata
    assert layer_info['layer_ids'] == metadata['rootfs']['diff_ids']

def test_create_dockerfile(tmp_path):
    metadata = {
        "config": {
            "Env": ["PATH=/usr/local/bin"],
            "ExposedPorts": {"80/tcp": {}},
            "Volumes": {"/data": {}},
            "Entrypoint": ["/bin/sh"],
            "Cmd": ["-c", "echo hello"]
        }
    }
    
    create_dockerfile(metadata, str(tmp_path))
    dockerfile_path = tmp_path / "Dockerfile"
    assert dockerfile_path.exists()
    
    content = dockerfile_path.read_text()
    assert "ENV PATH=/usr/local/bin" in content
    assert "EXPOSE 80/tcp" in content
    assert "VOLUME /data" in content
    assert 'ENTRYPOINT ["/bin/sh"]' in content
    assert 'CMD ["-c", "echo hello"]' in content

def test_create_manifest(tmp_path):
    image_id = "test123"
    layer_paths = ["/path/to/layer1.tar", "/path/to/layer2.tar"]
    
    manifest_path = create_manifest(image_id, layer_paths, str(tmp_path))
    assert os.path.exists(manifest_path)
    
    with open(manifest_path) as f:
        manifest = json.load(f)
        assert len(manifest) == 1
        assert manifest[0]["Config"] == f"{image_id}.json"
        assert len(manifest[0]["Layers"]) == len(layer_paths)

def test_extract_image_layers_mock(tmp_path, mocker):
    # Mock the Docker root finding
    mocker.patch(
        'docker_forensics.docker.find_docker_root',
        return_value=str(tmp_path / "docker")
    )
    
    # Mock layer info
    mock_layer_info = {
        'metadata': {'config': {}},
        'layer_ids': ['sha256:layer1', 'sha256:layer2'],
        'layerdb_path': str(tmp_path / "docker" / "layerdb")
    }
    mocker.patch(
        'docker_forensics.docker.find_layer_dir',
        return_value=mock_layer_info
    )
    
    # Mock layer extraction
    mocker.patch(
        'docker_forensics.docker.extract_layer_contents',
        return_value=str(tmp_path / "layer.tar")
    )
    
    output_dir = extract_image_layers("test123", str(tmp_path), str(tmp_path / "output"))
    assert os.path.exists(output_dir)
    assert os.path.exists(os.path.join(output_dir, "image_metadata.json"))
    assert os.path.exists(os.path.join(output_dir, "Dockerfile"))
    assert os.path.exists(os.path.join(output_dir, "manifest.json"))
