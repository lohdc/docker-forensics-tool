# Docker Image Forensics Tool

A Python-based forensic tool for extracting and reconstructing Docker images from mounted forensic disk images (E01) containing Docker host filesystems.

## Project Structure
```
docker-forensics-tool/
├── docs/              # Documentation
├── examples/          # Example scripts
├── src/              # Source code
│   └── docker_forensics/
│       ├── __init__.py
│       ├── cli.py    # Command-line interface
│       ├── core.py   # Core functionality
│       ├── docker.py # Docker-specific functions
│       └── utils.py  # Utility functions
└── tests/            # Unit tests
```

## Overview

This tool is designed for digital forensics investigators who need to analyze Docker images from disk images without having Docker installed. It can extract Docker image layers and reconstruct them into a format that can be imported into Docker on another system. 

To find all the layers of a specific image (e.g., nginx:latest), Docker stores image metadata in:

 `/var/lib/docker/image/overlay2/imagedb/content/sha256`

The content of that file is JSON, containing:
```{
  "rootfs": {
    "diff_ids": [
      "sha256:layer1",
      "sha256:layer2",
      ...
    ]
  },
  ...
}
```
Match each `diff_id` (sha256 hash) to layer IDs in:

`/var/lib/docker/image/overlay2/layerdb/sha256/`

Each directory in there represents a layer and contains a `diff` file:

`/var/lib/docker/image/overlay2/layerdb/sha256/<layer>/diff`

Layers must be applied in the correct order (lowest to highest)


## Features

- Extract Docker images from mounted E01 forensic images
- Support for overlay2 storage driver
- Automatic detection of Docker root directory
- Reconstruction of image layers and metadata
- Generation of importable Docker image archives
- Cross-platform compatibility (Windows/Linux)
- Detailed progress reporting and error handling

## Prerequisites

- Python 3.6 or higher
- No Docker installation required
- Access to mounted E01 image containing Docker host filesystem

## Installation

1. Clone this repository:
```bash
git clone https://github.com/lohdc/docker-forensics-tool.git
cd docker-forensics-tool
```

2. Install the package:
```bash
pip install -e .
```

## Development Setup

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

2. Run tests:
```bash
pytest
```

## Usage

### Command Line Interface

```bash
docker-forensics <image_id> <mount_path> <output_dir>
```

Arguments:
- `image_id`: Docker image ID (sha256 hash without prefix)
- `mount_path`: Path where the E01 is mounted
- `output_dir`: Directory to save extracted image data

Example:
```bash
docker-forensics d69a5113cecd /mnt/evidence/disk001 ./output
```

### Python API

```python
from docker_forensics.core import extract_image_layers

# Extract a Docker image
extract_image_layers(
    image_id="d69a5113cecd",
    mount_path="/mnt/evidence/disk001",
    output_dir="./output"
)
```

## Output Structure

The tool creates the following structure in the output directory:

```
output/
└── image_[image_id]/
    ├── Dockerfile              # Reconstructed Dockerfile
    ├── image.tar              # Importable Docker image archive
    ├── image_metadata.json    # Original image metadata
    ├── manifest.json          # Docker image manifest
    ├── layer_0/              # Extracted layer contents
    │   └── layer.tar
    ├── layer_1/
    │   └── layer.tar
    └── ...
```

## Importing Extracted Images

To import an extracted image into Docker on another system:

```bash
docker load -i output/image_[image_id]/image.tar
```

## Technical Details

See [Technical Documentation](docs/technical.md) for detailed information about:
- Docker image structure
- Layer extraction process
- Filesystem layouts
- Error handling

## Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/CONTRIBUTING.md) for guidelines.

## License

[MIT License](LICENSE)

## Author

lohdc (sod.brewmaster@gmail.com)

## Acknowledgments

- Docker documentation and specifications
- Digital forensics community
