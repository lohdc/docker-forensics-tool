# Docker Forensics Tool Documentation

## Introduction
This document provides detailed information about the Docker Forensics Tool, its architecture, and how to use it effectively in digital forensics investigations.

## Architecture
The tool is organized into several modules:

- `core.py`: Main functionality for image extraction
- `docker.py`: Docker-specific functions
- `utils.py`: Utility functions
- `cli.py`: Command-line interface

## Technical Details

### Docker Image Structure
Docker images are stored using the overlay2 storage driver in the following structure:
```
/var/lib/docker/
├── image/
│   └── overlay2/
│       └── imagedb/
│           └── content/
│               └── sha256/
├── overlay2/
│   ├── l/
│   └── [layer-dirs]/
```

### Layer Extraction Process
1. Locate image metadata in the Docker image database
2. Parse layer information from the metadata
3. Find and extract each layer's contents
4. Create a proper Docker image archive structure

## Usage Examples
See the `examples/` directory for complete usage examples.
