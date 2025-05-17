"""
Utility functions for the Docker forensics tool.
"""

import os

def normalize_path(*paths):
    """Normalize path separators for the current OS."""
    return os.path.join(*[str(path).replace('/', os.sep).replace('\\', os.sep) for path in paths])
