from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(    name="docker-forensics-tool",
    version="0.1.0",
    author="lohdc",
    author_email="sod.brewmaster@gmail.com",
    description="A tool for extracting Docker images from forensic disk images",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lohdc/docker-forensics-tool",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "docker-forensics=docker_forensics.cli:main",
        ],
    },
)
