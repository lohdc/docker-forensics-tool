# Example script demonstrating how to use the Docker Forensics Tool
from docker_forensics.core import extract_image_layers

def main():
    # Example parameters
    image_id = "d69a5113cecd"  # The Docker image ID to extract
    mount_path = "/mnt/evidence/disk001"  # Path to mounted E01 image
    output_dir = "./extracted_images"  # Where to save the extracted data
    
    # Extract the Docker image
    extract_image_layers(image_id, mount_path, output_dir)

if __name__ == "__main__":
    main()
