$projectPath = "c:\Users\loh_d\Documents\docker-forensics-tool"
Set-Location $projectPath

# Remove existing git repository if it exists
if (Test-Path ".git") {
    Remove-Item -Recurse -Force .git
}

# Initialize new repository
git init

# Configure git
git config --local user.name "lohdc"
git config --local user.email "sod.brewmaster@gmail.com"

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: Docker forensics tool"

# Add remote (create the GitHub repository first)
git remote add origin "https://github.com/lohdc/docker-forensics-tool.git"

# Set main branch
git branch -M main

Write-Host "Repository initialized successfully! Next steps:"
Write-Host "1. Create a new repository on GitHub at: https://github.com/new"
Write-Host "2. Then run: git push -u origin main"
