# Inside the Machine - Workflow Guide

## Quick Start

### Setting Up Your Environment

```bash
# Make the script executable
chmod +x setup_local.sh

# Run the setup script
./setup_local.sh
```

This script will:
- Check for Ruby and Bundler
- Configure Bundler for local installation
- Set up the appropriate Gemfile
- Install dependencies
- Provide macOS-specific fixes if needed
- Create helper scripts for development

### Running the Jekyll Server

```bash
./serve.sh
```

This will start the Jekyll server using the appropriate method for your system (native Ruby or Docker).

### Adding a New Chapter

```bash
./create_chapter.sh
```

Follow the prompts to create a new chapter file with the proper front matter.

### Deploying to GitHub Pages

```bash
# Prepare the site for GitHub Pages
./prepare_for_github.sh

# Commit and push your changes
git add .
git commit -m "Your commit message"
git push origin main
```

## Workflow Overview

1. **Initial Setup**: Run `./setup_local.sh` once to set up your environment
2. **Development**: 
   - Run `./serve.sh` to start the Jekyll server
   - Add chapters with `./create_chapter.sh`
   - Edit content in the `_chapters` directory
3. **Deployment**:
   - Run `./prepare_for_github.sh` to prepare for GitHub Pages
   - Commit and push to GitHub
   - GitHub Actions will automatically build and deploy your site

## Directory Structure

- `_chapters/`: Contains all chapter markdown files
- `Part-X-*/`: Contains supplementary materials for each part
- `_layouts/`: Jekyll layout templates
- `_includes/`: Jekyll include files
- `assets/`: Static assets (CSS, images, etc.)

## Troubleshooting

If you encounter issues:

1. For local development issues on macOS, try using Docker with `./serve.sh`
2. For GitHub Pages deployment issues, run `./prepare_for_github.sh` before pushing

## Scripts Reference

- `setup_local.sh`: Sets up your local development environment
- `serve.sh`: Starts the Jekyll server
- `create_chapter.sh`: Creates a new chapter file
- `prepare_for_github.sh`: Prepares the site for GitHub Pages deployment