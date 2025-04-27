# Quick Start Guide

## Setting Up Your Local Environment

1. Clone the repository (if you haven't already):
   ```bash
   git clone https://github.com/mohitmishra786/inside-the-machine.git
   cd inside-the-machine
   ```

2. Install dependencies locally:
   ```bash
   bundle config set --local path 'vendor/bundle'
   bundle install
   ```

3. Run the Jekyll server locally:
   ```bash
   bundle exec jekyll serve
   ```

4. Access the site at http://localhost:4000

> **Note for macOS Users**: If you encounter issues with FFI or native extensions on macOS, please refer to the [macOS Setup Guide](MACOS_SETUP.md) for detailed troubleshooting steps.

### Alternative: Using Docker (Recommended for macOS)

To avoid dependency issues, especially on macOS, you can use Docker:

```bash
docker run --rm \
  --volume="$PWD:/srv/jekyll" \
  --volume="$PWD/vendor/bundle:/usr/local/bundle" \
  -p 4000:4000 \
  jekyll/jekyll:4.2.2 \
  jekyll serve
```

## Adding a New Chapter

### Option 1: Using the Script (Recommended)

1. Run the chapter creation script:
   ```bash
   ruby create_chapter.rb
   ```
   or
   ```bash
   ./create_chapter.sh
   ```

2. Follow the prompts to enter chapter number, title, and part number

3. Edit the newly created file in the `_chapters` directory

### Option 2: Manual Creation

1. Copy the template from `_chapters/chapter-template.md`

2. Create a new file in the `_chapters` directory with the naming convention:
   ```
   chapter-XX-name-of-chapter.md
   ```

3. Edit the front matter and content as needed

## Pushing Updates to GitHub

1. Commit your changes:
   ```bash
   git add .
   git commit -m "Add Chapter X: Chapter Title"
   ```

2. Push to GitHub:
   ```bash
   git push origin main
   ```

3. GitHub Actions will automatically build and deploy your site

## Checking Build Status

You can check the status of your GitHub Pages deployment in the Actions tab of your GitHub repository.

## For More Information

See the full [WORKFLOW.md](WORKFLOW.md) document for detailed instructions and best practices.