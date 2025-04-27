# Book Development Workflow

## Project Overview

"Inside the Machine" is a book about reverse engineering that is being developed incrementally. The book uses Jekyll and GitHub Pages for publishing.

## Current Status

- Total planned chapters: 17
- Currently available: Sample chapter(s) only
- The book is organized into 6 parts

## Local Development Setup

### Prerequisites

- Ruby (recommended version: 2.7.0 or newer)
- Git
- Docker (alternative option, especially recommended for macOS)

### Setting Up Local Environment

1. Clone the repository (if you haven't already):
   ```bash
   git clone https://github.com/mohitmishra786/inside-the-machine.git
   cd inside-the-machine
   ```

2. Install dependencies locally (without global installation):
   ```bash
   bundle config set --local path 'vendor/bundle'
   bundle install
   ```

3. Run the Jekyll server locally:
   ```bash
   bundle exec jekyll serve
   ```

4. Access the site at http://localhost:4000

### Alternative: Using Docker (Recommended for macOS)

To avoid dependency issues, especially on macOS, you can use Docker:

1. Make sure Docker is installed on your system

2. Run the provided script:
   ```bash
   ./serve.sh
   ```

   Or manually run Docker:
   ```bash
   docker run --rm \
     --volume="$PWD:/srv/jekyll" \
     --volume="$PWD/vendor/bundle:/usr/local/bundle" \
     -p 4000:4000 \
     jekyll/jekyll:4.2.2 \
     jekyll serve
   ```

3. Access the site at http://localhost:4000

### Troubleshooting macOS Issues

If you encounter issues on macOS, especially with FFI or native extensions:

1. Run the fix script:
   ```bash
   ./fix_macos.sh
   ```

2. For detailed troubleshooting steps, refer to [MACOS_SETUP.md](MACOS_SETUP.md)

## Adding New Chapters

1. Create a new markdown file in the `_chapters` directory with the following naming convention:
   ```
   chapter-XX-name-of-chapter.md
   ```
   Where XX is the chapter number (e.g., 01, 02, etc.)

2. Add the following front matter to the top of the file:
   ```yaml
   ---
   layout: chapter
   title: "Chapter Title"
   chapter_number: X
   part: Y
   permalink: /chapters/chapter-title/
   ---
   ```
   Replace X with the chapter number and Y with the part number (1-6).

3. Write your chapter content in Markdown format below the front matter.

## Updating the Book Progress

The about.md file automatically calculates the book progress based on the number of files in the `_chapters` directory compared to the total planned chapters (17).

## GitHub Workflow

### Regular Updates

1. Create a new branch for your changes:
   ```bash
   git checkout -b chapter-XX
   ```

2. Make your changes (add/edit chapters, update content, etc.)

3. Commit your changes:
   ```bash
   git add .
   git commit -m "Add Chapter XX: Chapter Title"
   ```

4. Push to GitHub:
   ```bash
   git push origin chapter-XX
   ```

5. Create a Pull Request on GitHub to merge your changes into the main branch

6. After review, merge the Pull Request

### Automated Deployment

The site is automatically deployed to GitHub Pages whenever changes are pushed to the main branch.

## Directory Structure

- `_chapters/`: Contains all chapter markdown files
- `Part-X-*/`: Contains supplementary materials for each part
- `_layouts/`: Jekyll layout templates
- `_includes/`: Jekyll include files
- `assets/`: Static assets (CSS, images, etc.)

## Tips for Maintaining the Book

1. Keep a consistent style across chapters
2. Regularly update the README.md with new information
3. Consider adding a CHANGELOG.md to track major updates
4. Use GitHub Issues to track planned chapters and features
5. Engage with readers through GitHub Discussions

## Publishing Updates

When you're ready to publish updates to your readers:

1. Ensure all changes are merged to the main branch
2. GitHub Pages will automatically build and deploy the site
3. Announce the update through GitHub Releases or other channels

## Troubleshooting

### Local Jekyll Issues

If you encounter issues with the local Jekyll server:

```bash
bundle update
bundle exec jekyll clean
bundle exec jekyll serve
```

### GitHub Pages Build Failures

Check the GitHub Actions tab in your repository to see build logs and error messages.