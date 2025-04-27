#!/bin/bash

echo "Setting up local development environment..."

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Step 1: Check if Ruby is installed
echo "Step 1: Checking Ruby installation..."
if command_exists ruby; then
  ruby_version=$(ruby -v | cut -d' ' -f2)
  echo "  Ruby $ruby_version is installed"
else
  echo "  Error: Ruby is not installed. Please install Ruby before continuing."
  echo "  Visit https://www.ruby-lang.org/en/documentation/installation/ for instructions."
  exit 1
fi

# Step 2: Check if Bundler is installed
echo "Step 2: Checking Bundler installation..."
if command_exists bundle; then
  bundle_version=$(bundle -v | cut -d' ' -f3)
  echo "  Bundler $bundle_version is installed"
else
  echo "  Installing Bundler..."
  gem install bundler
fi

# Step 3: Configure Bundler for local installation
echo "Step 3: Configuring Bundler for local installation..."
bundle config set --local path 'vendor/bundle'
echo "  Bundler configured to install gems to vendor/bundle"

# Step 4: Create or update Gemfile for local development
echo "Step 4: Setting up Gemfile for local development..."

# Create a local development Gemfile
cat > Gemfile << EOL
source "https://rubygems.org"

gem "jekyll", "~> 4.2.0"

# Specify FFI version to avoid issues on macOS
gem "ffi", "~> 1.15.5"

# Add faraday-retry for GitHub Pages
gem "faraday-retry"

group :jekyll_plugins do
  gem "jekyll-feed", "~> 0.12"
  gem "jekyll-seo-tag", "~> 2.7"
end

# Windows and JRuby does not include zoneinfo files, so bundle the tzinfo-data gem
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", "~> 1.2"
  gem "tzinfo-data"
end

# Performance-booster for watching directories on Windows
gem "wdm", "~> 0.1.1", :platforms => [:mingw, :x64_mingw, :mswin]

# For Ruby 3.0+ compatibility
gem "webrick", "~> 1.7"
EOL

echo "  Created local development Gemfile"

# Step 5: Install dependencies
echo "Step 5: Installing dependencies..."
bundle install
echo "  Dependencies installed"

# Step 6: Check for macOS and offer fixes if needed
echo "Step 6: Checking for macOS-specific issues..."
if [[ "$(uname)" == "Darwin" ]]; then
  echo "  Detected macOS system"
  
  # Check if using Apple Silicon
  if [[ $(uname -m) == 'arm64' ]]; then
    echo "  Detected Apple Silicon (M1/M2)"
    echo "  Note: You may need to use Rosetta for some Ruby gems."
    echo "  If you encounter issues, try running: arch -x86_64 bundle exec jekyll serve"
  fi
  
  # Offer Docker as an alternative
  echo "  For macOS, Docker is recommended to avoid dependency issues."
  echo "  Would you like to set up Docker for Jekyll? (y/n)"
  read -r use_docker
  
  if [[ "$use_docker" =~ ^[Yy]$ ]]; then
    # Create docker-compose.yml
    cat > docker-compose.yml << EOL
version: '3'

services:
  jekyll:
    image: jekyll/jekyll:4.2.2
    command: jekyll serve --livereload
    ports:
      - 4000:4000
      - 35729:35729
    volumes:
      - .:/srv/jekyll
      - ./vendor/bundle:/usr/local/bundle
    environment:
      - JEKYLL_ENV=development
EOL
    
    echo "  Created docker-compose.yml"
    
    # Check if Docker is installed
    if command_exists docker; then
      echo "  Docker is installed. You can run Jekyll with: docker-compose up"
    else
      echo "  Docker is not installed. Please install Docker Desktop from:"
      echo "  https://www.docker.com/products/docker-desktop"
    fi
  else
    echo "  Skipping Docker setup. Using native Ruby/Jekyll."
  fi
fi

# Step 7: Create a helper script for adding new chapters
echo "Step 7: Creating helper script for adding new chapters..."

cat > create_chapter.sh << EOL
#!/bin/bash

# Get chapter information from user
read -p "Enter chapter number (e.g., 01, 02): " chapter_number
read -p "Enter chapter title: " chapter_title
read -p "Enter part number (1-6): " part_number

# Create permalink-friendly title
permalink_title=$(echo "$chapter_title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//' | sed 's/-$//')

# Create filename
filename="_chapters/chapter-${chapter_number}-${permalink_title}.md"

# Check if file already exists
if [ -f "$filename" ]; then
  echo "Error: Chapter file already exists: $filename"
  exit 1
fi

# Create chapter content
cat > "$filename" << CONTENT
---
layout: chapter
title: "$chapter_title"
chapter_number: ${chapter_number}
part: "Part ${part_number}"
permalink: /chapters/${permalink_title}/
---

# $chapter_title

## Introduction

Introduce the chapter here.

## Main Content Section 1

Write your content here.

### Subsection 1.1

More detailed content.

## Main Content Section 2

Continue with more content.

## Summary

Summarize the key points of the chapter.

## References

- Reference 1
- Reference 2
CONTENT

echo "Created new chapter: $filename"
echo "You can now edit this file to add your chapter content."
EOL

chmod +x create_chapter.sh
echo "  Created create_chapter.sh script"

# Step 8: Create a helper script for running Jekyll
echo "Step 8: Creating helper script for running Jekyll..."

cat > serve.sh << EOL
#!/bin/bash

# Check if Docker is installed and docker-compose.yml exists
if command -v docker &> /dev/null && [ -f "docker-compose.yml" ]; then
  echo "Starting Jekyll with Docker..."
  docker-compose up
else
  # Check if we're on macOS with Apple Silicon
  if [[ "$(uname)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
    echo "Detected macOS with Apple Silicon. Using Rosetta..."
    arch -x86_64 bundle exec jekyll serve --livereload
  else
    echo "Starting Jekyll with Ruby..."
    bundle exec jekyll serve --livereload
  fi
fi
EOL

chmod +x serve.sh
echo "  Created serve.sh script"

echo "\nSetup complete!"
echo "To start the Jekyll server, run: ./serve.sh"
echo "To create a new chapter, run: ./create_chapter.sh"
echo "To prepare for GitHub Pages deployment, run: ./prepare_for_github.sh"