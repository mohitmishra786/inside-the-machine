#!/bin/bash

# This script prepares the Jekyll site for build

set -e

echo "Preparing Jekyll site for build..."

# Ensure the _sass directory exists
mkdir -p _sass

# Remove any Gemfile.lock to ensure fresh dependencies
if [ -f "Gemfile.lock" ]; then
  echo "Removing Gemfile.lock to ensure clean build"
  rm Gemfile.lock
fi

# Check and fix front matter in chapter files
if [ -f "fix_frontmatter.rb" ]; then
  echo "Running front matter fix script..."
  ruby fix_frontmatter.rb
fi

# Ensure assets directory exists
mkdir -p assets

# Log completion
echo "Jekyll site preparation completed successfully!" 