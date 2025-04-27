#!/bin/bash

echo "Cleaning up unnecessary scripts..."

# List of scripts to remove
scripts_to_remove=(
  "fix_chapter_frontmatter.rb"
  "cleanup_chapters.rb"
  "create_chapter.rb"
  "fix_macos.sh"
  "make_scripts_executable.sh"
  "Gemfile.new"
  "Gemfile.github"
)

# Remove each script
for script in "${scripts_to_remove[@]}"; do
  if [ -f "$script" ]; then
    echo "  Removing $script..."
    rm "$script"
  else
    echo "  $script not found, skipping"
  fi
done

echo "Cleanup complete!"