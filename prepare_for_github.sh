#!/bin/bash

echo "Preparing site for GitHub Pages..."

# Step 1: Fix chapter front matter
echo "Step 1: Fixing chapter front matter..."

# Fix YAML front matter in chapter files
for file in _chapters/chapter-*.md; do
  if [ -f "$file" ]; then
    echo "  Processing $file..."
    # Create a temporary file
    tmp_file="${file}.tmp"
    
    # Process the file line by line
    in_frontmatter=false
    frontmatter_start=false
    
    while IFS= read -r line; do
      # Detect front matter boundaries
      if [[ "$line" == "---" ]]; then
        if [ "$in_frontmatter" = false ] && [ "$frontmatter_start" = false ]; then
          in_frontmatter=true
          frontmatter_start=true
        elif [ "$in_frontmatter" = true ]; then
          in_frontmatter=false
        fi
      fi
      
      # Fix title and part lines in front matter
      if [ "$in_frontmatter" = true ]; then
        if [[ "$line" =~ ^title:\ (.*):(.*)$ ]]; then
          # Title contains a colon, wrap in quotes
          title="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
          line="title: \"$title\""
        elif [[ "$line" =~ ^part:\ (.*):(.*)$ ]]; then
          # Part contains a colon, wrap in quotes
          part="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
          line="part: \"$part\""
        fi
      fi
      
      # Write the line to the temporary file
      echo "$line" >> "$tmp_file"
    done < "$file"
    
    # Replace the original file with the fixed one
    mv "$tmp_file" "$file"
  fi
done

# Step 2: Clean up template and sample chapters
echo "Step 2: Cleaning up template and sample chapters..."
for file in "_chapters/chapter-template.md" "_chapters/sample-chapter.md"; do
  if [ -f "$file" ]; then
    echo "  Removing $file..."
    rm "$file"
  fi
done

# Step 3: Use GitHub Pages specific Gemfile
echo "Step 3: Setting up GitHub Pages Gemfile..."

# Create a GitHub Pages compatible Gemfile
cat > Gemfile << EOL
source "https://rubygems.org"

# Use GitHub Pages gem for compatibility
gem "github-pages", group: :jekyll_plugins

# Add faraday-retry for GitHub Pages
gem "faraday-retry"

# Specify a compatible version of ffi for GitHub Actions
gem "ffi", "~> 1.15.0"

# Additional plugins
group :jekyll_plugins do
  gem "jekyll-feed", "~> 0.15"
  gem "jekyll-seo-tag", "~> 2.8"
end

# For Ruby 3.0+ compatibility
gem "webrick", "~> 1.7"
EOL

echo "  Created GitHub Pages compatible Gemfile"

# Step 4: Ensure the assets/css directory exists
echo "Step 4: Setting up CSS..."
mkdir -p assets/css

# For GitHub Pages, we need to make sure CSS is properly processed
if [ -f "assets/css/main.scss" ]; then
  # If SCSS exists, make sure it has front matter
  if ! grep -q "^---" "assets/css/main.scss"; then
    echo "---" > assets/css/main.scss.new
    echo "---" >> assets/css/main.scss.new
    cat assets/css/main.scss >> assets/css/main.scss.new
    mv assets/css/main.scss.new assets/css/main.scss
    echo "  Added front matter to assets/css/main.scss"
  else
    echo "  assets/css/main.scss already has front matter"
  fi
elif [ -f "assets/css/main.css" ]; then
  # If only CSS exists, create basic SCSS with front matter for GitHub Pages
  echo "---" > assets/css/main.scss
  echo "---" >> assets/css/main.scss
  echo "@import 'minima';" >> assets/css/main.scss 
  echo "" >> assets/css/main.scss
  cat assets/css/main.css >> assets/css/main.scss
  echo "  Created assets/css/main.scss with front matter"
  # We can remove the CSS file as we've migrated to SCSS
  rm assets/css/main.css
  echo "  Removed assets/css/main.css"
else
  # Create a basic SCSS file with front matter
  echo "---" > assets/css/main.scss
  echo "---" >> assets/css/main.scss
  echo "@import 'minima';" >> assets/css/main.scss
  echo "  Created basic assets/css/main.scss"
fi

# Step 5: Update _config.yml for GitHub Pages if needed
echo "Step 5: Checking _config.yml..."
if [ -f "_config.yml" ]; then
  # Check if baseurl is set correctly
  if ! grep -q "^baseurl:" "_config.yml"; then
    echo "baseurl: '/inside-the-machine'" >> _config.yml
    echo "  Added baseurl to _config.yml"
  fi
  
  # Check if url is set correctly
  if ! grep -q "^url:" "_config.yml"; then
    echo "url: 'https://mohitmishra786.github.io'" >> _config.yml
    echo "  Added url to _config.yml"
  fi
else
  echo "  Warning: _config.yml not found"
fi

echo "\nSite preparation complete!"
echo "Next steps:"
echo "1. Commit and push your changes to GitHub"
echo "2. GitHub Actions will build and deploy your site"
echo "3. Visit https://mohitmishra786.github.io/inside-the-machine to see your site"