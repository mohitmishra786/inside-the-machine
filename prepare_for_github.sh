#!/bin/bash

echo "Preparing site for GitHub Pages..."

# Step 1: Fix chapter front matter
echo "Step 1: Fixing chapter front matter..."
ruby fix_chapter_frontmatter.rb

# Step 2: Clean up template and sample chapters
echo "Step 2: Cleaning up template and sample chapters..."
ruby cleanup_chapters.rb

# Step 3: Use GitHub Pages specific Gemfile
echo "Step 3: Setting up GitHub Pages Gemfile..."
if [ -f "Gemfile.github" ]; then
  cp Gemfile.github Gemfile
  echo "  Copied Gemfile.github to Gemfile"
else
  echo "  Warning: Gemfile.github not found"
fi

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