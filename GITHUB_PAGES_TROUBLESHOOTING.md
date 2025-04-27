# GitHub Pages Troubleshooting Guide

## Common Issues and Solutions

### YAML Front Matter Errors

**Error Message:**
```
YAML Exception reading file: mapping values are not allowed in this context
```

**Solution:**
This usually happens when you have colons (`:`) in your YAML front matter values. Fix by:

1. Run the fix script:
   ```bash
   ./fix_chapter_frontmatter.rb
   ```

2. Or manually wrap values containing colons in quotes:
   ```yaml
   ---
   title: "Chapter 1: Introduction"
   part: "Part 1: Fundamentals"
   ---
   ```

### Faraday Retry Middleware Warning

**Warning Message:**
```
To use retry middleware with Faraday v2.0+, install `faraday-retry` gem
```

**Solution:**
1. Add the gem to your Gemfile:
   ```ruby
   gem "faraday-retry"
   ```

2. Run bundle install:
   ```bash
   bundle install
   ```

3. Or use the GitHub Pages preparation script:
   ```bash
   ./prepare_for_github.sh
   ```

### CSS Not Loading

**Symptom:** Site appears without styling

**Solution:**
Ensure your CSS files have proper front matter for Jekyll processing:

1. Make sure your main.scss file starts with:
   ```scss
   ---
   ---
   ```

2. Or run the preparation script:
   ```bash
   ./prepare_for_github.sh
   ```

### Wrong Chapter Count

**Symptom:** The progress bar shows incorrect chapter count

**Solution:**
Remove template and sample chapters:

1. Run the cleanup script:
   ```bash
   ruby cleanup_chapters.rb
   ```

2. Or manually delete:
   - `_chapters/chapter-template.md`
   - `_chapters/sample-chapter.md`

### Baseurl Issues

**Symptom:** Links are broken or resources not loading

**Solution:**
Ensure your `_config.yml` has the correct baseurl:

```yaml
baseurl: '/inside-the-machine'
url: 'https://mohitmishra786.github.io'
```

### Build Failures

If your GitHub Pages build is failing:

1. Check the GitHub Actions logs for specific error messages
2. Run the preparation script before pushing:
   ```bash
   ./prepare_for_github.sh
   ```
3. Test locally with:
   ```bash
   bundle exec jekyll build --safe
   ```

## Complete Reset

If you're experiencing multiple issues, you can perform a complete reset:

```bash
# Remove all generated files
rm -rf _site vendor .jekyll-cache .sass-cache

# Run the preparation script
./prepare_for_github.sh

# Commit and push
git add .
git commit -m "Reset and fix GitHub Pages issues"
git push origin main
```

## Getting Help

If you continue to experience issues:

1. Check the [GitHub Pages documentation](https://docs.github.com/en/pages)
2. Look for error messages in the GitHub Actions build logs
3. Test your site locally with the github-pages gem:
   ```bash
   bundle exec jekyll serve --config _config.yml
   ```