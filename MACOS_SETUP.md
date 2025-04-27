# macOS Setup Guide for Jekyll

## Fixing FFI and Native Extension Issues

If you encounter errors like `LoadError: cannot load such file -- ffi_c` when running Jekyll on macOS, follow these steps:

### Step 1: Install or Update Xcode Command Line Tools

```bash
xcode-select --install
```

If you already have it installed, make sure it's up to date.

### Step 2: Install Ruby with Homebrew

MacOS comes with Ruby pre-installed, but it's better to use a version manager like rbenv or use Homebrew:

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Ruby
brew install ruby
```

After installation, add the Ruby path to your shell configuration file (.zshrc or .bash_profile):

```bash
echo 'export PATH="/usr/local/opt/ruby/bin:/usr/local/lib/ruby/gems/3.0.0/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Note: The path might be different depending on the Ruby version. Check the output of the brew install command.

### Step 3: Clean and Reinstall Gems

```bash
# Remove the vendor directory
rm -rf vendor/

# Clear bundler cache
bundle clean --force

# Reinstall gems
bundle config set --local path 'vendor/bundle'
bundle install
```

### Step 4: Install Specific FFI Version

If you're still having issues, try installing a specific version of FFI:

```bash
bundle add ffi -v "1.15.5"
bundle update
```

### Step 5: Install Jekyll Directly

If bundler is still causing issues, you can try installing Jekyll directly:

```bash
gem install jekyll
jekyll serve
```

## Alternative Approach: Using Docker

If you continue to face issues with the native setup, consider using Docker:

1. Install Docker Desktop for Mac from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)

2. Run Jekyll using the official Jekyll Docker image:

```bash
docker run --rm \
  --volume="$PWD:/srv/jekyll" \
  --volume="$PWD/vendor/bundle:/usr/local/bundle" \
  -p 4000:4000 \
  jekyll/jekyll:4.2.2 \
  jekyll serve
```

This will start a Jekyll server inside a Docker container, avoiding any native dependency issues on your Mac.

## Specific Solution for M1/M2 Macs

If you're using an Apple Silicon Mac (M1, M2, etc.), you might need additional steps:

```bash
arch -x86_64 gem install ffi
arch -x86_64 bundle install
arch -x86_64 bundle exec jekyll serve
```

Or use the arch command with the Docker approach:

```bash
arch -x86_64 docker run --rm \
  --volume="$PWD:/srv/jekyll" \
  --volume="$PWD/vendor/bundle:/usr/local/bundle" \
  -p 4000:4000 \
  jekyll/jekyll:4.2.2 \
  jekyll serve
```