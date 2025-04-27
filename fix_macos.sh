#!/bin/bash

echo "Fixing Jekyll setup for macOS..."

# Remove the vendor directory
echo "Removing vendor directory..."
rm -rf vendor/

# Clear bundler cache
echo "Clearing bundler cache..."
bundle clean --force

# Check if using Apple Silicon
if [[ $(uname -m) == 'arm64' ]]; then
    echo "Detected Apple Silicon (M1/M2)..."
    echo "Installing FFI with x86_64 architecture..."
    arch -x86_64 gem install ffi
    echo "Reinstalling gems with x86_64 architecture..."
    arch -x86_64 bundle config set --local path 'vendor/bundle'
    arch -x86_64 bundle install
    echo "\nTo run Jekyll, use: arch -x86_64 bundle exec jekyll serve"
    echo "Or use the Docker method described in MACOS_SETUP.md"
 else
    echo "Installing a specific version of FFI..."
    gem install ffi -v "1.15.5"
    echo "Reinstalling gems..."
    bundle config set --local path 'vendor/bundle'
    bundle install
    echo "\nTo run Jekyll, use: bundle exec jekyll serve"
    echo "If you still encounter issues, please refer to MACOS_SETUP.md"
fi

echo "\nSetup complete! If you continue to have issues, consider using Docker:"
echo "./serve.sh"