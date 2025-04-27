# macOS Setup for "Inside the Machine"

## Quick Fix for FFI Issues

If you're experiencing the `LoadError: cannot load such file -- ffi_c` error, follow these steps:

### Option 1: Use the Fix Script (Recommended)

```bash
# Make the script executable
chmod +x fix_macos.sh

# Run the script
./fix_macos.sh
```

### Option 2: Use Docker (Most Reliable)

Docker provides the most reliable way to run Jekyll on macOS without dependency issues:

```bash
# Make the script executable
chmod +x serve.sh

# Run Jekyll with Docker
./serve.sh
```

### Option 3: Manual Fix

If you prefer to fix the issue manually:

1. Remove the vendor directory:
   ```bash
   rm -rf vendor/
   ```

2. Install a specific version of FFI:
   ```bash
   gem install ffi -v "1.15.5"
   ```

3. Reinstall gems:
   ```bash
   bundle config set --local path 'vendor/bundle'
   bundle install
   ```

4. Run Jekyll:
   ```bash
   bundle exec jekyll serve
   ```

## For Apple Silicon Macs (M1/M2)

If you're using an Apple Silicon Mac, you may need to use the x86_64 architecture:

```bash
arch -x86_64 gem install ffi
arch -x86_64 bundle install
arch -x86_64 bundle exec jekyll serve
```

## Detailed Troubleshooting

For more detailed troubleshooting steps, refer to [MACOS_SETUP.md](MACOS_SETUP.md).