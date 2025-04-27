#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    echo "Visit https://www.docker.com/products/docker-desktop for installation instructions."
    exit 1
fi

# Check if docker-compose is installed
if command -v docker-compose &> /dev/null; then
    echo "Starting Jekyll with docker-compose..."
    docker-compose up
else
    echo "docker-compose not found, using docker run instead..."
    docker run --rm \
      --volume="$PWD:/srv/jekyll" \
      --volume="$PWD/vendor/bundle:/usr/local/bundle" \
      -p 4000:4000 \
      -p 35729:35729 \
      jekyll/jekyll:4.2.2 \
      jekyll serve --livereload
fi

echo "Jekyll server is running at http://localhost:4000"