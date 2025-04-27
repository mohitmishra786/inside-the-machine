#!/usr/bin/env ruby

require 'fileutils'

# Get chapter information from user
print "Enter chapter number (e.g., 01, 02): "
chapter_number = gets.chomp

print "Enter chapter title: "
chapter_title = gets.chomp

print "Enter part number (1-6): "
part_number = gets.chomp

# Create permalink-friendly title
permalink_title = chapter_title.downcase.gsub(/[^a-z0-9\s]/, '').gsub(/\s+/, '-')

# Create filename
filename = "_chapters/chapter-#{chapter_number}-#{permalink_title}.md"

# Check if file already exists
if File.exist?(filename)
  puts "Error: Chapter file already exists: #{filename}"
  exit 1
end

# Create chapter content
content = <<~CONTENT
---
layout: chapter
title: "#{chapter_title}"
chapter_number: #{chapter_number.to_i}
part: #{part_number}
permalink: /chapters/#{permalink_title}/
---

# #{chapter_title}

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

# Create the file
File.write(filename, content)

puts "Created new chapter: #{filename}"
puts "You can now edit this file to add your chapter content."