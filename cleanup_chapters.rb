#!/usr/bin/env ruby

require 'fileutils'

# Files to remove
files_to_remove = [
  '_chapters/chapter-template.md',
  '_chapters/sample-chapter.md'
]

# Remove each file
files_to_remove.each do |file|
  if File.exist?(file)
    puts "Removing #{file}..."
    FileUtils.rm(file)
  else
    puts "File not found: #{file}"
  end
end

puts "\nDone! Removed template and sample chapter files."