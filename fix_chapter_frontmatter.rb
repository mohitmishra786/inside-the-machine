#!/usr/bin/env ruby

require 'fileutils'

# Get all chapter files
chapter_files = Dir.glob('_chapters/chapter-*.md')

# Process each file
chapter_files.each do |file|
  puts "Processing #{file}..."
  
  # Read the file content
  content = File.read(file)
  
  # Fix the front matter
  if content.start_with?('---\n')
    # Split the content into front matter and body
    parts = content.split('---', 3)
    
    if parts.length >= 3
      front_matter = parts[1]
      body = parts[2]
      
      # Fix title with colons
      front_matter = front_matter.gsub(/^title: (.+?):.+$/) do |match|
        # Wrap the entire title in quotes
        full_title = $1.strip + $'.strip
        "title: \"#{full_title}\""
      end
      
      # Fix part with colons
      front_matter = front_matter.gsub(/^part: (.+?):.+$/) do |match|
        # Wrap the entire part in quotes
        full_part = $1.strip + $'.strip
        "part: \"#{full_part}\""
      end
      
      # Reassemble the file
      new_content = "---\n#{front_matter}---\n#{body}"
      
      # Write the fixed content back to the file
      File.write(file, new_content)
      puts "  Fixed front matter in #{file}"
    else
      puts "  Warning: Could not parse front matter in #{file}"
    end
  else
    puts "  Warning: No front matter found in #{file}"
  end
end

puts "\nDone! Fixed front matter in chapter files."