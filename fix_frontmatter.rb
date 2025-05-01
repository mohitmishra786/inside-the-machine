#!/usr/bin/env ruby

# This script fixes YAML front matter in chapter files
# It ensures:
# 1. All chapter files have proper front matter
# 2. Values with colons are properly quoted

Dir.glob('_chapters/*.md').each do |file|
  puts "Processing #{file}..."
  content = File.read(file)
  
  # Check if file has front matter
  if content.start_with?('---')
    lines = content.split("\n")
    in_frontmatter = false
    frontmatter_end = 0
    
    lines.each_with_index do |line, index|
      if line.strip == '---'
        if !in_frontmatter
          in_frontmatter = true
        else
          frontmatter_end = index
          break
        end
      elsif in_frontmatter && frontmatter_end == 0
        # Inside front matter, check for values with colons that need quoting
        if line =~ /^\s*(title|part):\s+.*:.*/ && line !~ /^\s*(title|part):\s+".*".*/ && line !~ /^\s*(title|part):\s+'.*'.*/
          key, value = line.split(':', 2)
          lines[index] = "#{key}: \"#{value.strip}\""
          puts "  Fixed unquoted value with colon in line: #{line}"
        end
      end
    end
    
    # Write the file back
    File.write(file, lines.join("\n"))
  else
    puts "  Warning: No front matter found in #{file}"
  end
end

puts "Front matter fixing complete!" 