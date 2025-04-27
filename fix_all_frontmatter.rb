#!/usr/bin/env ruby

# Process all chapter files
Dir.glob('_chapters/chapter-*.md').each do |file|
  puts "Processing #{file}..."
  
  # Read file content
  content = File.read(file)
  
  # Check if it starts with front matter
  if content.start_with?('---')
    # Split by front matter delimiters
    parts = content.split('---', 3)
    
    if parts.size >= 3
      # First part is empty (before first ---)
      # Second part is the front matter
      # Third part is the content after front matter
      
      # Clean up front matter by removing empty lines
      front_matter = parts[1].lines.reject(&:empty?).join
      
      # Ensure titles with colons are properly quoted
      front_matter = front_matter.gsub(/^(title|part):\s+(.+)$/) do |line|
        key, value = $1, $2.strip
        if value.include?(':') && !value.start_with?('"') && !value.end_with?('"')
          "#{key}: \"#{value}\""
        else
          line
        end
      end
      
      # Reassemble the file
      fixed_content = "---\n#{front_matter}---\n#{parts[2]}"
      
      # Write back to the file
      File.write(file, fixed_content)
      puts "  Fixed front matter in #{file}"
    else
      puts "  Warning: Could not parse front matter in #{file}"
    end
  else
    puts "  Warning: No front matter found in #{file}"
  end
end

puts "Done! Fixed all chapter files." 