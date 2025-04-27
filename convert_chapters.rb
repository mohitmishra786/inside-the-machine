#!/usr/bin/env ruby

require 'fileutils'

# Define the part titles
PART_TITLES = {
  'Part-1-Fundamentals' => 'Part 1: Reverse Engineering Fundamentals',
  'Part-2-Disassembly' => 'Part 2: Disassembly and Analysis',
  'Part-3-Dynamic-Analysis' => 'Part 3: Dynamic Analysis and Debugging',
  'Part-4-Advanced' => 'Part 4: Advanced Reverse Engineering',
  'Part-5-Applications' => 'Part 5: Practical Applications',
  'Part-6-Future' => 'Part 6: Future of Reverse Engineering'
}

# Create _chapters directory if it doesn't exist
FileUtils.mkdir_p('_chapters') unless Dir.exist?('_chapters')

# Process each part directory
PART_TITLES.each do |dir, title|
  next unless Dir.exist?(dir)
  
  # Get all markdown files in the directory
  files = Dir.glob("#{dir}/*.md").sort
  
  files.each do |file|
    # Extract chapter number and name from filename
    basename = File.basename(file, '.md')
    if basename =~ /chapter-(\d+)-(.*)/
      chapter_num = $1.to_i
      chapter_name = $2.gsub('-', ' ')
      
      # Read the file content
      content = File.read(file)
      
      # Extract the title from the first line if it starts with #
      title_from_content = content.lines.first.strip.sub(/^# /, '') if content.lines.first&.start_with?('# ')
      
      # Create the front matter
      front_matter = <<~YAML
      ---
      layout: chapter
      title: #{title_from_content || chapter_name.split.map(&:capitalize).join(' ')}
      part: #{title}
      order: #{chapter_num}
      ---
      
      YAML
      
      # Remove the first line (title) from content if we extracted it
      content = content.lines[1..-1].join if title_from_content
      
      # Create the new file in _chapters directory
      new_filename = "_chapters/chapter-#{chapter_num.to_s.rjust(2, '0')}-#{basename.sub(/chapter-\d+-/, '')}.md"
      
      # Write the new file with front matter
      File.write(new_filename, front_matter + content)
      
      puts "Converted #{file} to #{new_filename}"
    end
  end
end

puts "Conversion complete!"