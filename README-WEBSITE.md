# Inside the Machine - Book Website

This is the Jekyll-based website for the book "Inside the Machine: A Practical Approach to Reverse Engineering for Developers".

## Features

- Minimalist design focused on readability
- Dark/light mode toggle
- Mobile-responsive layout
- Syntax highlighting for code blocks
- Easy navigation between chapters

## Local Development

### Prerequisites

- Ruby (version 2.5.0 or higher)
- RubyGems
- GCC and Make

### Setup

1. Install Jekyll and Bundler:
   ```
   gem install jekyll bundler
   ```

2. Clone this repository:
   ```
   git clone https://github.com/mohitmishra786/inside-the-machine.git
   cd inside-the-machine
   ```

3. Install dependencies:
   ```
   bundle install
   ```

4. Start the local server:
   ```
   bundle exec jekyll serve
   ```

5. Open your browser and visit: `http://localhost:4000`

## Adding Content

### Adding a New Chapter

1. Create a new Markdown file in the `_chapters` directory
2. Add the following front matter:
   ```yaml
   ---
   layout: chapter
   title: Chapter Title
   part: Part X: Part Title
   order: X (chapter number)
   ---
   ```
3. Add your chapter content in Markdown format

## Deployment

This site is designed to be deployed on GitHub Pages. Simply push changes to the main branch, and GitHub will automatically build and deploy the site.

## Customization

- Colors and theme variables can be modified in `assets/css/styles.scss`
- Layout templates are in the `_layouts` directory
- Reusable components are in the `_includes` directory

## License

This website is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.