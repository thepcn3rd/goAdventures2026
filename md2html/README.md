# Markdown to HTML Converter

A simple, zero-dependency Go program that converts Markdown to HTML.

## Features

- **No external dependencies** - Uses only Go standard library
- **Supports common Markdown syntax:**
  - Headings (H1-H6): `# Heading`, `## Subheading`, etc.
  - Paragraphs: Plain text separated by blank lines
  - Bold: `**text**` → `<strong>text</strong>`
  - Italic: `*text*` → `<em>text</em>`
  - Inline code: `` `code` `` → `<code>code</code>`
  - Code blocks: Triple backticks
  - Unordered lists: Lines starting with `-` or `*`
  - Ordered lists: Lines starting with numbers (1. 2. 3. etc)
  - Links: `[text](url)` → `<a href="url">text</a>`
  - Tables: Pipe-delimited rows with alignment support
- **Complete HTML documents** - Includes styling and proper HTML structure
- **Headings get IDs** - Auto-generated from heading text for linking

## Installation

```bash
cd /path/to/project
go build -o md2html main.go markdown.go
```

## Usage

```bash
# Output to stdout
./md2html input.md

# Save to file
./md2html -o output.html input.md
```

## Examples

### Basic Markdown
```markdown
# My Document

This is a **bold** statement with *italic* text.

- Item 1
- Item 2
- Item 3
```

### Code Block
````markdown
```go
package main

func main() {
    println("Hello, World!")
}
```
````

### Table
```markdown
| Name  | Age | City      |
|-------|-----|-----------|
| Alice | 28  | New York  |
| Bob   | 35  | San Diego |
```

### Links
```markdown
[Click here](https://example.com) to visit the site.
```

## Building

```bash
go build -o md2html main.go markdown.go
```

## Testing

Convert the included sample file:
```bash
./md2html -o output.html tic-tac-toe-instructions.md
```

Then open `output.html` in a web browser to view the rendered HTML.

## Notes

- Flags must come before file arguments: `./md2html -o output.html input.md`
- The output includes responsive styling and a clean layout
- HTML special characters are properly escaped
- Code blocks are displayed with dark styling for readability
