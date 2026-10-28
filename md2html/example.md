# Markdown to HTML Converter - Feature Demo

## Introduction

Welcome to the **markdown to HTML converter**! This document demonstrates all the *supported features*.

## Text Formatting

You can use `**bold**` for strong emphasis and `*italic*` for regular emphasis. You can also use `inline code` like this.

## Code Blocks

Here's a Go code example:

```go
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
```

## Lists

### Unordered List
- First item
- Second item
- Third item

### Ordered List
1. First step
2. Second step
3. Third step

## Tables

| Feature | Status | Notes |
|---------|--------|-------|
| Headings | ✓ | All levels supported |
| Bold/Italic | ✓ | Complete |
| Code blocks | ✓ | With syntax class |
| Lists | ✓ | Ordered and unordered |
| Tables | ✓ | With alignment |
| Links | ✓ | Full support |

## Links

Visit the [Go website](https://golang.org) for more information.

## Multi-line Content

This is a paragraph that spans multiple lines
in the markdown source but will render as a single
paragraph in HTML due to how the parser handles
line continuations.

Paragraphs are separated by blank lines and each paragraph
gets its own `<p>` tag with proper spacing.

## Final Notes

This converter is designed to be **simple yet practical** for everyday markdown-to-HTML conversion tasks. No external dependencies means lightweight and fast compilation!
