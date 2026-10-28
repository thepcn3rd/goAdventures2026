package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	outputFile := flag.String("o", "", "output HTML file (default: stdout)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <markdown-file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	inputFile := args[0]
	markdown, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	html := generateHTMLDocument(string(markdown), inputFile)

	if *outputFile != "" {
		err = ioutil.WriteFile(*outputFile, []byte(html), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("HTML written to %s\n", *outputFile)
	} else {
		fmt.Print(html)
	}
}

func generateHTMLDocument(content, filename string) string {
	title := strings.TrimSuffix(filepath.Base(filename), ".md")

	html := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + escapeHTML(title) + `</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
			line-height: 1.6;
			color: #333;
			background-color: #f9f9f9;
			padding: 2rem;
		}
		main {
			max-width: 900px;
			margin: 0 auto;
			background-color: white;
			padding: 2rem;
			border-radius: 8px;
			box-shadow: 0 1px 3px rgba(0,0,0,0.1);
		}
		h1 {
			font-size: 2.5rem;
			margin: 2rem 0 1rem 0;
			color: #222;
			border-bottom: 3px solid #007acc;
			padding-bottom: 0.5rem;
		}
		h2 {
			font-size: 2rem;
			margin: 1.5rem 0 0.75rem 0;
			color: #444;
		}
		h3 {
			font-size: 1.5rem;
			margin: 1.25rem 0 0.5rem 0;
			color: #555;
		}
		h4, h5, h6 {
			font-size: 1.2rem;
			margin: 1rem 0 0.5rem 0;
			color: #666;
		}
		p {
			margin-bottom: 1rem;
			text-align: justify;
		}
		a {
			color: #007acc;
			text-decoration: none;
		}
		a:hover {
			text-decoration: underline;
		}
		code {
			background-color: #f4f4f4;
			padding: 0.2rem 0.4rem;
			border-radius: 3px;
			font-family: 'Courier New', Courier, monospace;
			font-size: 0.9em;
		}
		pre {
			background-color: #2d2d2d;
			color: #f8f8f2;
			padding: 1rem;
			border-radius: 5px;
			overflow-x: auto;
			margin: 1rem 0;
		}
		pre code {
			background-color: transparent;
			color: inherit;
			padding: 0;
			border-radius: 0;
		}
		ul, ol {
			margin: 1rem 0 1rem 2rem;
		}
		li {
			margin-bottom: 0.5rem;
		}
		table {
			border-collapse: collapse;
			width: 100%;
			margin: 1rem 0;
		}
		th, td {
			border: 1px solid #ddd;
			padding: 0.75rem;
			text-align: left;
		}
		th {
			background-color: #f5f5f5;
			font-weight: bold;
		}
		tr:nth-child(even) {
			background-color: #fafafa;
		}
		strong {
			font-weight: bold;
		}
		em {
			font-style: italic;
		}
	</style>
</head>
<body>
	<main>
` + parseMarkdown(content) + `	</main>
</body>
</html>`

	return html
}
