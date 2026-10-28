package main

import (
	"regexp"
	"strings"
	"unicode"
)

func parseMarkdown(content string) string {
	lines := strings.Split(content, "\n")
	var html strings.Builder
	var i int

	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			i++
			continue
		}

		// Headings
		if level := getHeadingLevel(trimmed); level > 0 {
			text := strings.TrimPrefix(trimmed, strings.Repeat("#", level)+" ")
			id := slugify(text)
			html.WriteString("<h")
			html.WriteString(string(rune('0' + level)))
			html.WriteString(` id="`)
			html.WriteString(id)
			html.WriteString(`">`)
			html.WriteString(processInline(text))
			html.WriteString("</h")
			html.WriteString(string(rune('0' + level)))
			html.WriteString(">\n")
			i++
			continue
		}

		// Code blocks
		if strings.HasPrefix(trimmed, "```") {
			i = parseCodeBlock(&html, lines, i)
			continue
		}

		// Tables
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			i = parseTable(&html, lines, i)
			continue
		}

		// Lists
		if isListItem(trimmed) {
			i = parseList(&html, lines, i)
			continue
		}

		// Paragraphs
		i = parseParagraph(&html, lines, i)
	}

	return html.String()
}

func getHeadingLevel(line string) int {
	for i, ch := range line {
		if ch != '#' {
			if i > 0 && i < len(line) && line[i] == ' ' {
				return i
			}
			return 0
		}
	}
	return 0
}

func parseCodeBlock(html *strings.Builder, lines []string, start int) int {
	i := start + 1
	var code strings.Builder

	for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
		if code.Len() > 0 {
			code.WriteString("\n")
		}
		code.WriteString(lines[i])
		i++
	}

	html.WriteString("<pre><code>")
	html.WriteString(escapeHTML(code.String()))
	html.WriteString("</code></pre>\n")

	return i + 1
}

func parseTable(html *strings.Builder, lines []string, start int) int {
	headers := parseTableRow(lines[start])
	if start+1 >= len(lines) {
		return start + 1
	}

	separator := strings.TrimSpace(lines[start+1])
	aligns := parseTableAlignments(separator)
	if len(aligns) == 0 {
		return start + 1
	}

	html.WriteString("<table>\n<thead>\n<tr>")
	for _, header := range headers {
		html.WriteString("<th>")
		html.WriteString(processInline(strings.TrimSpace(header)))
		html.WriteString("</th>")
	}
	html.WriteString("</tr>\n</thead>\n<tbody>\n")

	i := start + 2
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
			break
		}

		cells := parseTableRow(lines[i])
		html.WriteString("<tr>")
		for j, cell := range cells {
			align := ""
			if j < len(aligns) && aligns[j] != "" {
				align = ` style="text-align:` + aligns[j] + `"`
			}
			html.WriteString("<td")
			html.WriteString(align)
			html.WriteString(">")
			html.WriteString(processInline(strings.TrimSpace(cell)))
			html.WriteString("</td>")
		}
		html.WriteString("</tr>\n")
		i++
	}

	html.WriteString("</tbody>\n</table>\n")
	return i
}

func parseTableRow(line string) []string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "|") {
		line = line[1:]
	}
	if strings.HasSuffix(line, "|") {
		line = line[:len(line)-1]
	}
	return strings.Split(line, "|")
}

func parseTableAlignments(sep string) []string {
	cells := parseTableRow(sep)
	var aligns []string
	for _, cell := range cells {
		cell = strings.TrimSpace(cell)
		if cell == "" {
			continue
		}
		left := strings.HasPrefix(cell, ":")
		right := strings.HasSuffix(cell, ":")
		if left && right {
			aligns = append(aligns, "center")
		} else if right {
			aligns = append(aligns, "right")
		} else if left {
			aligns = append(aligns, "left")
		} else if strings.Count(cell, "-") > 0 {
			aligns = append(aligns, "")
		}
	}
	return aligns
}

func isListItem(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
		return true
	}
	// Check for ordered list
	parts := strings.SplitN(trimmed, ".", 2)
	if len(parts) == 2 && len(parts[0]) > 0 {
		for _, ch := range parts[0] {
			if !unicode.IsDigit(ch) {
				return false
			}
		}
		return len(parts[1]) > 0 && (parts[1][0] == ' ' || parts[1][0] == '\t')
	}
	return false
}

func parseList(html *strings.Builder, lines []string, start int) int {
	var items []string
	var ordered bool
	var i int

	firstTrimmed := strings.TrimLeft(lines[start], " \t")
	if strings.HasPrefix(firstTrimmed, "-") || strings.HasPrefix(firstTrimmed, "*") {
		ordered = false
	} else {
		ordered = true
	}

	for i = start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || !isListItem(trimmed) {
			break
		}

		var item string
		if ordered {
			parts := strings.SplitN(trimmed, ".", 2)
			if len(parts) == 2 {
				item = strings.TrimSpace(parts[1])
			}
		} else {
			if strings.HasPrefix(trimmed, "- ") {
				item = trimmed[2:]
			} else if strings.HasPrefix(trimmed, "* ") {
				item = trimmed[2:]
			}
		}

		items = append(items, item)
	}

	if ordered {
		html.WriteString("<ol type=\"1\">")
	} else {
		html.WriteString("<ul>")
	}

	for _, item := range items {
		html.WriteString("\n<li>")
		html.WriteString(processInline(item))
		html.WriteString("</li>")
	}

	if ordered {
		html.WriteString("\n</ol>")
	} else {
		html.WriteString("\n</ul>")
	}
	html.WriteString("\n")

	return i
}

func parseParagraph(html *strings.Builder, lines []string, start int) int {
	var para strings.Builder
	i := start

	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || isListItem(trimmed) || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "|") {
			break
		}

		if para.Len() > 0 {
			para.WriteString(" ")
		}
		para.WriteString(trimmed)
		i++
	}

	if para.Len() > 0 {
		html.WriteString("<p>")
		html.WriteString(processInline(para.String()))
		html.WriteString("</p>\n")
	}

	return i
}

func processInline(text string) string {
	// Process formatting markers and build HTML
	// First escape HTML, then process markdown formatting
	text = escapeHTML(text)

	// Links [text](url)
	linkRe := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	text = linkRe.ReplaceAllStringFunc(text, func(match string) string {
		parts := linkRe.FindStringSubmatch(match)
		if len(parts) == 3 {
			return `<a href="` + parts[2] + `">` + parts[1] + `</a>`
		}
		return match
	})

	// Bold **text**
	boldRe := regexp.MustCompile(`\*\*([^*]+)\*\*`)
	text = boldRe.ReplaceAllString(text, `<strong>$1</strong>`)

	// Italic *text*
	italicRe := regexp.MustCompile(`\*([^*]+)\*`)
	text = italicRe.ReplaceAllString(text, `<em>$1</em>`)

	// Inline code `text`
	codeRe := regexp.MustCompile("`([^`]+)`")
	text = codeRe.ReplaceAllString(text, `<code>$1</code>`)

	return text
}

func slugify(text string) string {
	text = strings.ToLower(text)
	slug := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(text, "-")
	slug = strings.Trim(slug, "-")
	return slug
}

func escapeHTML(text string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(text)
}
