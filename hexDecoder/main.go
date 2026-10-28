package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Hex-to-ASCII character mappings for reference:
// %00 = NUL, %09 = TAB, %0a = LF, %0d = CR, %20 = SPACE, %21 = !, %22 = "
// %23 = #, %24 = $, %25 = %, %26 = &, %27 = ', %28 = (, %29 = ), %2a = *
// %2b = +, %2c = ,, %2d = -, %2e = ., %2f = /, %3a = :, %3b = ;, %3c = <
// %3d = =, %3e = >, %3f = ?, %40 = @, %5b = [, %5c = \, %5d = ], %5e = ^
// %5f = _, %60 = `, %7b = {, %7c = |, %7d = }, %7e = ~
// See: man ascii for complete ASCII table

func decodeHexChar(hexStr string) string {
	val, err := strconv.ParseInt(hexStr, 16, 8)
	if err != nil {
		return "%" + hexStr
	}
	return string(rune(val))
}

func isASCIIPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

func formatHexdump(data string) string {
	bytes := []byte(data)
	var result strings.Builder

	for i := 0; i < len(bytes); i += 16 {
		// Offset
		result.WriteString(fmt.Sprintf("%08x  ", i))

		// Hex values (first 8 bytes)
		end := i + 16
		if end > len(bytes) {
			end = len(bytes)
		}

		for j := i; j < end; j++ {
			if j == i+8 {
				result.WriteString(" ")
			}
			result.WriteString(fmt.Sprintf("%02x ", bytes[j]))
		}

		// Padding for missing bytes
		remaining := 16 - (end - i)
		for k := 0; k < remaining; k++ {
			if (end + k) == i+8 {
				result.WriteString(" ")
			}
			result.WriteString("   ")
		}

		result.WriteString(" |")

		// ASCII representation
		for j := i; j < end; j++ {
			b := bytes[j]
			if isASCIIPrintable(b) {
				result.WriteString(string(b))
			} else {
				result.WriteString(".")
			}
		}

		result.WriteString("|\n")
	}

	return result.String()
}

func main() {
	unsafe := flag.Bool("unsafe", false, "Output raw decoded text instead of hexdump")
	flag.Parse()
	args := flag.Args()

	var input *os.File
	var err error

	if len(args) == 0 {
		// Read from stdin if no file argument provided
		input = os.Stdin
	} else {
		// Read from file if argument provided
		input, err = os.Open(args[0])
		if err != nil {
			log.Fatalf("Error opening file: %v", err)
		}
		defer input.Close()
	}

	scanner := bufio.NewScanner(input)
	// Regex to match %XX where XX is a hex digit
	hexRegex := regexp.MustCompile(`%([0-9A-Fa-f]{2})`)

	var allDecoded strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		// Replace all %XX patterns with their ASCII equivalents
		decoded := hexRegex.ReplaceAllStringFunc(line, func(match string) string {
			hexStr := match[1:] // Remove the '%' prefix
			return decodeHexChar(hexStr)
		})

		if *unsafe {
			fmt.Println(decoded)
		} else {
			allDecoded.WriteString(decoded)
			allDecoded.WriteString("\n")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	if !*unsafe {
		fmt.Print(formatHexdump(allDecoded.String()))
	}
}
