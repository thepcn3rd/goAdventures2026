# hex_decoder

A safe command-line utility to decode hex-encoded characters (like `%7d`, `%7c`, etc.) back to their ASCII equivalents.

## Overview

`hex_decoder` reads text containing hex-encoded characters in the format `%XX` (where XX is a hexadecimal value) and converts them to their corresponding ASCII characters. By default, it displays the output in a safe `hexdump -C` format to allow inspection before viewing the raw decoded text.

## Features

- **Safe by default**: Output displayed as hexdump for secure inspection
- **Flexible input**: Read from files or stdin (pipe support)
- **ASCII conversion**: Decodes any valid hex character (0x00-0xFF)
- **Unsafe mode**: Explicit `--unsafe` flag for raw output
- **Cross-platform**: Works on Linux, macOS, and Windows

## Building

Requires Go 1.16 or later.

```bash
go build -o hex_decoder hex_decoder.go
```

Or with explicit output:

```bash
go build -o hex_decoder -v hex_decoder.go
```

## Usage

### Safe Mode (Default)

Display decoded output as a hexdump - safe for inspecting control characters and unknown data.

**From a file:**
```bash
./hex_decoder input.txt
```

**From stdin (pipe):**
```bash
cat input.txt | ./hex_decoder
echo "Hello %7d World %7c Test" | ./hex_decoder
```

**Output example:**
```
00000000  48 65 6c 6c 6f 20 7d 20  57 6f 72 6c 64 20 7c 20  |Hello } World | |
00000010  54 65 73 74 0a                                    |Test.|
```

### Unsafe Mode

Output raw decoded text. Use this flag only when you've verified the output is safe.

```bash
./hex_decoder --unsafe input.txt
cat input.txt | ./hex_decoder --unsafe
echo "Hello %7d World %7c" | ./hex_decoder --unsafe
```

**Output example:**
```
Hello } World |
Test
```

## Examples

### Example 1: URL-encoded characters

**Input file `urls.txt`:**
```
%2f path %2f to %2f file
```

**Safe mode output:**
```bash
$ ./hex_decoder urls.txt
00000000  2f 20 70 61 74 68 20 2f  20 74 6f 20 2f 20 66 69  |/ path / to / fi|
00000010  6c 65 0a                                          |le.|
```

**Unsafe mode output:**
```bash
$ ./hex_decoder --unsafe urls.txt
/ path / to / file
```

### Example 2: Special characters

**Input:**
```bash
echo "Special: %21 %40 %23 %24 %25 %26 %2a" | ./hex_decoder
```

**Output:**
```
00000000  53 70 65 63 69 61 6c 3a  20 21 20 40 20 23 20 24  |Special: ! @ # $|
00000010  20 25 20 26 20 2a 0a                              | % & *.|
```

### Example 3: Detecting control characters

When decoding untrusted data, control characters appear as `.` in the ASCII column:

**Input with control character (%00 = NUL):**
```bash
echo "Data%00Control" | ./hex_decoder
```

**Safe output shows it clearly:**
```
00000000  44 61 74 61 00 43 6f 6e  74 72 6f 6c 0a          |Data.Control.|
```

The `00` byte (NUL character) displays as `.` in the ASCII column, making it safe to inspect.

## Hex-to-ASCII Reference

Common hex-encoded characters:

| Hex | Char | Hex | Char | Hex | Char |
|-----|------|-----|------|-----|------|
| %00 | NUL  | %20 | SPACE | %40 | @ |
| %09 | TAB  | %21 | ! | %5b | [ |
| %0a | LF   | %23 | # | %5c | \ |
| %0d | CR   | %24 | $ | %5d | ] |
| %2f | /    | %25 | % | %7b | { |
| %2d | -    | %26 | & | %7c | \| |
| %2e | .    | %27 | ' | %7d | } |
| %3a | :    | %2a | * | %7e | ~ |

For a complete ASCII table, see `man ascii` on Linux/macOS or refer to the [ASCII Table](https://www.man7.org/linux/man-pages/man7/ascii.7.html).

## Safety

### Why Use Safe Mode by Default?

Decoding unknown hex data can produce:
- **Control characters** (0x00-0x1F, 0x7F) that could affect terminal behavior
- **Escape sequences** that might execute unintended actions
- **Non-printable bytes** that corrupt terminal output

### Verifying Output is Safe

1. **Review the hexdump**: Check the hex values column to identify any suspicious bytes
2. **Look for control characters**: 
   - `00` = NUL (null terminator)
   - `07` = BEL (bell/beep)
   - `1b` = ESC (escape - can trigger terminal sequences)
   - `7f` = DEL (delete)
3. **Only use `--unsafe` when confident**: After inspecting the hexdump

### Common Safe Characters

Control characters that are generally safe:
- `0a` (LF - newline)
- `0d` (CR - carriage return)
- `09` (TAB)
- `20` onwards (printable ASCII)

## Error Handling

- **Invalid hex values**: Malformed `%XX` patterns are left unchanged
- **Missing input file**: Error message displayed to stderr
- **Read errors**: Logged with error details

Example:
```bash
$ echo "Invalid %GG hex" | ./hex_decoder --unsafe
Invalid %GG hex
```

## Performance

The program processes data line-by-line and is suitable for:
- Large files (minimal memory overhead in unsafe mode)
- Real-time piped input
- Integration into shell scripts and pipelines

## Integration Examples

### Check what a file decodes to before using it

```bash
# Safely inspect first
./hex_decoder suspicious_file.txt

# Only use if verified
./hex_decoder --unsafe suspicious_file.txt > output.txt
```

### Use in pipelines

```bash
# Decode and redirect to file safely
curl https://example.com/data | ./hex_decoder > output.txt

# Then inspect with od
od -c output.txt
```

### Compare hex representations

```bash
# See both safe and unsafe side-by-side
echo "Data %7d encoded" | tee >(./hex_decoder) >(./hex_decoder --unsafe)
```

## Building for Distribution

Create release builds for different platforms:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o hex_decoder_linux_amd64

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o hex_decoder_darwin_amd64

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o hex_decoder_darwin_arm64

# Windows
GOOS=windows GOARCH=amd64 go build -o hex_decoder_windows_amd64.exe
```

## License

MIT License

## Contributing

Issues and pull requests welcome!
