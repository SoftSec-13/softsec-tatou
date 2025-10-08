# Fuzzing Seeds Summary

This document summarizes the comprehensive seed corpus added to the Tatou fuzzing infrastructure.

## Total Seeds: 480

### API Fuzzer Seeds: 145
Seeds targeting REST API endpoints with various attack patterns:

#### SQL Injection (30 seeds)
- Various SQL injection techniques including:
  - Authentication bypass attempts
  - UNION-based injections
  - Time-based blind injection
  - Boolean-based blind injection
  - Error-based injection
  - Stacked queries
  - Command execution attempts via SQL

#### Cross-Site Scripting / XSS (25 seeds)
- Script tag variations
- Event handler injections
- JavaScript protocol handlers
- Image/media tag exploits
- SVG/XML-based XSS
- Obfuscated and encoded variants

#### Command Injection (20 seeds)
- Shell metacharacter sequences
- Command chaining
- Subshell execution
- Backtick and $() syntax
- Path manipulation commands
- Reverse shell attempts

#### Path Traversal (15 seeds)
- Directory traversal sequences
- URL-encoded variants
- Windows and Unix paths
- File protocol handlers
- Double encoding attempts

#### Server-Side Request Forgery / SSRF (10 seeds)
- Localhost variations
- Cloud metadata endpoints
- Internal IP ranges
- IPv6 loopback
- File protocol access
- Dict/Gopher protocol exploitation

#### Authentication Bypass (15 seeds)
- Common default credentials
- Boolean manipulation
- Null values
- Integer boundary values
- JWT "none" algorithm
- Token manipulation

#### NoSQL Injection (10 seeds)
- MongoDB operator injection
- $ne, $gt, $regex operators
- Object injection
- Array manipulation

#### Valid/Edge Cases (10 seeds)
- Legitimate API requests
- Empty/null values
- Very long strings
- Whitespace-only inputs

#### Binary/Special Content (10 seeds)
- Null bytes
- Binary sequences
- CRLF injection
- Invalid JSON
- Nested structures
- Array inputs

### Inputs Fuzzer Seeds: 222
Seeds targeting input validation with focus on edge cases and exploits:

#### Path Traversal (30 seeds)
- Multiple depth levels
- Encoding variations
- Mixed separators
- Null byte injection
- File protocol attempts

#### Format String Exploits (20 seeds)
- %s, %x, %d, %n, %p specifiers
- Chained format strings
- Positional parameters
- Multiple specifier combinations

#### Buffer Overflow Patterns (15 seeds)
- Various lengths from 100 to 65K bytes
- NOP sleds
- INT3 patterns
- Repeated characters

#### Integer Overflow/Underflow (20 seeds)
- Boundary values for 32/64-bit integers
- Signed/unsigned limits
- Very large numbers
- Float edge cases

#### Null Bytes and Special Characters (20 seeds)
- Null byte variations
- URL-encoded nulls
- Newlines and carriage returns
- Tabs and control characters

#### Unicode Edge Cases (20 seeds)
- BOM markers
- Zero-width characters
- Right-to-left override (RTLO)
- Homoglyphs
- Extended emoji
- Cyrillic lookalikes

#### CRLF Injection (10 seeds)
- Header injection attempts
- HTTP response splitting
- Multiple encoding variants

#### Quote and Escape Characters (15 seeds)
- Single/double quotes
- Backslashes
- Backticks
- URL-encoded escapes
- HTML entities

#### Shell Metacharacters (15 seeds)
- Semicolons, pipes, ampersands
- Redirects and backticks
- Variable expansions
- Wildcards and brackets

#### Empty and Boundary Values (15 seeds)
- Empty strings
- Null/None/undefined
- Infinity values
- NaN values
- Empty containers

#### Control Characters (32 seeds)
- One seed for each ASCII control character (0x00-0x1F)

#### Whitespace Variations (10 seeds)
- Spaces, tabs, newlines
- Vertical tabs and form feeds
- Carriage returns
- Mixed whitespace

### Watermarking Fuzzer Seeds: 113
Seeds targeting PDF processing with focus on malformed and edge-case PDFs:

#### Valid PDFs with Variations (20 seeds)
- Multiple PDF versions (1.0-2.0)
- Minimal valid PDFs
- PDFs with metadata
- Multi-page documents
- PDFs with annotations
- Large documents (10+ pages)

#### Malformed PDFs (30 seeds)
- Missing headers/EOF markers
- Invalid version numbers
- Invalid object numbers
- Double-ended structures
- Empty dictionaries
- Invalid Length values
- Truncated PDFs
- Missing required objects
- Circular references
- Malformed xref tables

#### PDFs with Potential Exploits (20 seeds)
- JavaScript actions
- Launch actions
- URI actions
- Auto-actions
- Embedded files
- XFA forms
- Encryption headers
- Various compression filters

#### PDFs with XMP Metadata Variations (15 seeds)
- Minimal XMP
- Custom namespaces
- Watermark-specific metadata
- Malformed XML
- Empty XMP streams
- Very long XMP data
- Special characters in XMP
- Null bytes in metadata
- Duplicate entries

#### Edge Case PDFs (20 seeds)
- Empty PDFs
- Comments-only PDFs
- Huge object numbers
- Linearized PDFs
- Page labels
- Outlines and threads
- Extreme MediaBox values
- Info dictionaries
- Mixed line endings

#### Binary and Compressed Content (15 seeds)
- Binary stream data
- Random byte sequences
- Extremely long streams
- Wrong stream lengths
- Multiple streams
- Nested objects
- String escapes
- Hex strings

## Dictionary Files

### API Fuzzer Dictionary: 230 tokens
Comprehensive attack vectors and common API parameters

### Inputs Fuzzer Dictionary: 334 tokens  
Path traversal sequences, format strings, special characters, encoding variations

### Watermarking Fuzzer Dictionary: 379 tokens
PDF structure keywords, XMP metadata tags, encryption terms, attack vectors

## Verification

All fuzzers have been tested and verified to:
1. Load seeds correctly from corpus directories
2. Load dictionary tokens from dictionary files
3. Use seeds and dictionaries during fuzzing
4. Detect and report security patterns
5. Generate mutations combining seeds and dictionary tokens

## Usage

Run individual fuzzers:
```bash
python3 server/fuzz/api_fuzzer.py
python3 server/fuzz/inputs_fuzzer.py
python3 server/fuzz/watermarking_fuzzer.py
```

The fuzzers will automatically:
- Load all seeds from their respective corpus directories
- Load dictionary tokens
- Execute each seed
- Generate mutations using dictionary tokens
- Report detected attack patterns and anomalies
