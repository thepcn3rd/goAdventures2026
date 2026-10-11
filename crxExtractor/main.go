package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CRX file magic numbers
const (
	crxMagic = "Cr24"
)

type Configuration struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Prod         string `json:"prod"`
	ProdChannel  string `json:"prodchannel"`
	UserAgent    string `json:"useragent"`
	ProdVersion  string `json:"prodversion"`
	AcceptFormat string `json:"acceptformat"`
}

func (c *Configuration) CreateConfig(f string) error {
	// Reference: https://chromium.googlesource.com/experimental/chromium/src/+/b0a22f04854dbb16407c58a69589d64d32204e09/chrome/common/omaha_query_params/omaha_query_params.h
	c.OS = "linux"            // mac, win, android, cros (Chrome OS), linux
	c.Arch = "x86-64"         // x86-64, x86-32, arm, arm64, mips
	c.Prod = "chromium"       // chrome, chromecrx, chromiumcrx, and unknown
	c.ProdChannel = "unknown" // stable, beta, dev, canary
	c.ProdVersion = "120.0.0" // Version of Chrome to Emulate
	c.AcceptFormat = "crx2,crx3"
	c.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	jsonData, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}

	err = os.WriteFile(f, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (c *Configuration) SaveConfig(f string) error {
	jsonData, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}

	err = os.WriteFile(f, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (c *Configuration) LoadConfig(cPtr string) error {
	configFile, err := os.Open(cPtr)
	if err != nil {
		return err
	}
	defer configFile.Close()
	decoder := json.NewDecoder(configFile)
	if err := decoder.Decode(&c); err != nil {
		return err
	}

	return nil
}

// extractCRX extracts a CRX file to the output directory
func extractCRX(crxPath, outputDir string) error {
	f, err := os.Open(crxPath)
	if err != nil {
		return fmt.Errorf("failed to open CRX file: %w", err)
	}
	defer f.Close()

	// Read magic number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return fmt.Errorf("failed to read magic: %w", err)
	}
	if string(magic) != crxMagic {
		return fmt.Errorf("not a valid CRX file (bad magic: %q)", string(magic))
	}

	// Read version
	version := make([]byte, 4)
	if _, err := io.ReadFull(f, version); err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}
	versionNum := binary.LittleEndian.Uint32(version)
	fmt.Printf("CRX version: %d\n", versionNum)

	// Read header size (public key length + signature length in CRX2, or just header length in CRX3)
	headerSizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(f, headerSizeBytes); err != nil {
		return fmt.Errorf("failed to read header size: %w", err)
	}
	headerSize := binary.LittleEndian.Uint32(headerSizeBytes)
	fmt.Printf("Header size: %d bytes\n", headerSize)

	// Skip the header
	if _, err := f.Seek(int64(headerSize), io.SeekCurrent); err != nil {
		return fmt.Errorf("failed to skip header: %w", err)
	}

	// Read remaining bytes as zip
	zipData, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read zip data: %w", err)
	}

	// Create zip reader from bytes
	zipReader, err := zip.NewReader(strings.NewReader(string(zipData)), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %w", err)
	}

	// Extract each file
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for _, file := range zipReader.File {
		//fmt.Printf("Extracting: %s\n", file.Name)
		if err := extractZipFile(file, outputDir); err != nil {

			return fmt.Errorf("failed to extract %s: %w", file.Name, err)
		}
		// For some odd reason the _metadata directory is not getting the correct permissions, so we will set it here
		if file.Name == "_metadata/" {
			//fmt.Printf("Found it!!\n")
			// Change the permissions for the _metadata directory
			if err := os.Chmod(filepath.Join(outputDir, file.Name), 0755); err != nil {
				return fmt.Errorf("failed to set permissions for %s: %w", file.Name, err)
			}
		}
	}

	return nil
}

// extractZipFile extracts a single file from the zip archive
func extractZipFile(file *zip.File, outputDir string) error {
	// Sanitize the file path to prevent directory traversal
	cleanName := filepath.Clean(file.Name)
	if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
		return fmt.Errorf("invalid file path: %s", file.Name)
	}

	fpath := filepath.Join(outputDir, cleanName)

	if file.FileInfo().IsDir() {
		return os.MkdirAll(fpath, file.Mode())
	}

	if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
		return err
	}

	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	return err
}

// checksumFile computes the SHA-256 checksum of a single file
func checksumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// checksumAllFiles walks the directory and computes checksums for all files
func checksumAllFiles(dir string, f *os.File) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		sum, err := checksumFile(path)
		if err != nil {
			return fmt.Errorf("failed to checksum %s: %w", path, err)
		}

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "checksums.txt" {
			return nil // Skip the checksums file itself
		}
		f.WriteString(fmt.Sprintf("%s  %s\n", sum, relPath))
		return nil
	})
}

func writeCRX(destPath string, r io.Reader) error {
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, r); err != nil {
		return fmt.Errorf("failed to write CRX: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func DownloadCRXByID(extensionID, destPath, downloadURL, userAgent string) (string, error) {
	if extensionID == "" {
		return "", fmt.Errorf("extension ID is required")
	}

	updateURL := fmt.Sprintf(downloadURL, url.QueryEscape(extensionID))

	client := &http.Client{
		Timeout: 60 * time.Second,
		// Follow redirects (default), but cap the chain.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, updateURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}
	// The update endpoint sometimes gates responses on User-Agent.
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}

	// The endpoint returns either a CRX binary or an XML <updatecheck> response
	// (e.g. when no update is available). Detect the XML case by peeking.
	peek := make([]byte, 4)
	n, err := io.ReadFull(resp.Body, peek)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if n >= 4 && string(peek[:4]) == "Cr24" {
		// It's a CRX. Write the peeked bytes plus the rest.
		if err := writeCRX(destPath, io.MultiReader(strings.NewReader(string(peek[:n])), resp.Body)); err != nil {
			return "", err
		}
	} else {
		// Likely an XML response — read and report it.
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned non-CRX response (got %q...): %s",
			string(peek[:n]), truncate(string(body), 300))
	}

	return resp.Request.URL.String(), nil
}

func extractCRXFromFile(crxFile, outputDir string) error {
	fmt.Printf("Extracting %s to %s...\n\n", crxFile, outputDir)
	if err := extractCRX(crxFile, outputDir); err != nil {
		return fmt.Errorf("failed to extract CRX: %w", err)
	}
	// Set the permissions on the extracted files to be rwxr-xr-x (755) for directories and rw-r--r-- (644) for files
	if err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0755)
		}
		return os.Chmod(path, 0644)
	}); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	// Write the checksums to a file named checksums.txt in the output directory
	checksumFile := filepath.Join(outputDir, "checksums.txt")
	f, err := os.Create(checksumFile)
	if err != nil {
		return fmt.Errorf("failed to create checksums file: %w", err)
	}
	defer f.Close()
	f.WriteString("\nSHA-256 Checksums:\n")
	f.WriteString(strings.Repeat("-", 80))
	if err := checksumAllFiles(outputDir, f); err != nil {
		return fmt.Errorf("failed to compute checksums: %w", err)
	}
	return nil
}

const UpdateURLTemplate = "https://clients2.google.com/service/update2/crx?response=redirect&os=linux&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&prod=chromiumcrx&prodchannel=unknown&prodversion=120.0.0&acceptformat=crx2,crx3&x=id%%3D%s%%26uc"

func buildChromeCRXURL(c Configuration) string {
	base := "https://clients2.google.com/service/update2/crx"

	// Preserve exact order — do NOT use url.Values (it sorts alphabetically)
	params := []string{
		"response=redirect",
		"os=" + c.OS,
		"arch=" + c.Arch,
		"os_arch=" + c.Arch,
		"nacl_arch=" + c.Arch,
		"prod=" + c.Prod,
		"prodchannel=" + c.ProdChannel,
		"prodversion=" + c.ProdVersion,
		"acceptformat=" + c.AcceptFormat,
		"x=id%%3D%s%%26uc",
	}

	return base + "?" + strings.Join(params, "&")
}

func main() {
	ConfigPtr := flag.String("config", "config.json", "Path to configuration file")
	FilePtr := flag.String("file", "", "Path to CRX file")
	ExtIDPtr := flag.String("id", "", "Extension ID (used to construct update URL)")
	OutputPtr := flag.String("output", "extracted", "Output directory for extracted files")
	flag.Parse()

	var config Configuration
	configFile := *ConfigPtr
	log.Println("Loading the following config file: " + configFile + "\n")
	if err := config.LoadConfig(configFile); err != nil {
		config.CreateConfig(configFile)
		log.Fatalf("Created %s, modify the file to customize how the tool functions.\n", configFile)
	}

	outputDir := *OutputPtr
	crxFile := *FilePtr
	extID := *ExtIDPtr
	if crxFile == "" && len(extID) == 0 {
		fmt.Fprintf(os.Stderr, "Error: --file is required OR --id is required\n")
		os.Exit(1)
	} else if len(extID) == 0 && len(crxFile) > 0 {
		fmt.Printf("Extracting CRX from file: %s\n", crxFile)
		outputDir = strings.TrimSuffix(filepath.Base(crxFile), filepath.Ext(crxFile)) + "_" + outputDir + "_" + time.Now().Format("20060102_1504")
		if err := extractCRXFromFile(crxFile, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else if len(extID) > 0 {
		urlPath := buildChromeCRXURL(config)
		fmt.Printf("Downloading CRX from: %s\n", urlPath)
		crxFile = extID + "_temp" + "_" + time.Now().Format("20060102_1504") + ".crx"
		url, err := DownloadCRXByID(extID, crxFile, urlPath, config.UserAgent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		info, _ := os.Stat(crxFile)
		fmt.Printf("Downloaded %s (%d bytes)\n  from: %s\n", crxFile, info.Size(), url)
		fmt.Printf("Extracting CRX from file: %s\n", crxFile)
		outputDir = strings.TrimSuffix(filepath.Base(crxFile), filepath.Ext(crxFile)) + "_" + outputDir + "_" + time.Now().Format("20060102_1504")
		if err := extractCRXFromFile(crxFile, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Unable to use an extension ID and a crx path at the same time. Please use one or the other.\n")
	}
}
