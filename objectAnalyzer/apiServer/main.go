package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"log"
	"net/http"
	"os"

	"common"

	_ "github.com/mattn/go-sqlite3"
)

/** Future Enhancements
1. Incorporate logging for the connecting IP Addresses and the actions taken
2. Move the API Key to a database table for better management
3. Pull a record of an object from the database after processing (Browser or API)
4. Pull multiple records from the database based on a CSV of objects (Browser or API)
5. API Pull List of IP Addresses to Block
6. Geolocation Lookup of IP Addresses being imported

Admin Functions
1. Add/Delete API Keys
2. Add/Delete Trusted IP Addresses that should be removed from what is being imported
3. Configure the Thresholds of Severity and Duration of Time to Block an IP Address based on scoring
4. Export an List of IP Addresses to Block
5. Process the pending_import table to the main threat intelligence table after validation
**/

func main() {
	ConfigPtr := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Load the Configuration file
	var config common.Configuration
	configFile := *ConfigPtr
	log.Println("Loading the following config file: " + configFile + "\n")
	if err := config.LoadConfig(configFile); err != nil {
		config.CreateConfig(configFile)
		log.Fatalf("Created %s, modify the file to customize how the tool functions.\n", configFile)
	}

	// Verify the TLS Certificate and Key files exist for the https server
	// Create the location of the keys folder
	dirPathTLS := filepath.Dir(config.TLSConfig)
	err := os.MkdirAll(dirPathTLS, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directories for TLS: %v", err)
	}
	// Does the tlsConfig.json  file exist in the keys folder
	TLSConfigFileExists := common.FileExists("/" + config.TLSConfig)
	//fmt.Println(configFileExists)
	if !TLSConfigFileExists {
		common.CreateCertConfigFile(config.TLSConfig)
		log.Fatalf("Created %s, modify the values to create the self-signed cert utilized", config.TLSConfig)
	}

	// Does the server.crt and server.key files exist in the keys folder
	crtFileExists := common.FileExists("/" + config.TLSCert)
	keyFileExists := common.FileExists("/" + config.TLSKey)
	if !crtFileExists || !keyFileExists {
		common.CreateCerts(config.TLSConfig, config.TLSCert, config.TLSKey)
		crtFileExists := common.FileExists("/" + config.TLSCert)
		keyFileExists := common.FileExists("/" + config.TLSKey)
		if !crtFileExists || !keyFileExists {
			fmt.Printf("Failed to create %s and %s files\n", config.TLSCert, config.TLSKey)
			os.Exit(0)
		}
	}

	if config.Debug {
		log.Printf("API Key from config: %s\n", config.APIKey)
		log.Printf("Database Path from config: %s\n", config.DBPath)
	}

	if len(config.APIKey) < 16 {
		log.Println("The API Key is too short.Recommended length of an API key is more than 64 characters")
		generatedKey := common.GenerateRandomString(64)
		log.Printf("Generated API Key: %s\n", generatedKey)
	}

	// Initialize the server with the configuration loaded from the config file
	server := &common.ServerConfig{
		Config: config,
	}

	// Initialize the database
	err = server.InitDatabase()
	if err != nil {
		log.Fatalf("database initialization failed: %v", err)
	}
	defer server.DB.Close()

	// Build appropriate directories for the web server
	common.CreateDirectory("static")
	common.CreateIndexHTML("static/index.html")

	// ** New Enhancement of Validating an API Key for each request ** API Key stored in the database ** Admin function to add the API Keys... API Key for adding trusted IP Addresses

	// Setup the API Routes for the Web Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("./static")).ServeHTTP(w, r)
	})

	mux.HandleFunc("/upload.html", server.HandleFileUploadHTML) // The HTML calls /api/importFile to do the actual file upload

	// API Endpoints
	mux.HandleFunc("/api/config", server.HandleConfig)         // This is optional at the moment...
	mux.HandleFunc("/api/import", server.HandleImport)         // Imports a single object to import
	mux.HandleFunc("/api/importJSON", server.HandleImportJSON) // Import multiple objects using JSON
	mux.HandleFunc("/api/importFile", server.HandleImportCSV)
	mux.HandleFunc("/api/verifyImport", server.HandleVerify) // Verifies that a single object exists in the pending_import table
	// Import IP Addresses that are trusted

	// Start the HTTP server
	log.Printf("Starting HTTP with TLS server on %s:%d", server.Config.Hostname, server.Config.Port)
	err = http.ListenAndServeTLS(fmt.Sprintf("%s:%d", server.Config.Hostname, server.Config.Port), server.Config.TLSCert, server.Config.TLSKey, mux)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
