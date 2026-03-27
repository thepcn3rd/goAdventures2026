package main

/**
Create a go.work file to include the common module
go work init

go 1.25.5

use (
        .
        ../common
)

**/

// Query the pending_import table for new objects to process
// Create or update the entries in the object_intel table
// Create entries in the weekly object occurrences table

// Enhancements:
// Remove the files from the trusted folder after imported... (Completed)
// When handling imports to the object_intel table max is about 10k - create setting in config
// Create a trusted networks table because the objects may become cluttered...
// Create simple reports that can be seen through the API
// - object, object_type, occurrence_count SORT DESC LIMIT 100
// - object, object_type, occurrence_count > 100
// Added a database object of object_additionalInfo - Add to other handlers...

import (
	"common"
	"flag"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	ConfigPtr := flag.String("config", "config.json", "Path to configuration file")
	ImportsPtr := flag.Bool("i", false, "Process pending_imports")
	ImportsCSVPtr := flag.Bool("ic", false, "Load import sources from CSV")
	TrustedCSVPtr := flag.Bool("tc", false, "Load trusted sources from CSV")
	UpdateRiskScoresPtr := flag.Bool("u", false, "Update object risk scores")
	MarkTrustedPtr := flag.Bool("m", false, "Mark trusted objects in the object_intel table")
	RunAllPtr := flag.Bool("all", false, "Run all processing: import CSV, process imports, trusted CSV, mark trusted, update risk scores")
	flag.Parse()

	// Load the Configuration file
	var config common.Configuration
	configFile := *ConfigPtr
	log.Println("Loading the following config file: " + configFile + "\n")
	if err := config.LoadConfig(configFile); err != nil {
		config.CreateConfig(configFile)
		log.Fatalf("Created %s, modify the file to customize how the tool functions.\n", configFile)
	}

	if config.Debug {
		log.Printf("API Key from config: %s\n", config.APIKey)
		log.Printf("Database Path from config: %s\n", config.DBPath)
	}
	// Initialize the server with the configuration loaded from the config file
	server := &common.ServerConfig{
		Config: config,
	}

	// Initialize the database
	err := server.InitDatabase()
	if err != nil {
		log.Fatalf("database initialization failed: %v", err)
	}
	defer server.DB.Close()
	log.Println("Database initialized successfully.")

	// Check if any csv files are available to add to pending_import
	common.CreateDirectory(config.ImportCSVLocation)
	if *ImportsCSVPtr || *RunAllPtr {
		err = server.LoadImportObjectsFromCSV()
		if err != nil {
			log.Fatalf("processing import sources CSV failed: %v", err)
		}
		if config.Debug {
			log.Println("Import sources CSV processed successfully.")
		}
	}

	// Process the pending_import table to the main threat intelligence table after validation
	if *ImportsPtr || *RunAllPtr {
		err = server.ProcessPendingImports()
		if err != nil {
			log.Fatalf("processing pending imports failed: %v", err)
		}
		if config.Debug {
			log.Println("Pending imports processed successfully.")
		}
	}

	// Check if any csv files are available to process for trusted sources
	// Crashing...
	common.CreateDirectory(config.TrustedCSVLocation)
	if *TrustedCSVPtr || *RunAllPtr {
		err = server.LoadTrustedObjectsFromCSV()
		if err != nil {
			log.Fatalf("processing trusted sources CSV failed: %v", err)
		}
		if config.Debug {
			log.Println("Trusted sources CSV processed successfully.")
		}
	}

	// Query the trusted_objects and mark objects in object_intel as trusted
	if *MarkTrustedPtr || *RunAllPtr {
		err = server.MarkTrustedObjects()
		if err != nil {
			log.Fatalf("marking trusted objects failed: %v", err)
		}
		if config.Debug {
			log.Println("Trusted objects marked successfully.")
		}
	}

	// Update 1000 of the Objects in the object_intel table
	if *UpdateRiskScoresPtr || *RunAllPtr {
		err = server.UpdateObjectIntelRiskScores()
		if err != nil {
			log.Fatalf("updating object risk scores failed: %v", err)
		}
		if config.Debug {
			log.Println("Object risk scores updated successfully.")
		}
	}

	log.Println("Database connection closed.")
}
