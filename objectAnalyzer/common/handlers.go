package common

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Configuration struct {
	Hostname           string `json:"hostname"`
	Port               int    `json:"port"`
	DBPath             string `json:"dbPath"`
	TLSConfig          string `json:"tlsConfig"`
	TLSCert            string `json:"tlsCert"`
	TLSKey             string `json:"tlsKey"`
	APIKey             string `json:"apiKey"`
	Debug              bool   `json:"debug"`
	TrustedCSVLocation string `json:"trustedCSVDirectory"`
	ImportCSVLocation  string `json:"importCSVDirectory"`
	ArchiveCSVLocation string `json:"archiveCSVDirectory"`
}

type InsertPendingImportStruct struct {
	Object       string `json:"object"`
	ObjectType   string `json:"object_type"`
	Notes        string `json:"notes"`
	Source       string `json:"source"`
	TimeProvided string `json:"time_provided"`
	GeoRegion    string `json:"geo_region"`
	GeoCountry   string `json:"geo_country"`
	GeoOrg       string `json:"geo_org"`
	APIKey       string `json:"apiKey,omitempty"`
}

func (c *Configuration) CreateConfig(f string) error {
	c.Hostname = "localhost"
	c.Port = 9000
	c.DBPath = "../data/threatintel.sqlite"
	c.TLSConfig = "keys/tlsconfig.json"
	c.TLSCert = "keys/tls.crt"
	c.TLSKey = "keys/tls.key"
	c.APIKey = "changeThisAPIKeyToSomethingSecure" // This needs to be passed on each call
	c.Debug = false
	c.TrustedCSVLocation = "trustedCSV"
	c.ImportCSVLocation = "importCSV"
	c.ArchiveCSVLocation = "archiveCSV"

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

type ServerConfig struct {
	Config   Configuration // Each configuration may be differenct depending on the function
	DB       *sql.DB
	Mutex    sync.RWMutex
	InitOnce sync.Once
}

func CreateIndexHTML(folderDir string) {
	currentDir, _ := os.Getwd()
	newDir := currentDir + "/" + folderDir
	//cf.CheckError("Unable to get the working directory", err, true)
	if _, err := os.Stat(newDir); errors.Is(err, os.ErrNotExist) {
		// Output to File - Overwrites if file exists...
		f, err := os.Create(newDir)
		CheckError("Unable create file index.html "+currentDir, err, true)
		defer f.Close()
		f.Write([]byte(headerHTML()))
		f.Write([]byte("<h1>Yet Another Threat Intelligence Platform</h1>"))
		f.Write([]byte("<hr />"))
		f.Write([]byte("<p><a href=\"/upload.html\">Upload CSV File</a> with column headers of object, object_type, notes, source, and time.  Required columns are object and object_type.</p>"))
		f.Write([]byte(tailHTML()))
		f.Close()
	}
}

func headerHTML() string {
	hHTML := `<!DOCTYPE html>
			  <html lang="en">
  			  <head>
    			<meta charset="UTF-8" />
    			<meta name="viewport" content="width=device-width, initial-scale=1.0" />
    			<meta http-equiv="X-UA-Compatible" content="ie=edge" />
  			  </head>
  			  <body>`
	return hHTML
}

func tailHTML() string {
	tHTML := "</body></html>"
	return tHTML
}

func (s *ServerConfig) InitDatabase() error {
	var err error
	if s.Config.Debug {
		log.Printf("DB Path: %s\n", s.Config.DBPath)
	}
	s.DB, err = sql.Open("sqlite3", s.Config.DBPath)
	//s.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create pending_import table
	// Object types: ip, domain, url, hash
	_, err = s.DB.Exec(`
		CREATE TABLE IF NOT EXISTS pending_import (
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			object VARCHAR NOT NULL,  
			object_type VARCHAR NOT NULL,
			notes TEXT,
			source VARCHAR,
			geo_region VARCHAR,
			geo_country VARCHAR,
			geo_org VARCHAR,
			fidelity VARCHAR DEFAULT 'Low',
			time_imported TIMESTAMP NOT NULL,
			time_provided TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create pending_import table: %w", err)
	}
	if s.Config.Debug {
		log.Println("pending_import table created successfully or already exists")
	}
	// Create the Main Threat Intelligence Table
	_, err = s.DB.Exec(`
		CREATE TABLE IF NOT EXISTS object_intel (
			object VARCHAR NOT NULL PRIMARY KEY, 
			object_additionalInfo VARCHAR, 
			object_type VARCHAR NOT NULL,
			IPDecimal INTEGER,
			geo_region VARCHAR,
			geo_country VARCHAR,
			geo_org VARCHAR,
			geo_asn VARCHAR,
			notes TEXT,
			fidelity VARCHAR DEFAULT 'Low',
			first_seen TIMESTAMP NOT NULL,
			last_seen TIMESTAMP,
			occurrence_count INTEGER DEFAULT 1,
			risk_score INTEGER,
			risk_score_last_updated TIMESTAMP,
			confirmed_risk BOOLEAN DEFAULT FALSE,
			trusted BOOLEAN DEFAULT FALSE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create object_intel table: %w", err)
	}
	if s.Config.Debug {
		log.Println("object_intel table created successfully or already exists")
	}
	now := time.Now()
	year, week := now.ISOWeek()
	// The API server may not restart on a weekly basis, will need another script to run this also...
	// Create Weekly Table to Track Object Occurrences
	_, err = s.DB.Exec(`
		CREATE TABLE IF NOT EXISTS objects_` + fmt.Sprintf("%d_%d", week, year) + ` (
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			object VARCHAR NOT NULL,  
			object_additionalInfo VARCHAR,
			object_type VARCHAR NOT NULL,
			ipDecimal INTEGER,
			notes TEXT,
			source VARCHAR,
			fidelity VARCHAR DEFAULT 'Low',
			time_imported TIMESTAMP NOT NULL,
			time_provided TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create objects table: %w", err)
	}
	if s.Config.Debug {
		log.Println("objects table created successfully or already exists")
	}

	// Create the Table of Trusted Objects
	// Objects are ipv4, ipv4CIDR, ipv6, (ipv6CIDR Future)
	_, err = s.DB.Exec(`
		CREATE TABLE IF NOT EXISTS trusted_objects (
			object VARCHAR NOT NULL PRIMARY KEY,
			object_additionalInfo VARCHAR,  
			object_type VARCHAR NOT NULL,
			ipDecimal INTEGER DEFAULT 0,
			startIPDecimal INTEGER DEFAULT 0,
			endIPDecimal INTEGER DEFAULT 0,
			notes TEXT,
			source TEXT,
			time_imported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			occurrence_count INTEGER DEFAULT 1,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create trusted_objects table: %w", err)
	}
	if s.Config.Debug {
		log.Println("trusted_objects table created successfully or already exists")
	}

	return nil
}

func (s *ServerConfig) HandleFileUploadHTML(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, headerHTML())
	ufHTML := `<form enctype="multipart/form-data" action="/api/importFile" method="post">
      API Key for File Upload:&nbsp;
      <input type="password" name="apiKey" /><br />
      <input type="file" name="myFile" /><br />
      <input type="submit" value="Upload" />
    </form>`
	fmt.Fprint(w, ufHTML)
	fmt.Fprint(w, tailHTML())
}

func (s *ServerConfig) HandleConfig(w http.ResponseWriter, r *http.Request) {
	// Respond to GET Requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	// Remove the API Key before sending the config
	backupAPIKey := s.Config.APIKey
	s.Config.APIKey = ""

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.Config); err != nil {
		http.Error(w, "Failed to encode config", http.StatusInternalServerError)
		return
	}

	// Restore the API Key
	s.Config.APIKey = backupAPIKey
}

// Test by uploading a CSV file via the HTML form at /upload.html
// Added the validation of the API Key
func (s *ServerConfig) HandleImportCSV(w http.ResponseWriter, r *http.Request) {
	// Respond to POST Requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate API Key
	apiKey := r.FormValue("apiKey")
	if apiKey != s.Config.APIKey {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := r.ParseMultipartForm(10 << 20) // Limit upload size to 10MB
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("myFile")
	if err != nil {
		http.Error(w, "Failed to retrieve file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate MIME type
	contentType := handler.Header.Get("Content-Type")
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mimeType != "text/csv" {
		//fmt.Fprintf(w, "Uploaded File: %+v<br />", handler.Filename)
		fmt.Fprintf(w, "File Size: %+v<br />", handler.Size)
		fmt.Fprintf(w, "MIME Header: %+v<br /><br />", handler.Header)
		http.Error(w, "Invalid file type. Only CSV files are allowed. <a href='/upload.html'>Link to Upload</a>", http.StatusBadRequest)
		return
	}

	// Validate file extension is CSV (additional security)
	filename := handler.Filename
	if !strings.HasSuffix(strings.ToLower(filename), ".csv") {
		//fmt.Fprintf(w, "Uploaded File: %+v<br />", handler.Filename)
		fmt.Fprintf(w, "File Size: %+v<br />", handler.Size)
		fmt.Fprintf(w, "MIME Header: %+v<br /><br />", handler.Header)
		http.Error(w, "File must have .csv extension. <a href='/upload.html'>Link to Upload</a>", http.StatusBadRequest)
		return
	}

	//fmt.Fprintf(w, "Uploaded File: %+v<br />", handler.Filename)
	fmt.Fprintf(w, "File Size: %+v<br />", handler.Size)
	fmt.Fprintf(w, "MIME Header: %+v<br /><br />", handler.Header)
	fileBytes, err := io.ReadAll(file)
	CheckError("Unable to Read File Selected", err, true)

	// Verify the file is ASCII
	if !isASCII(fileBytes) {
		http.Error(w, "File contains non-ASCII characters. Please upload a valid CSV file. <a href='/upload.html'>Link to Upload</a>", http.StatusBadRequest)
		return
	}

	/**
	f, err := os.Create("./uploads/" + handler.Filename)
	CheckError("Unable create file to save output", err, true)
	defer f.Close()
	f.Write(fileBytes)
	fmt.Fprintf(w, "Successfully Uploaded File<br />")
	**/

	// Reset and parse as CSV
	reader := csv.NewReader(strings.NewReader(string(fileBytes)))
	reader.TrimLeadingSpace = true

	// Read all records
	records, err := reader.ReadAll()
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid CSV format: %v", err), http.StatusBadRequest)
		return
	}

	// Process records
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Assume first row is header
	header := records[0]
	colIndex := make(map[string]int)
	for i, colName := range header {
		colIndex[strings.ToLower(colName)] = i
	}

	// Required columns
	requiredCols := []string{"object", "object_type"}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			http.Error(w, fmt.Sprintf("Missing required columns object and object_type: %s", col), http.StatusBadRequest)
			return
		}
	}

	// Insert records into the database
	tx, err := s.DB.Begin()
	if err != nil {
		http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
		return
	}

	for i, record := range records {
		var data InsertPendingImportStruct
		if i == 0 {
			continue // Skip header row
		}
		data.Object = record[colIndex["object"]]
		data.ObjectType = record[colIndex["object_type"]]

		if colIndex["notes"] < len(record) {
			data.Notes = record[colIndex["notes"]]
		}
		if colIndex["source"] < len(record) {
			data.Source = record[colIndex["source"]]
		}
		if colIndex["time_provided"] < len(record) {
			data.TimeProvided = record[colIndex["time_provided"]]
		}
		if colIndex["geo_region"] < len(record) {
			data.GeoRegion = record[colIndex["geo_region"]]
		}
		if colIndex["geo_country"] < len(record) {
			data.GeoCountry = record[colIndex["geo_country"]]
		}
		if colIndex["geo_org"] < len(record) {
			data.GeoOrg = record[colIndex["geo_org"]]
		}

		if data.ObjectType != "ipv4" && data.ObjectType != "ipv6" && data.ObjectType != "domain" && data.ObjectType != "url" && data.ObjectType != "hash" {
			http.Error(w, fmt.Sprintf("Invalid object_type in row %d. Valid Object Types are: ipv4, ipv6, domain, url, hash", i), http.StatusBadRequest)
			return
		}

		if err := s.InsertImportTable(data, tx); err != nil {
			log.Printf("Failed to insert import table data for row %d: %v\n", i, err)
		}

	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Imported CSV with %d records<br />", len(records)-1) // Assume the 1st record listed is the header
	fmt.Fprint(w, "<a href='/upload.html'>Link to Upload another File</a>")
}

// Test curl command w/o APIKey: curl -k "https://127.0.0.1:9000/api/import" -X POST  -d '{ "object": "114.6.6.6", "object_type": "ipv4" }'
// Test curl command w/ APIKey: curl -k "https://127.0.0.1:9000/api/import" -X POST  -d '{ "object": "114.6.6.6", "object_type": "ipv4", "apiKey": "testingtheapikey" }'
func (s *ServerConfig) HandleImport(w http.ResponseWriter, r *http.Request) {
	// Respond to POST Requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	/**
	// Parse the incoming JSON payload
	var importData struct {
		Object       string `json:"object"`
		ObjectType   string `json:"object_type"`
		Notes        string `json:"notes,omitempty"`
		Source       string `json:"source,omitempty"`
		TimeProvided string `json:"time_provided,omitempty"`
		APIKey       string `json:"apiKey,omitempty"`
	}
	**/

	var data InsertPendingImportStruct

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate API Key
	if data.APIKey != s.Config.APIKey {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	if data.ObjectType != "ipv4" && data.ObjectType != "ipv6" && data.ObjectType != "domain" && data.ObjectType != "url" && data.ObjectType != "hash" {
		http.Error(w, "Invalid object_type.  Valid Object Types are: ipv4, ipv6, domain, url, hash", http.StatusBadRequest)
		return
	}

	// Future Enhancement - Include a validation step for the objects imported... (Security and Integrity of the Data)

	// Insert the data into the pending_import table
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	tx, err := s.DB.Begin()
	if err != nil {
		http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
		return
	}

	if err := s.InsertImportTable(data, tx); err != nil {
		log.Printf("Failed to insert import table data for row %s - %s: %v\n", data.Object, data.TimeProvided, err)
	}

	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		http.Error(w, fmt.Sprintf("Failed to commit transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// For demonstration, we just return a success message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"import successful"}`))
}

// Test curl command w/o APIKey: curl -k "https://127.0.0.1:9000/api/importJSON" -X POST  -d '{ "apiKey": "testing", "data": [{"object": "149.9.9.9", "object_type": "ipv4"}, {"object": "149.9.9.8", "object_type": "ipv4"} ] }'
// Test curl command w/ APIKey: curl -k "https://127.0.0.1:9000/api/importJSON" -X POST  -d '{ "apiKey": "testingtheapikey", "data": [{"object": "149.9.9.9", "object_type": "ipv4"}, {"object": "149.9.9.8", "object_type": "ipv4"} ] }'
func (s *ServerConfig) HandleImportJSON(w http.ResponseWriter, r *http.Request) {
	// Respond to POST Requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var JSONData struct {
		APIKey     string                      `json:"apiKey,omitempty"`
		ImportData []InsertPendingImportStruct `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&JSONData); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate API Key
	if JSONData.APIKey != s.Config.APIKey {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	// Insert the data into the pending_import table
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	tx, err := s.DB.Begin()
	if err != nil {
		http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
		return
	}

	for _, data := range JSONData.ImportData {
		//log.Printf("%s\n", importData.ObjectType)
		if data.ObjectType != "ipv4" && data.ObjectType != "ipv6" && data.ObjectType != "domain" && data.ObjectType != "url" && data.ObjectType != "hash" {
			http.Error(w, "Invalid object_type.  Valid Object Types are: ipv4, ipv6, domain, url, hash", http.StatusBadRequest)
			return
		}

		// ** Future Enhancement **
		// Include a validation step for the objects imported... (Security and Integrity of the Data)

		if err := s.InsertImportTable(data, tx); err != nil {
			log.Printf("Failed to insert import table data for row %s - %s: %v\n", data.Object, data.TimeProvided, err)
		}

	}

	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		http.Error(w, fmt.Sprintf("Failed to commit transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// For demonstration, we just return a success message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"import successful"}`))
}

// Test curl command w/o APIKey: curl -k "https://127.0.0.1:9000/api/verifyImport" -X GET  -d '{ "object": "114.6.6.6" }'
// Test curl command w/ APIKey: curl -k "https://127.0.0.1:9000/api/verifyImport" -X GET  -d '{ "object": "114.6.6.6", "apiKey": "testingtheapikey" }'
func (s *ServerConfig) HandleVerify(w http.ResponseWriter, r *http.Request) {
	// Respond to GET Requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the incoming JSON payload
	var importData struct {
		Object string `json:"object"`
		APIKey string `json:"apiKey,omitempty"`
	}

	// ** Future Enhancement **
	// Provide a JSON payload that would be valid when an error is sent
	if err := json.NewDecoder(r.Body).Decode(&importData); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate API Key
	if importData.APIKey != s.Config.APIKey {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	row := s.DB.QueryRow(`
		SELECT id, object, object_type, ipDecimal, notes, source, time_imported, time_provided
		FROM pending_import
		WHERE object = ?
	`, importData.Object)

	var result struct {
		ID           int    `json:"id"`
		Object       string `json:"object"`
		ObjectType   string `json:"object_type"`
		IPDecimal    int    `json:"ipDecimal"`
		Notes        string `json:"notes"`
		Source       string `json:"source"`
		TimeImported string `json:"time_imported"`
		TimeProvided string `json:"time_provided"`
	}

	err := row.Scan(&result.ID, &result.Object, &result.ObjectType, &result.IPDecimal, &result.Notes, &result.Source, &result.TimeImported, &result.TimeProvided)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No data found for the given object", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to retrieve data", http.StatusInternalServerError)
		return
	}

	// Return the retrieved data as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Failed to encode result", http.StatusInternalServerError)
		return
	}
}

func (s *ServerConfig) ProcessPendingImports() error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	rows, err := s.DB.Query(`SELECT id, object, object_type, notes, source, time_imported, time_provided, geo_region, geo_country, geo_org FROM pending_import LIMIT 10000`) // Due to performance issues this limit may need to be modified
	if err != nil {
		return fmt.Errorf("failed to query pending_import table: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var object, objectType, notes, source, timeImported, timeProvided, geoRegion, geoCountry, geoOrg string
		invalidObject := false
		if err := rows.Scan(&id, &object, &objectType, &notes, &source, &timeImported, &timeProvided, &geoRegion, &geoCountry, &geoOrg); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}

		fmt.Printf("Processing ID: %d, Object: %s, Type: %s\n", id, object, objectType)

		// Validate the object_type for example if ipv4 verify the structure matches a regex of IPv4
		var ipv4Decimal int
		if objectType == "ipv4" {
			// Add IPv4 validation logic here
			if !IsValidIPv4(object) {
				fmt.Printf("invalid IPv4 address: %s", object)
				invalidObject = true
			}
			ipv4Decimal, err = ipv4ToDecimal(object)
			if err != nil {
				return fmt.Errorf("failed to convert IPv4 to decimal: %w", err)
			}
		} else if objectType == "ipv6" {
			// Add IPv6 validation logic here
			if !IsValidIPv6(object) {
				fmt.Printf("invalid IPv6 address: %s", object)
				invalidObject = true
			}
		}

		if !invalidObject {
			_, err = tx.Exec(`
			INSERT INTO object_intel (object, object_type, ipDecimal, notes, first_seen, last_seen, occurrence_count, geo_region, geo_country, geo_org)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
			ON CONFLICT(object) DO UPDATE SET
				notes=excluded.notes,
				last_seen=excluded.last_seen,
				occurrence_count = object_intel.occurrence_count + 1
			`, object, objectType, ipv4Decimal, notes, timeImported, timeImported, geoRegion, geoCountry, geoOrg)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to insert/update object_intel: %w", err)
			}

			now := time.Now()
			year, week := now.ISOWeek()
			_, err = tx.Exec(`
			INSERT INTO objects_`+fmt.Sprintf("%d_%d", week, year)+` (object, object_type, ipDecimal, notes, source, time_imported, time_provided)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, object, objectType, ipv4Decimal, notes, source, timeImported, timeProvided)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to insert into weekly occurrences table: %w", err)
			}

			_, err = tx.Exec(`DELETE FROM pending_import WHERE id = ?`, id)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to delete from pending_import: %w", err)
			}
		} else {
			log.Printf("Skipping invalid object with ID %d\n", id)
			_, err = s.DB.Exec(`DELETE FROM pending_import WHERE id = ?`, id)
			if err != nil {
				tx.Rollback()
				log.Printf("failed to delete from pending_import: %v", err)
			}
		}

	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *ServerConfig) InsertImportTable(importData InsertPendingImportStruct, tx *sql.Tx) error {

	stmt, err := tx.Prepare(`
			INSERT INTO pending_import (object, object_type, notes, source, time_imported, time_provided, geo_region, geo_country, geo_org)
			VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
		`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	if _, err := stmt.Exec(importData.Object, importData.ObjectType, importData.Notes, importData.Source, importData.TimeProvided, importData.GeoRegion, importData.GeoCountry, importData.GeoOrg); err != nil {
		return fmt.Errorf("failed to insert/update trusted object in row %s - %s: %w", importData.Object, importData.TimeProvided, err)
	}

	return nil
}

// Objects are ipv4, ipv4CIDR, ipv6, ipv6CIDR
func (s *ServerConfig) LoadImportObjectsFromCSV() error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// read the files in the directory at s.Config.CSVLocation and loop through them
	files, err := os.ReadDir(s.Config.ImportCSVLocation)
	if err != nil {
		return fmt.Errorf("failed to read trusted CSV directory: %w", err)
	}

	for _, file := range files {
		fullPath := ""
		if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".csv") {
			fullPath = s.Config.ImportCSVLocation + "/" + file.Name()
			log.Printf("Loading import objects from CSV file: %s\n", fullPath)
		} else {
			continue
		}
		csvFile, err := os.Open(fullPath)
		if err != nil {
			return fmt.Errorf("failed to open import CSV file: %w", err)
		}
		defer csvFile.Close()

		reader := csv.NewReader(csvFile)
		reader.TrimLeadingSpace = true

		// Read all records
		records, err := reader.ReadAll()
		if err != nil {
			return fmt.Errorf("failed to read CSV file: %w", err)
		}

		// Assume first row is header
		header := records[0]
		colIndex := make(map[string]int)
		for i, colName := range header {
			colIndex[strings.ToLower(colName)] = i
		}

		// Required columns
		requiredCols := []string{"object", "object_type"}
		for _, col := range requiredCols {
			if _, ok := colIndex[col]; !ok {
				return fmt.Errorf("missing required columns object, object_type: %s", col)
			}
		}

		for i, record := range records {
			var data InsertPendingImportStruct
			if i == 0 {
				continue // Skip header row
			}
			data.Object = record[colIndex["object"]]
			data.ObjectType = record[colIndex["object_type"]]

			if colIndex["notes"] < len(record) {
				data.Notes = record[colIndex["notes"]]
			} else {
				data.Notes = ""
			}
			if colIndex["source"] < len(record) {
				data.Source = record[colIndex["source"]]
			} else {
				data.Source = ""
			}
			if colIndex["time_provided"] < len(record) {
				data.TimeProvided = record[colIndex["time_provided"]]
			} else {
				data.TimeProvided = ""
			}
			if colIndex["geo_region"] < len(record) {
				data.GeoRegion = record[colIndex["geo_region"]]
			} else {
				data.GeoRegion = ""
			}
			if colIndex["geo_country"] < len(record) {
				data.GeoCountry = record[colIndex["geo_country"]]
			} else {
				data.GeoCountry = ""
			}
			if colIndex["geo_org"] < len(record) {
				data.GeoOrg = record[colIndex["geo_org"]]
			} else {
				data.GeoOrg = ""
			}

			fmt.Printf("Processing CSV Row %d: Object: %s, Type: %s, Notes: %s, Source: %s, GeoRegion: %s, GeoCountry: %s, GeoOrg: %s\n", i, data.Object, data.ObjectType, data.Notes, data.Source, data.GeoRegion, data.GeoCountry, data.GeoOrg)

			if err := s.InsertImportTable(data, tx); err != nil {
				log.Printf("Failed to insert import table data for row %d: %v\n", i, err)
			}
		}

		err = tx.Commit()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		// Move the import CSV file to an archive directory
		archiveDir := s.Config.ArchiveCSVLocation
		CreateDirectory(archiveDir)
		if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
			err = os.MkdirAll(archiveDir, 0755)
			if err != nil {
				return fmt.Errorf("failed to create archive directory: %w", err)
			}
		}
		archivedFilePath := archiveDir + "/" + file.Name() + "_import_" + time.Now().Format("20060102_150405")
		err = os.Rename(fullPath, archivedFilePath)
		if err != nil {
			return fmt.Errorf("failed to move processed CSV file to archive: %w", err)
		}
		log.Printf("Moved processed import CSV file to archive: %s\n", archivedFilePath)
	}

	return nil
}

// Objects are ipv4, ipv4CIDR, ipv6, ipv6CIDR
func (s *ServerConfig) LoadTrustedObjectsFromCSV() error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// read the files in the directory at s.Config.CSVLocation and loop through them
	files, err := os.ReadDir(s.Config.TrustedCSVLocation)
	if err != nil {
		return fmt.Errorf("failed to read trusted CSV directory: %w", err)
	}

	for _, file := range files {
		fullPath := ""
		if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".csv") {
			fullPath = s.Config.TrustedCSVLocation + "/" + file.Name()
			log.Printf("Loading trusted objects from CSV file: %s\n", fullPath)
		} else {
			continue
		}
		csvFile, err := os.Open(fullPath)
		if err != nil {
			return fmt.Errorf("failed to open trusted CSV file: %w", err)
		}
		defer csvFile.Close()

		reader := csv.NewReader(csvFile)
		reader.TrimLeadingSpace = true

		// Read all records
		records, err := reader.ReadAll()
		if err != nil {
			return fmt.Errorf("failed to read CSV file: %w", err)
		}

		tx, err := s.DB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		stmt, err := tx.Prepare(`
		INSERT INTO trusted_objects (object, object_type, ipDecimal, startIPDecimal, endIPDecimal, notes, source, occurrence_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(object) DO UPDATE SET
			notes=excluded.notes,
			source=excluded.source,
			last_seen=CURRENT_TIMESTAMP,
			occurrence_count = trusted_objects.occurrence_count + 1
		`)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer stmt.Close()

		// Assume first row is header
		header := records[0]
		colIndex := make(map[string]int)
		for i, colName := range header {
			colIndex[strings.ToLower(colName)] = i
		}

		// Required columns
		requiredCols := []string{"object", "object_type"}
		for _, col := range requiredCols {
			if _, ok := colIndex[col]; !ok {
				tx.Rollback()
				return fmt.Errorf("missing required column: %s", col)
			}
		}

		for i, record := range records {
			if i == 0 {
				continue // Skip header row
			}
			object := record[colIndex["object"]]
			objectType := record[colIndex["object_type"]]
			var notes, source string
			if colIndex["notes"] < len(record) {
				notes = record[colIndex["notes"]]
			}
			if colIndex["source"] < len(record) {
				source = record[colIndex["source"]]
			}

			var ipv4Decimal int
			if objectType == "ipv4" {
				ipv4Decimal, err = ipv4ToDecimal(object)
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("unable to convert IPv4 address to decimal in row %d: %w", i, err)
				}
			}

			var startIPDecimal, endIPDecimal int
			if objectType == "ipv4CIDR" {
				startIP, endIP, err := GetFirstAndLastIP(object)
				startIPDecimal, err = ipv4ToDecimal(startIP.String())
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("unable to convert start IPv4 address to decimal in row %d: %w", i, err)
				}
				endIPDecimal, err = ipv4ToDecimal(endIP.String())
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("unable to convert end IPv4 address to decimal in row %d: %w", i, err)
				}
			}

			if _, err := stmt.Exec(object, objectType, ipv4Decimal, startIPDecimal, endIPDecimal, notes, source); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to insert/update trusted object in row %d: %w", i, err)
			}

		}

		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		// Move the trusted CSV file to an archive directory
		archiveDir := s.Config.ArchiveCSVLocation
		CreateDirectory(archiveDir)
		if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
			err = os.MkdirAll(archiveDir, 0755)
			if err != nil {
				return fmt.Errorf("failed to create archive directory: %w", err)
			}
		}
		archivedFilePath := archiveDir + "/" + file.Name() + "_trusted_" + time.Now().Format("20060102_150405")
		err = os.Rename(fullPath, archivedFilePath)
		if err != nil {
			return fmt.Errorf("failed to move processed CSV file to archive: %w", err)
		}
		log.Printf("Moved processed trusted CSV file to archive: %s\n", archivedFilePath)

	}

	return nil
}

func (s *ServerConfig) MarkTrustedObjects() error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Update for ipv4 trusted objects
	_, err = tx.Exec(`
		UPDATE object_intel
		SET trusted = TRUE
		WHERE object IN (SELECT object FROM trusted_objects WHERE object_type = "ipv4")
			AND object_type = "ipv4"
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to mark trusted objects: %w", err)
	}

	// Update for ipv6 trusted objects
	_, err = tx.Exec(`
		UPDATE object_intel
		SET trusted = TRUE
		WHERE object IN (SELECT object FROM trusted_objects WHERE object_type = "ipv6")
			AND object_type = "ipv6"
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to mark trusted objects: %w", err)
	}

	// Cycle through the ipv4CIDR trusted objects and mark them
	rows, err := tx.Query(`SELECT object FROM trusted_objects WHERE object_type = "ipv4CIDR"`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to query ipv4CIDR trusted objects: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to scan cidr: %w", err)
		}

		startIP, endIP, err := GetFirstAndLastIP(cidr)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to get first and last IP for cidr %s: %w", cidr, err)
		}
		startIPDec, err := ipv4ToDecimal(startIP.String())
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to convert start IP to decimal for cidr %s: %w", cidr, err)
		}
		endIPDec, err := ipv4ToDecimal(endIP.String())
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to convert end IP to decimal for cidr %s: %w", cidr, err)
		}

		log.Printf("Marking trusted ipv4CIDR objects from %s to %s\n", startIP.String(), endIP.String())

		_, err = tx.Exec(`
			UPDATE object_intel
			SET trusted = TRUE
			WHERE object_type = "ipv4" 
				AND IPDecimal BETWEEN ? AND ?
		`, startIPDec, endIPDec)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to mark ipv4CIDR trusted objects: %w", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *ServerConfig) TableExists(tableName string) (bool, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	_, err := s.DB.Begin()
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction: %w", err)
	}

	var name string
	err = s.DB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tableName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Select a row from the object_intel table where the last updated date is within the last 7 days
func (s *ServerConfig) GetObjectListIPv4(tableName string, ipv4 string) ([]string, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	query := "SELECT id FROM " + tableName + " WHERE object = '" + ipv4 + "'"

	// Set the risk scoring to 2 days due to large databases and performance concerns
	if tableName == "object_intel" {
		query = `SELECT object
		FROM object_intel
		WHERE (risk_score_last_updated <= datetime('now', '-2 days') OR risk_score_last_updated IS NULL) AND trusted = FALSE
		LIMIT 10000`
	}

	rows, err := s.DB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent object_intel: %w", err)
	}
	defer rows.Close()

	// The results only have 1 value return as a list of strings
	var results []string
	for rows.Next() {
		var object string
		if err := rows.Scan(&object); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		result := strings.TrimSpace(object)
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}

	return results, nil
}

func (s *ServerConfig) UpdateObjectRiskScore(object string, riskScore int) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	_, err := s.DB.Exec(`
		UPDATE object_intel
		SET risk_score = ?, risk_score_last_updated = CURRENT_TIMESTAMP
		WHERE object = ?
	`, riskScore, object)
	if err != nil {
		return fmt.Errorf("failed to update risk score: %w", err)
	}

	return nil
}

func (s *ServerConfig) UpdateObjectIntelRiskScores() error {
	now := time.Now()
	year, week := now.ISOWeek()
	tableNowName := "objects_" + fmt.Sprintf("%d_%d", week, year)
	boolTableNow, err := s.TableExists(tableNowName)
	if err != nil {
		log.Fatalf("Error checking if table %s exists: %v", tableNowName, err)
	}

	// Last Week
	lastWeek := now.AddDate(0, 0, -7)
	year, week = lastWeek.ISOWeek()
	tableLastWeekName := "objects_" + fmt.Sprintf("%d_%d", week, year)
	boolTableLastWeek, err := s.TableExists(tableLastWeekName)
	if err != nil {
		log.Fatalf("Error checking if table %s exists: %v", tableLastWeekName, err)
	}

	// 2 weeks ago
	twoWeeksago := now.AddDate(0, 0, -14)
	year, week = twoWeeksago.ISOWeek()
	tableTwoWeeksAgoName := "objects_" + fmt.Sprintf("%d_%d", week, year)
	boolTableTwoWeeksAgo, err := s.TableExists(tableTwoWeeksAgoName)
	if err != nil {
		log.Fatalf("Error checking if table %s exists: %v", tableTwoWeeksAgoName, err)
	}

	// 3 weeks ago
	threeWeeksago := now.AddDate(0, 0, -21)
	year, week = threeWeeksago.ISOWeek()
	tableThreeWeeksAgoName := "objects_" + fmt.Sprintf("%d_%d", week, year)
	boolTableThreeWeeksAgo, err := s.TableExists(tableThreeWeeksAgoName)
	if err != nil {
		log.Fatalf("Error checking if table %s exists: %v", tableThreeWeeksAgoName, err)
	}

	// Calculate Risk Score for the IP Addresses in the object intel database
	listIPv4, err := s.GetObjectListIPv4("object_intel", "")
	if err != nil {
		log.Fatalf("retrieving IPv4 object list failed: %v", err)
	}
	if s.Config.Debug {
		log.Printf("Retrieved %d IPv4 objects for risk score calculation.\n", len(listIPv4))
	}

	for _, obj := range listIPv4 {
		score := 0
		// Now
		if boolTableNow {
			listNow, err := s.GetObjectListIPv4(tableNowName, obj)
			if err != nil {
				log.Fatalf("retrieving IPv4 object list from %s failed: %v", tableNowName, err)
			}
			if s.Config.Debug {
				log.Printf("Retrieved %d IPv4 objects from %s for risk score calculation.\n", len(listNow), tableNowName)
			}
			score += len(listNow) * 4
		}
		// Last Week
		if boolTableLastWeek {
			listLastWeek, err := s.GetObjectListIPv4(tableLastWeekName, obj)
			if err != nil {
				log.Fatalf("retrieving IPv4 object list from %s failed: %v", tableLastWeekName, err)
			}
			if s.Config.Debug {
				log.Printf("Retrieved %d IPv4 objects from %s for risk score calculation.\n", len(listLastWeek), tableLastWeekName)
			}
			score += len(listLastWeek) * 2
		}

		// 2 Weeks Ago
		if boolTableTwoWeeksAgo {
			listTwoWeeksAgo, err := s.GetObjectListIPv4(tableTwoWeeksAgoName, obj)
			if err != nil {
				log.Fatalf("retrieving IPv4 object list from %s failed: %v", tableTwoWeeksAgoName, err)
			}
			if s.Config.Debug {
				log.Printf("Retrieved %d IPv4 objects from %s for risk score calculation.\n", len(listTwoWeeksAgo), tableTwoWeeksAgoName)
			}
			score += len(listTwoWeeksAgo) * 1
		}

		// 3 Weeks Ago
		if boolTableThreeWeeksAgo {
			listThreeWeeksAgo, err := s.GetObjectListIPv4(tableThreeWeeksAgoName, obj)
			if err != nil {
				log.Fatalf("retrieving IPv4 object list from %s failed: %v", tableThreeWeeksAgoName, err)
			}
			if s.Config.Debug {
				log.Printf("Retrieved %d IPv4 objects from %s for risk score calculation.\n", len(listThreeWeeksAgo), tableThreeWeeksAgoName)
			}
			score += len(listThreeWeeksAgo) * 1
		}

		// Update the risk score in the database
		err = s.UpdateObjectRiskScore(obj, score)
		if err != nil {
			log.Fatalf("updating risk score for object %s failed: %v", obj, err)
		}
		if s.Config.Debug {
			log.Printf("Updated risk score for object %s to %d.\n", obj, score)
		}
	}

	return nil
}
