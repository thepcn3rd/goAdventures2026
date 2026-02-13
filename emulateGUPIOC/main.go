package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
)

/**
This is a tool that will create indicators based on the detection guidance provided by Orca Security in their blog post about the Notepad++ supply chain attack.
Then create detections based on the indicators.

Reference: https://orca.security/resources/blog/notepad-plus-plus-supply-chain-attack/

Detection Guidance

Host-level indicators:

    gup.exe spawning processes other than explorer.exe and npp* themed installers
    Files named AutoUpdater.exe or update.exe in %TEMP% (Notepad++ does not use these names)
    Evidence of reconnaissance commands saving output to a.txt
    (Completed) Execution of curl.exe from Notepad++ related processes

Network-level indicators:

    gup.exe connecting to domains other than notepad-plus-plus.org, github.com, or release-assets.githubusercontent.com
    Outbound connections to temp.sh (IP: 51.91.79.17) or similar anonymous file-sharing services


**/

type Configuration struct {
	LogPath string `json:"log_path"`
}

func (c *Configuration) CreateConfig(f string) error {
	c.LogPath = "logs"

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

type TestResults struct {
	Results []TestCaseResult
	LogPath string
}

type TestCaseResult struct {
	Name        string
	Description string
	Status      string // Pass, faile, warning, info
	Message     string
}

func (t *TestResults) CommandExecution(commandDescription string, command []string) error {
	var c TestCaseResult
	c.Name = commandDescription
	c.Description = "Test the command execution function with a known command"

	//cmd := exec.Command("curl.exe", "https://www.google.com")
	cmd := exec.Command(command[0], command[1:]...)

	cmdOutput, err := cmd.Output()
	if err != nil {
		c.Status = "Failed"
		c.Message = "Command execution failed: " + err.Error()
		t.Results = append(t.Results, c)
		return err
	}

	if len(cmdOutput) > 0 {
		c.Status = "Successfully Executed"
		c.Message = fmt.Sprintf("Command execution succeeded, output length: %d", len(cmdOutput))
		t.Results = append(t.Results, c)
	} else {
		c.Status = "Informational"
		c.Message = "Command execution returned no output"
		t.Results = append(t.Results, c)
	}

	return nil
}

func CreateDirectory(createDir string) error {
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}
	newDir := currentDir + "/" + createDir
	if _, err := os.Stat(newDir); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(newDir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	ConfigPtr := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Load the Configuration file
	var config Configuration
	configFile := *ConfigPtr
	log.Println("Loading the following config file: " + configFile + "\n")
	if err := config.LoadConfig(configFile); err != nil {
		config.CreateConfig(configFile)
		log.Fatalf("Created %s, modify the file to customize how the tool functions.\n", configFile)
	}

	err := CreateDirectory(config.LogPath)
	if err != nil {
		log.Fatalf("Failed to create log directory: %v\n", err)
	}

	testResults := &TestResults{
		LogPath: config.LogPath,
	}

	// Test the curl functionality
	err = testResults.CommandExecution("Test Curl Execution", []string{"curl.exe", "https://www.google.com"})
	if err != nil {
		log.Printf("Command execution test failed: %v\n", err)
	} else {
		log.Printf("Command execution test completed successfully.\n")
	}

	// Test saving the results to a file called "a.txt"
	testResults.CommandExecution("Test Saving Results to a.txt File", []string{"cmd.exe", "/C", "netstat -ano >> a.txt"})
	testResults.CommandExecution("Test Saving Results to b.txt File", []string{"cmd.exe", "/C", "netstat -ano >> b.txt && systeminfo >> b.txt && tasklist >> b.txt && whoami >> a.txt"})

	// Test execution of %TEMP%\AutoUpdater.exe and %TEMP%\update.exe
	// Copy cmd.exe to %TEMP%\AutoUpdater.exe and %TEMP%\update.exe before running this test to simulate the presence of these files in the TEMP directory
	// The copy of cmd.exe should get flagged also...
	testResults.CommandExecution("Copy cmd.exe to %TEMP%\\AutoUpdater.exe", []string{"cmd.exe", "/C", "copy c:\\windows\\system32\\cmd.exe %TEMP%\\AutoUpdater.exe"})
	testResults.CommandExecution("Test Execution of AutoUpdater.exe in TEMP", []string{"cmd.exe", "/C", "%TEMP%\\AutoUpdater.exe"})
	testResults.CommandExecution("Copy cmd.exe to %TEMP%\\update.exe", []string{"cmd.exe", "/C", "copy c:\\windows\\system32\\cmd.exe %TEMP%\\update.exe"})
	testResults.CommandExecution("Test Execution of update.exe in TEMP", []string{"cmd.exe", "/C", "%TEMP%\\update.exe"})
	fmt.Printf("Remove manually the copied cmd.exe files in the TEMP directory after testing: %TEMP%\\AutoUpdater.exe and %TEMP%\\update.exe\n")

	// Test a curl connection to temp.sh
	testResults.CommandExecution("Test Curl Connection to temp.sh", []string{"curl.exe", "https://temp.sh"})

	// Save the test results to a log file
	logFile, err := os.Create(config.LogPath + "/results.log")
	if err != nil {
		log.Fatalf("Failed to create log file: %v\n", err)
	}
	defer logFile.Close()

	for _, result := range testResults.Results {
		logEntry := fmt.Sprintf("Test Name: %s\nDescription: %s\nStatus: %s\nMessage: %s\n\n",
			result.Name, result.Description, result.Status, result.Message)
		logFile.WriteString(logEntry)
	}

}
