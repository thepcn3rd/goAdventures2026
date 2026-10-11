package common

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
)

func isASCII(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] > 127 {
			return false
		}
	}
	return true
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" // Define the characters to be used
	var result string
	for i := 0; i < length; i++ {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result += string(charset[randomIndex.Int64()])
	}
	return result
}

func CheckError(reasonString string, err error, exitBool bool) {
	if err != nil && exitBool == true {
		fmt.Printf("%s\n%v\n", reasonString, err)
		//fmt.Printf("%s\n\n", err)
		os.Exit(0)
	} else if err != nil && exitBool == false {
		fmt.Printf("%s\n%v\n", reasonString, err)
		//fmt.Printf("%s\n", err)
		return
	}
}

func CreateDirectory(createDir string) {
	currentDir, err := os.Getwd()
	CheckError("Unable to get the working directory", err, true)
	newDir := currentDir + "/" + createDir
	if _, err := os.Stat(newDir); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(newDir, os.ModePerm)
		CheckError("Unable to create directory "+createDir, err, true)
	}
}

// Check if the file exists, display the error message but does not exit
func FileExists(file string) bool {
	currentDir, err := os.Getwd()
	CheckError("Unable to get the working directory", err, false)
	//fmt.Println(currentDir)
	filePath := currentDir + "/" + file
	if _, err := os.Stat(filePath); err != nil {
		CheckError("Unable to find file "+filePath+"\n", err, false)
		return false
	}
	return true
}

func SaveOutputFile(message string, fileName string) {
	outFile, _ := os.Create(fileName)
	//CheckError("Unable to create txt file", err, true)
	defer outFile.Close()
	w := bufio.NewWriter(outFile)
	n, err := w.WriteString(message)
	if n < 1 {
		CheckError("Unable to write to txt file", err, true)
	}
	outFile.Sync()
	w.Flush()
	outFile.Close()
}

func IsValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	// Ensure it's IPv4 (not IPv6)
	return parsedIP.To4() != nil
}

func IsValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if it's IPv6 and not IPv4-mapped IPv6
	return parsedIP.To4() == nil && parsedIP.To16() != nil
}

func isIPInCIDR(ipStr, cidrStr string) (bool, error) {
	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Parse the CIDR notation
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, err
	}

	// Check if IP is within the network
	return ipNet.Contains(ip), nil
}

func ipv4ToDecimal(ipStr string) (int, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Convert to IPv4 if it's an IPv6-mapped IPv4 address
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	// Calculate decimal value
	var decimal uint32
	for i := 0; i < 4; i++ {
		decimal = decimal<<8 | uint32(ip[i])
	}

	return int(decimal), nil
}

// GetFirstAndLastIP calculates the first and last usable IP addresses in a CIDR range
func GetFirstAndLastIP(cidr string) (net.IP, net.IP, error) {
	// Parse the CIDR string
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	// Calculate the first IP (network address + 1 for IPv4, network address for IPv6)
	firstIP := make(net.IP, len(ipNet.IP))
	copy(firstIP, ipNet.IP)

	// For IPv4, first usable address is typically network address + 1
	// For IPv6, first usable address is typically the network address itself
	if ip.To4() != nil {
		// IPv4: increment the last octet
		firstIP[len(firstIP)-1]++
	}

	// Calculate the last IP (broadcast address - 1 for IPv4, last address for IPv6)
	lastIP := make(net.IP, len(ipNet.IP))
	copy(lastIP, ipNet.IP)

	// Apply the mask to get the network portion
	for i := 0; i < len(lastIP); i++ {
		// OR with the inverse of the mask to get the broadcast address
		lastIP[i] |= ^ipNet.Mask[i]
	}

	// For IPv4, last usable address is typically the broadcast address
	if ip.To4() != nil {
		// Decrement the last octet
		lastIP[len(lastIP)-1]--
	}

	return firstIP, lastIP, nil
}
