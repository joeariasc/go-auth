package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Config holds the application configuration
type Config struct {
	SecretKey      string
	TokenDuration  int
	ServerAddress  string
	AllowedOrigins []string
	DbHost         string
	DbPort         int
	DbUser         string
	DbPassword     string
	DbName         string
}

// LoadEnvFile loads environment variables from a file and returns Config
func LoadEnvFile(configFile string) (*Config, error) {
	if _, err := os.Stat(configFile); err == nil {
		envFile, err := os.Open(configFile)
		if err == nil {
			defer envFile.Close()
			return processEnvFile(envFile)
		}
	}

	return loadFromEnvironment()
}

func processEnvFile(envFile *os.File) (*Config, error) {
	defer func(envFile *os.File) {
		if err := envFile.Close(); err != nil {
			log.Printf("Error closing .env file: %v", err)
		}
	}(envFile)

	// First, load all environment variables
	scanner := bufio.NewScanner(envFile)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split the text on the first equal sign to handle values that might contain =
		parts := strings.SplitN(line, "=", 2)

		if len(parts) != 2 {
			log.Printf("Warning: Invalid environment variable format: %s", line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			log.Printf("Warning: Empty key found in environment file")
			continue
		}

		if value == "" {
			log.Printf("Warning: Empty value for key: %s", key)
		}

		err := os.Setenv(key, value)
		if err != nil {
			return nil, fmt.Errorf("error setting env var %s: %v", key, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning .env file: %v", err)
	}

	return loadFromEnvironment()
}

func loadFromEnvironment() (*Config, error) {
	tokenDuration, err := strconv.Atoi(os.Getenv("TOKEN_DURATION"))
	if err != nil {
		return nil, fmt.Errorf("invalid TOKEN_DURATION value: %v", err)
	}

	dbPort, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT value: %v", err)
	}

	originsStr := os.Getenv("ALLOWED_ORIGINS")

	var allowedOrigins []string

	if originsStr != "" {
		allowedOrigins = strings.Split(originsStr, ",")
		for i := range allowedOrigins {
			allowedOrigins[i] = strings.TrimSpace(allowedOrigins[i])
		}
	} else {
		log.Printf("Warning: ALLOWED_ORIGINS is empty")
	}

	config := &Config{
		SecretKey:      os.Getenv("SECRET_KEY"),
		TokenDuration:  tokenDuration,
		ServerAddress:  os.Getenv("SERVER_ADDRESS"),
		AllowedOrigins: allowedOrigins,
		DbHost:         os.Getenv("DB_HOST"),
		DbPort:         dbPort,
		DbUser:         os.Getenv("DB_USER"),
		DbPassword:     os.Getenv("DB_PASSWORD"),
		DbName:         os.Getenv("DB_NAME"),
	}

	// Validate required fields
	if config.SecretKey == "" {
		return nil, fmt.Errorf("SECRET_KEY is required")
	}

	if config.ServerAddress == "" {
		return nil, fmt.Errorf("SERVER_ADDRESS is required")
	}

	return config, nil
}
