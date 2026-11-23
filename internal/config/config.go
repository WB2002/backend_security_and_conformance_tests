package config

import (
	"os"
	"strconv"
	"strings"
)

type ConformanceConfig struct {
	BaseURL              string
	SocketPath           string
	MongoURI             string
	RedisURL             string
	PostgresURL          string
	MockUpstreamPort     int
	AdminEmail           string
	CountryUSIP          string
	CountryGBIP          string
	IsDestructiveEnabled bool
	ShutdownCommand      string
}

func LoadConfig(getenv func(string) string) ConformanceConfig {
	if getenv == nil {
		getenv = os.Getenv
	}
	getOrDefault := func(key, def string) string {
		if val := getenv(key); val != "" {
			return val
		}
		return def
	}

	baseURL := strings.TrimRight(getOrDefault("BASE_URL", "http://127.0.0.1:3000"), "/")
	mockPortStr := getOrDefault("MOCK_UPSTREAM_PORT", "4010")
	mockPort, err := strconv.Atoi(mockPortStr)
	if err != nil {
		mockPort = 4010
	}

	return ConformanceConfig{
		BaseURL:              baseURL,
		SocketPath:           getOrDefault("SOCKET_PATH", "/socket.io"),
		MongoURI:             getOrDefault("MONGO_URI", "mongodb://127.0.0.1:27017/nestjs-boilerplate"),
		RedisURL:             getOrDefault("REDIS_URL", "redis://127.0.0.1:6379"),
		PostgresURL:          getOrDefault("POSTGRES_URL", "postgresql://user:password@127.0.0.1:5432/nestjs_db"),
		MockUpstreamPort:     mockPort,
		AdminEmail:           getOrDefault("ADMIN_EMAIL", "conformance-admin@example.test"),
		CountryUSIP:          getOrDefault("COUNTRY_US_IP", "8.8.8.8"),
		CountryGBIP:          getOrDefault("COUNTRY_GB_IP", "81.2.69.142"),
		IsDestructiveEnabled: getenv("RUN_DESTRUCTIVE") == "true",
		ShutdownCommand:      getenv("SHUTDOWN_COMMAND"),
	}
}
