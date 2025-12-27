package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("returns API key when valid Authorization header is provided", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey test-api-key-123")

		apiKey, err := GetAPIKey(headers)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if apiKey != "test-api-key-123" {
			t.Errorf("expected API key 'test-api-key-123', got '%s'", apiKey)
		}
	})

	t.Run("returns error when Authorization header is missing", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)

		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
		if apiKey != "" {
			t.Errorf("expected empty API key, got '%s'", apiKey)
		}
	})

	t.Run("returns error when Authorization header is malformed", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer test-api-key-123")

		apiKey, err := GetAPIKey(headers)

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("expected 'malformed authorization header' error, got '%v'", err)
		}
		if apiKey != "" {
			t.Errorf("expected empty API key, got '%s'", apiKey)
		}
	})

	t.Run("returns error when ApiKey prefix is present but key is missing", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		apiKey, err := GetAPIKey(headers)

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("expected 'malformed authorization header' error, got '%v'", err)
		}
		if apiKey != "" {
			t.Errorf("expected empty API key, got '%s'", apiKey)
		}
	})
}
