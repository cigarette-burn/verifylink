package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Config
type Config struct {
	Port           string
	GoogleAPIKey   string
	GoogleClientID string
}

func loadConfig() Config {
	return Config{
		Port:           getEnv("PORT", "8080"),
		GoogleAPIKey:   mustGetEnv("GOOGLE_API_KEY"),
		GoogleClientID: getEnv("GOOGLE_CLIENT_ID", "my-app"), // Необязательный
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func mustGetEnv(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	log.Fatalf("Требуется переменная окружения: %s", key)
	return ""
}

// Google Client
type GoogleClient struct {
	apiKey   string
	clientID string
	http     *http.Client
}

func NewGoogleClient(apiKey, clientID string) *GoogleClient {
	return &GoogleClient{
		apiKey:   apiKey,
		clientID: clientID,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *GoogleClient) CheckURL(ctx context.Context, url string) (bool, []string, error) {
	reqBody := map[string]interface{}{
		"client": map[string]string{
			"clientId":      c.clientID,
			"clientVersion": "1.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{{"url": url}},
		},
	}

	jsonData, _ := json.Marshal(reqBody)
	req, _ := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", c.apiKey),
		bytes.NewBuffer(jsonData),
	)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, nil, err
	}

	var threats []string
	for _, m := range result.Matches {
		threats = append(threats, m.ThreatType)
	}

	return len(threats) == 0, threats, nil
}

// Handlers
var tmpl *template.Template

func init() {
	tmpl = template.Must(template.ParseFiles(filepath.Join("templates", "index.html")))
}

func isValidURL(u string) bool {
	_, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}
	return regexp.MustCompile(`^(http(s)?:\/\/)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$`).MatchString(u)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tmpl.Execute(w, nil)
}

func checkHandler(client *GoogleClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		url := r.FormValue("url")
		if !isValidURL(url) {
			tmpl.Execute(w, map[string]interface{}{"Error": "Invalid URL"})
			return
		}

		safe, threats, err := client.CheckURL(r.Context(), url)
		if err != nil {
			tmpl.Execute(w, map[string]interface{}{"Error": "Check failed"})
			return
		}

		tmpl.Execute(w, map[string]interface{}{
			"Result":  safe,
			"Threats": threats,
		})
	}
}

// Main
func main() {
	cfg := loadConfig()
	client := NewGoogleClient(cfg.GoogleAPIKey, cfg.GoogleClientID)

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/check", checkHandler(client))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	log.Printf("Server starting on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
}