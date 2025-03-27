// handler.go - основной обработчик для Vercel
package handler

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

// ========== Конфигурация ==========
type Config struct {
	GoogleAPIKey   string
	GoogleClientID string
}

func loadConfig() Config {
	return Config{
		GoogleAPIKey:   mustGetEnv("GOOGLE_API_KEY"),
		GoogleClientID: getEnv("GOOGLE_CLIENT_ID", "securelink-app"),
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
	log.Fatalf("Missing required env var: %s", key)
	return ""
}

// ========== Safe Browsing API ==========
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
		return false, nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, nil, fmt.Errorf("failed to decode response: %w", err)
	}

	threats := make([]string, 0, len(result.Matches))
	for _, m := range result.Matches {
		threats = append(threats, m.ThreatType)
	}

	return len(threats) == 0, threats, nil
}

// ========== Глобальные переменные ==========
var (
	tmpl   *template.Template
	client *GoogleClient
)

func init() {
	// Инициализация шаблонов
	templatePath := filepath.Join("templates", "index.html")
	absPath, err := filepath.Abs(templatePath)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	tmpl = template.Must(template.ParseFiles(absPath))
	log.Printf("Template initialized from: %s", absPath)

	// Инициализация API клиента
	cfg := loadConfig()
	client = NewGoogleClient(cfg.GoogleAPIKey, cfg.GoogleClientID)
}

// ========== Обработчики маршрутов ==========
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	urlStr := r.FormValue("url")
	if !isValidURL(urlStr) {
		renderTemplateWithError(w, "Invalid URL format")
		return
	}

	safe, threats, err := client.CheckURL(r.Context(), urlStr)
	if err != nil {
		log.Printf("Safe Browsing check failed: %v", err)
		renderTemplateWithError(w, "Security check unavailable")
		return
	}

	if err := tmpl.Execute(w, map[string]interface{}{
		"Result":  safe,
		"Threats": threats,
	}); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func renderTemplateWithError(w http.ResponseWriter, errorMsg string) {
	if err := tmpl.Execute(w, map[string]interface{}{"Error": errorMsg}); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func serveStatic(w http.ResponseWriter, r *http.Request) {
    // Полный путь к файлу относительно корня проекта
    staticPath := filepath.Join("public", r.URL.Path)
    
    // Проверка существования файла
    if _, err := os.Stat(staticPath); os.IsNotExist(err) {
        http.NotFound(w, r)
        return
    }
    
    // Отдача файла с правильными headers
    http.ServeFile(w, r, staticPath)
}

func isValidURL(u string) bool {
	_, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}
	return regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`).MatchString(u)
}

// ========== Главный обработчик Vercel ==========
func Handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Incoming request: %s %s", r.Method, r.URL.Path)

	switch r.URL.Path {
	case "/":
		handleIndex(w, r)
	case "/check":
		handleCheck(w, r)
	default:
		if isStaticAsset(r.URL.Path) {
			serveStatic(w, r)
		} else {
			http.NotFound(w, r)
		}
	}
}

func isStaticAsset(path string) bool {
	return regexp.MustCompile(`^/(css|js|images)/`).MatchString(path)
}