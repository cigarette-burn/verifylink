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

// Config и GoogleClient (остаются без изменений)
type Config struct {
	Port           string
	GoogleAPIKey   string
	GoogleClientID string
}

type GoogleClient struct {
	apiKey   string
	clientID string
	http     *http.Client
}

// Глобальные переменные (инициализация в init())
var (
	tmpl   *template.Template
	client *GoogleClient
)

func init() {
	// Загрузка шаблона
	var err error
	tmpl, err = template.ParseFiles(filepath.Join("templates", "index.html"))
	if err != nil {
		log.Fatalf("Ошибка загрузки шаблона: %v", err)
	}

	// Инициализация клиента Google
	cfg := Config{
		Port:           getEnv("PORT", "8080"),
		GoogleAPIKey:   mustGetEnv("GOOGLE_API_KEY"),
		GoogleClientID: getEnv("GOOGLE_CLIENT_ID", "securelink-app"),
	}
	client = NewGoogleClient(cfg.GoogleAPIKey, cfg.GoogleClientID)
}

// Вспомогательные функции (без изменений)
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

func NewGoogleClient(apiKey, clientID string) *GoogleClient {
	return &GoogleClient{
		apiKey:   apiKey,
		clientID: clientID,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *GoogleClient) CheckURL(ctx context.Context, url string) (bool, []string, error) {
	// ... (код метода CheckURL без изменений)
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

// Главный обработчик для Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		handleIndex(w, r)
	case "/check":
		handleCheck(w, r)
	case "/assets/":
		serveAssets(w, r)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

// Обработчики маршрутов
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Ошибка рендеринга: %v", err)
	}
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	urlStr := r.FormValue("url")
	if !isValidURL(urlStr) {
		tmpl.Execute(w, map[string]interface{}{"Error": "Некорректный URL"})
		return
	}

	safe, threats, err := client.CheckURL(r.Context(), urlStr)
	if err != nil {
		tmpl.Execute(w, map[string]interface{}{"Error": "Ошибка проверки"})
		return
	}

	tmpl.Execute(w, map[string]interface{}{
		"Result":  safe,
		"Threats": threats,
	})
}

func serveAssets(w http.ResponseWriter, r *http.Request) {
	http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))).ServeHTTP(w, r)
}

func isValidURL(u string) bool {
	_, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}
	return regexp.MustCompile(`^(http(s)?:\/\/)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$`).MatchString(u)
}