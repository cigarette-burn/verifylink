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
	"strings"
	"time"
)

// Конфигурация приложения
type Config struct {
	Port           string
	GoogleAPIKey   string
	GoogleClientID string
}

func loadConfig() Config {
	return Config{
		Port:           getEnv("PORT", "10000"), // Render использует порт 10000
		GoogleAPIKey:   mustGetEnv("GOOGLE_API_KEY"),
		GoogleClientID: getEnv("GOOGLE_CLIENT_ID", "securelink-render"),
	}
}

// Загрузка переменных окружения
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

// Клиент для Google Safe Browsing API
type GoogleClient struct {
	apiKey   string
	clientID string
	http     *http.Client
}

func NewGoogleClient(apiKey, clientID string) *GoogleClient {
	return &GoogleClient{
		apiKey:   apiKey,
		clientID: clientID,
		http:     &http.Client{Timeout: 15 * time.Second}, // Увеличенный таймаут
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
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", c.apiKey),
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return false, nil, fmt.Errorf("ошибка создания запроса: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("ошибка API запроса: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, nil, fmt.Errorf("ошибка декодирования ответа: %w", err)
	}

	threats := make([]string, 0, len(result.Matches))
	for _, m := range result.Matches {
		threats = append(threats, m.ThreatType)
	}

	return len(threats) == 0, threats, nil
}

// Глобальные переменные
var (
	tmpl   *template.Template
	client *GoogleClient
)

func init() {
	// Инициализация шаблонов
	initTemplates()
	
	// Инициализация клиента Google
	cfg := loadConfig()
	client = NewGoogleClient(cfg.GoogleAPIKey, cfg.GoogleClientID)
}

func initTemplates() {
    // Абсолютный путь для Render
    absPath := filepath.Join(filepath.Dir("."), "templates", "index.html")
    
    // Проверка существования файла
    if _, err := os.Stat(absPath); err != nil {
        log.Fatalf("Template file not found: %v", err)
    }

    // Парсинг с проверкой ошибок
    var err error
    tmpl, err = template.ParseFiles(absPath)
    if err != nil {
        log.Fatalf("Template parsing error: %v", err)
    }
    log.Printf("Template loaded successfully: %s", absPath)
}

// Обработчики маршрутов
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Cache-Control", "no-cache")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Ошибка рендеринга: %v", err)
		http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
	}
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	urlStr := r.FormValue("url")
	if !isValidURL(urlStr) {
		renderError(w, "Некорректный URL")
		return
	}

	safe, threats, err := client.CheckURL(r.Context(), urlStr)
	if err != nil {
		log.Printf("Ошибка проверки URL: %v", err)
		renderError(w, "Ошибка проверки безопасности")
		return
	}

	data := map[string]interface{}{
		"Result":  safe,
		"Threats": threats,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Ошибка рендеринга: %v", err)
	}
}

func renderError(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusBadRequest)
	if err := tmpl.Execute(w, map[string]interface{}{"Error": message}); err != nil {
		log.Printf("Ошибка рендеринга: %v", err)
	}
}

func serveStatic(w http.ResponseWriter, r *http.Request) {
	// Безопасная обработка путей
	cleanPath := filepath.Clean(r.URL.Path)
	fullPath := filepath.Join(filepath.Dir("."), "public", cleanPath)

	// Защита от directory traversal
	if !strings.HasPrefix(fullPath, filepath.Join(filepath.Dir("."), "public")) {
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}

	// Установка правильных Content-Type
	switch filepath.Ext(cleanPath) {
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	}

	http.ServeFile(w, r, fullPath)
}

func isValidURL(u string) bool {
	parsed, err := url.ParseRequestURI(u)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`).MatchString(u)
}

// Главная функция для Render
func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/check", handleCheck)
	mux.HandleFunc("/css/", serveStatic)
	mux.HandleFunc("/js/", serveStatic)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("Сервер запущен на порту %s", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Ошибка сервера: %v", err)
	}
}