package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// JiraConfig holds Jira configuration
type JiraConfig struct {
	BaseURL  string
	Username string
	APIToken string
}

// JiraIssue represents a Jira issue
type JiraIssue struct {
	Key    string `json:"key"`
	Fields struct {
		Summary string `json:"summary"`
		Status  struct {
			Name string `json:"name"`
		} `json:"status"`
		IssueType struct {
			Name string `json:"name"`
		} `json:"issuetype"`
		Updated  string     `json:"updated"`
		Parent   *JiraIssue `json:"parent,omitempty"`            // Parent Epic (if ticket is linked to an Epic)
		EpicLink string     `json:"customfield_10001,omitempty"` // Epic Link custom field
	} `json:"fields"`
}

// JiraSearchResult represents the response from Jira search API
type JiraSearchResult struct {
	Issues []JiraIssue `json:"issues"`
}

// SearchRequest represents the request to search Jira tickets
type SearchRequest struct {
	QAEmail string `json:"qa_email"`
}

// SearchResponse represents the response from search
type SearchResponse struct {
	Issues []JiraIssue `json:"issues"`
	Error  string      `json:"error,omitempty"`
}

var jiraConfig JiraConfig

func main() {
	// Load Jira configuration from environment variables
	jiraConfig = JiraConfig{
		BaseURL:  getEnvOrDefault("JIRA_BASE_URL", "https://jira.shopee.io"),
		Username: getEnvOrDefault("JIRA_USERNAME", ""),
		APIToken: getEnvOrDefault("JIRA_API_TOKEN", ""),
	}

	// Validate configuration
	if jiraConfig.BaseURL == "" || jiraConfig.Username == "" || jiraConfig.APIToken == "" {
		log.Fatal("Jira configuration is incomplete. Please set JIRA_BASE_URL, JIRA_USERNAME, and JIRA_API_TOKEN environment variables.")
	}

	// Set Gin to release mode for production
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	// Add CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Search Jira tickets endpoint
	r.POST("/search", searchJiraTickets)

	// Get port from environment or use default
	port := getEnvOrDefault("PORT", "8082")
	log.Printf("Jira service starting on port %s", port)
	log.Fatal(r.Run(":" + port))
}

func searchJiraTickets(c *gin.Context) {
	var req SearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, SearchResponse{Error: "Invalid request format"})
		return
	}

	if req.QAEmail == "" {
		c.JSON(400, SearchResponse{Error: "qa_email is required"})
		return
	}

	// Search for Jira tickets
	issues, err := searchJiraQATickets(req.QAEmail)
	if err != nil {
		log.Printf("ERROR: Failed to search Jira tickets for %s: %v", req.QAEmail, err)
		c.JSON(500, SearchResponse{Error: fmt.Sprintf("Failed to search Jira tickets: %v", err)})
		return
	}

	c.JSON(200, SearchResponse{Issues: issues})
}

func searchJiraQATickets(qaEmail string) ([]JiraIssue, error) {
	// Calculate the date range for "recently updated" (last 2 business days)
	now := time.Now()
	var startDate time.Time

	switch now.Weekday() {
	case time.Monday:
		// Previous business day is Friday (3 days ago)
		startDate = now.AddDate(0, 0, -3)
	case time.Sunday:
		// Previous business day is Friday (2 days ago)
		startDate = now.AddDate(0, 0, -2)
	default:
		// Previous business day is yesterday
		startDate = now.AddDate(0, 0, -1)
	}

	// Format date for JQL (YYYY-MM-DD)
	startDateStr := startDate.Format("2006-01-02")

	// Query tickets with both status and date filtering at Jira level
	jql := fmt.Sprintf("status in (\"2ND REVIEW\", \"UAT\", \"STAGING\", \"REGRESSION\", \"DELIVERING\", \"LIVE TESTING\", \"DONE\") AND QA in (\"%s\") AND type != \"Bug\" AND updated >= \"%s\"", qaEmail, startDateStr)

	// URL encode the JQL query
	encodedJQL := url.QueryEscape(jql)

	endpoint := fmt.Sprintf("/rest/api/2/search?jql=%s&maxResults=50&fields=status,updated,summary,issuetype,parent,customfield_10001", encodedJQL)
	resp, err := makeJiraRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read Jira API response body: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		contentType := resp.Header.Get("Content-Type")

		if contentType == "application/json" {
			log.Printf("ERROR: Jira API returned %d with JSON error: %s", resp.StatusCode, string(bodyBytes))
		} else {
			log.Printf("ERROR: Jira API returned %d with non-JSON response (Content-Type: %s)", resp.StatusCode, contentType)
		}
		return nil, fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	var result JiraSearchResult
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		log.Printf("ERROR: Failed to decode Jira search response: %v", err)
		return nil, err
	}

	return result.Issues, nil
}

func makeJiraRequest(method, endpoint string, body []byte) (*http.Response, error) {
	url := jiraConfig.BaseURL + endpoint

	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, err
	}

	// Set Bearer token authentication
	req.Header.Set("Authorization", "Bearer "+jiraConfig.APIToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		log.Printf("ERROR: Jira API request failed: %v", err)
		return nil, err
	}

	return resp, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
