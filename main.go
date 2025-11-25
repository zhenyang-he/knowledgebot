package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"knowledgebot/db"

	"github.com/gin-gonic/gin"
)

// Struct definitions
type SOPEventCallbackReq struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	TimeStamp uint64 `json:"timestamp"`
	AppID     string `json:"app_id"`
	Event     Event  `json:"event"`
}

// Jira Integration Structs
type JiraConfig struct {
	BaseURL  string
	Username string
	APIToken string
}

type JiraIssue struct {
	Key    string     `json:"key"`
	Fields JiraFields `json:"fields"`
}

type JiraFields struct {
	// Only the essential fields we need
	Status    JiraStatus    `json:"status"`
	Updated   string        `json:"updated"`
	Summary   string        `json:"summary"`
	Issuetype JiraIssuetype `json:"issuetype"`
	EpicLink  string        `json:"customfield_10001,omitempty"` // Epic Link custom field
	QADueDate string        `json:"customfield_10305,omitempty"` // QA Due Date custom field
}

type JiraStatus struct {
	Name string `json:"name"`
}

type JiraIssuetype struct {
	Name string `json:"name"`
}

type JiraSearchResult struct {
	Issues []JiraIssue `json:"issues"`
}

// JiraServiceResponse represents the response from the Jira service
type JiraServiceResponse struct {
	Issues []JiraIssue `json:"issues"`
	Error  string      `json:"error,omitempty"`
}

// QA Reminder tracking
type QAReminder struct {
	IssueKey       string    `json:"issue_key"`
	QAName         string    `json:"qa_name"`
	QAEmail        string    `json:"qa_email"`
	MessageID      string    `json:"message_id"`
	SentTime       time.Time `json:"sent_time"`
	LastSentTime   time.Time `json:"last_sent_time"`
	ReminderNumber int       `json:"reminder_number"`
	Summary        string    `json:"summary"`        // Store Jira ticket summary for easy access
	IssueType      string    `json:"issue_type"`     // Store Jira ticket type (Epic, Task, Bug, etc.)
	ButtonStatus   string    `json:"button_status"`  // Track button click status: "completed", "nothing_to_update", or ""
	UpdatedTime    time.Time `json:"updated_time"`   // Store Jira ticket update time
	CompletedTime  time.Time `json:"completed_time"` // Store when the button was actually clicked
}

// Group member info
type GroupMember struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

type SOPEventVerificationResp struct {
	SeatalkChallenge string `json:"seatalk_challenge"`
}

type Event struct {
	SeatalkChallenge string  `json:"seatalk_challenge"`
	EmployeeCode     string  `json:"employee_code"`
	DisplayName      string  `json:"display_name"`
	Email            string  `json:"email"`
	GroupID          string  `json:"group_id"`
	Message          Message `json:"message"`
	MessageID        string  `json:"message_id"`
	Value            string  `json:"value"`
}

type Message struct {
	Tag  string      `json:"tag"`
	Text TextMessage `json:"text"`
}

type TextMessage struct {
	Content   string `json:"content"`
	PlainText string `json:"plain_text"`
}

type AppAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpireTime  uint64 `json:"expire"`
}

type SOPAuthAppResp struct {
	Code           int    `json:"code"`
	AppAccessToken string `json:"app_access_token"`
	Expire         uint64 `json:"expire"`
}

type SOPSendMessageToUser struct {
	EmployeeCode string     `json:"employee_code"`
	Message      SOPMessage `json:"message"`
}

type SOPSendMessageToGroup struct {
	GroupID string     `json:"group_id"`
	Message SOPMessage `json:"message"`
}

type SOPMessage struct {
	Tag                string                 `json:"tag"`
	Text               *SOPTextMsg            `json:"text,omitempty"`
	InteractiveMessage *SOPInteractiveMessage `json:"interactive_message,omitempty"`
	ThreadID           string                 `json:"thread_id,omitempty"`
}

type SOPInteractiveMessage struct {
	Elements []SOPInteractiveElement `json:"elements"`
}

type SOPInteractiveElement struct {
	ElementType string                     `json:"element_type"`
	Title       *SOPInteractiveTitle       `json:"title,omitempty"`
	Description *SOPInteractiveDescription `json:"description,omitempty"`
	Button      *SOPInteractiveButton      `json:"button,omitempty"`
}

type SOPInteractiveTitle struct {
	Text string `json:"text"`
}

type SOPInteractiveDescription struct {
	Format int    `json:"format"`
	Text   string `json:"text"`
}

type SOPInteractiveButton struct {
	ButtonType   string `json:"button_type"`
	Text         string `json:"text"`
	Value        string `json:"value"`
	CallbackData string `json:"callback_data"`
	ActionID     string `json:"action_id"`
}

type SOPTextMsg struct {
	Format  int8   `json:"format"`
	Content string `json:"content"`
}

type SendMessageToUserResp struct {
	Code      int    `json:"code"`
	MessageID string `json:"message_id"`
}

// Global variables
var (
	appAccessToken AppAccessToken
	groupID        = "ODQ0ODgxNzk2Mjg5"                   // big group: ODQ0ODgxNzk2Mjg5, small group: OTIzMTMwNjE4MTI4, test group: NDY5MTA1MzQwMTI5
	alertResponses = make(map[string]map[string][]string) // messageID -> employeeCode -> [button_types_pressed]
	responseMutex  sync.RWMutex
	jiraServiceURL string

	// Event deduplication
	processedEvents = make(map[string]bool)
	eventMutex      sync.RWMutex

	// Daily message deduplication per member
	dailyMessagesSent = make(map[string]string) // employeeCode -> date
	dailyMessageMutex sync.RWMutex

	// Jira configuration (loaded from environment variables)
	jiraConfig = JiraConfig{
		BaseURL:  getEnvOrDefault("JIRA_BASE_URL", "https://jira.shopee.io"),
		Username: getEnvOrDefault("JIRA_USERNAME", ""),
		APIToken: getEnvOrDefault("JIRA_API_TOKEN", ""),
	}

	// QA Reminder tracking
	qaReminders   = make(map[string]*QAReminder) // issueKey -> QAReminder
	reminderMutex sync.RWMutex

	// Track reminder count for each QA member
	qaReminderCounts = make(map[string]int) // qaEmail -> current reminder count
	qaCountMutex     sync.RWMutex
)

// Generate the knowledge base status list message
func generateKnowledgeBaseList() string {
	// Calculate start of current week (Monday)
	now := getSingaporeTime()
	weekday := int(now.Weekday())
	// Convert Sunday (0) to 7, Monday (1) to 1, etc.
	if weekday == 0 {
		weekday = 7
	}
	// Calculate days to subtract to get to Monday
	daysToMonday := weekday - 1
	startOfWeek := now.AddDate(0, 0, -daysToMonday)
	startOfWeek = time.Date(startOfWeek.Year(), startOfWeek.Month(), startOfWeek.Day(), 0, 0, 0, 0, startOfWeek.Location())

	// Get all reminders
	reminderMutex.RLock()
	var completedReminders []*QAReminder
	var pendingReminders []*QAReminder

	for key, reminder := range qaReminders {
		// Skip main keys (they're not actual Jira tickets)
		if strings.HasPrefix(key, "main_") {
			continue
		}

		if !reminder.CompletedTime.IsZero() {
			// Only include completed reminders from this week
			if reminder.CompletedTime.After(startOfWeek) || reminder.CompletedTime.Equal(startOfWeek) {
				completedReminders = append(completedReminders, reminder)
			}
		} else {
			// Include all pending reminders
			pendingReminders = append(pendingReminders, reminder)
		}
	}
	reminderMutex.RUnlock()

	// Group reminders by QA name
	completedByQA := make(map[string][]*QAReminder)
	pendingByQA := make(map[string][]*QAReminder)

	for _, reminder := range completedReminders {
		completedByQA[reminder.QAName] = append(completedByQA[reminder.QAName], reminder)
	}

	for _, reminder := range pendingReminders {
		pendingByQA[reminder.QAName] = append(pendingByQA[reminder.QAName], reminder)
	}

	// Build the list message
	var listMsg strings.Builder
	listMsg.WriteString("📋 **Knowledge Base Status List**\n\n")

	// Completed section (shows only completed reminders from current week)
	listMsg.WriteString("✅ **Completed reminders this week:**\n")
	if len(completedByQA) == 0 {
		listMsg.WriteString("• None\n\n")
	} else {
		// Sort QA names for consistent ordering
		var qaNames []string
		for qaName := range completedByQA {
			qaNames = append(qaNames, qaName)
		}
		sort.Strings(qaNames)

		for _, qaName := range qaNames {
			listMsg.WriteString(fmt.Sprintf("**By %s**\n", qaName))
			for i, reminder := range completedByQA[qaName] {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)
				completedTime := reminder.CompletedTime.Format("Mon 3:04 PM")

				// Display button status
				var statusText string
				switch reminder.ButtonStatus {
				case "completed":
					statusText = " - **Completed**"
				case "nothing_to_update":
					statusText = " - **Nothing to update**"
				default:
					statusText = ""
				}

				// Display as numbered list
				listMsg.WriteString(fmt.Sprintf("%d) %s%s (%s)\n", i+1, jiraURL, statusText, completedTime))
			}
			listMsg.WriteString("\n")
		}
	}

	listMsg.WriteString("⏳ **All pending reminders:**\n")
	if len(pendingByQA) == 0 {
		listMsg.WriteString("• None\n")
	} else {
		// Sort QA names for consistent ordering
		var qaNames []string
		for qaName := range pendingByQA {
			qaNames = append(qaNames, qaName)
		}
		sort.Strings(qaNames)

		for _, qaName := range qaNames {
			listMsg.WriteString(fmt.Sprintf("**By %s**\n", qaName))
			for i, reminder := range pendingByQA[qaName] {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)
				// Display as numbered list
				listMsg.WriteString(fmt.Sprintf("%d) %s\n", i+1, jiraURL))
			}
			listMsg.WriteString("\n")
		}
	}

	return listMsg.String()
}

func main() {
	// Initialize database connection (optional - will continue without DB if not configured)
	if err := db.Init(); err != nil {
		log.Printf("WARN: Database not available (continuing with in-memory only): %v", err)
		log.Println("INFO: To enable persistence, set DATABASE_URL environment variable")
	} else {
		log.Println("INFO: Database connection established")
		// Load existing data from database
		if err := loadAllFromDB(); err != nil {
			log.Printf("WARN: Failed to load data from database: %v", err)
		} else {
			log.Printf("INFO: Loaded %d reminders from database", len(qaReminders))
		}
	}

	// Initialize Jira service URL
	jiraServiceURL = getEnvOrDefault("JIRA_SERVICE_URL", "")

	// Log configuration
	if jiraServiceURL != "" {
		log.Println("INFO: Using Jira service, skipping VPN connection")
	} else {
		log.Println("INFO: Using direct Jira API (VPN may be required)")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	r := gin.New()

	// Custom logger that skips callback and GET health check endpoints
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Skip logging for callback endpoints
		if param.Path == "/callback" {
			return ""
		}
		// Skip logging for GET /health and GET / (but log HEAD requests)
		if (param.Path == "/health" || param.Path == "/") && param.Method == "GET" {
			return ""
		}
		// Simplified format: IP, Method, Path, Status, Latency, UserAgent
		return fmt.Sprintf("%s %s %s %d %s %s\n",
			param.ClientIP,
			param.Method,
			param.Path,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
		)
	}))

	// Add panic recovery middleware to prevent crashes
	r.Use(gin.Recovery())

	// Health check endpoint for uptime monitoring (no signature validation needed)
	// Enhanced health check that verifies critical components
	healthHandler := func(ctx *gin.Context) {
		healthStatus := gin.H{
			"status": "healthy",
			"bot":    "knowledgebot",
			"time":   getSingaporeTime().Format("2006-01-02 15:04:05 GMT+8"),
		}

		// Check if critical components are accessible
		reminderMutex.RLock()
		reminderCount := len(qaReminders)
		reminderMutex.RUnlock()

		healthStatus["reminders_tracked"] = reminderCount
		healthStatus["uptime_check"] = "ok"

		ctx.JSON(http.StatusOK, healthStatus)
	}

	// Support GET and HEAD requests for health checks
	r.GET("/health", healthHandler)
	r.HEAD("/health", healthHandler)

	// Root path handler for uptime monitors that hit "/"
	r.GET("/", healthHandler)
	r.HEAD("/", healthHandler)

	// Callback endpoint with conditional signature validation
	r.POST("/callback", func(ctx *gin.Context) {
		var reqSOP SOPEventCallbackReq
		if err := ctx.ShouldBindJSON(&reqSOP); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}
		log.Printf("INFO: received event with event_type %s", reqSOP.EventType)

		// Event deduplication - check if event already processed
		eventMutex.Lock()
		if processedEvents[reqSOP.EventID] {
			log.Printf("INFO: Event %s already processed, skipping", reqSOP.EventID)
			eventMutex.Unlock()
			ctx.JSON(http.StatusOK, "Event already processed")
			return
		}
		processedEvents[reqSOP.EventID] = true
		eventMutex.Unlock()

		// Handle verification requests without signature validation
		if reqSOP.EventType == "event_verification" {
			ctx.JSON(http.StatusOK, SOPEventVerificationResp{SeatalkChallenge: reqSOP.Event.SeatalkChallenge})
			return
		}

		// For other events, skip signature validation for now (for testing)
		// TODO: Re-enable signature validation in production
		// if !validateSignature(ctx) {
		// 	return
		// }

		switch reqSOP.EventType {
		case "interactive_message_click":
			handleButtonClick(ctx, reqSOP)
			ctx.JSON(http.StatusOK, "Success")
		case "message_from_bot_subscriber":
			handlePrivateMessage(ctx, reqSOP)
			ctx.JSON(http.StatusOK, "Success")
		case "new_mentioned_message_received_from_group_chat":
			handleGroupMessage(ctx, reqSOP)
			ctx.JSON(http.StatusOK, "Success")
		case "user_enter_chatroom_with_bot":
			log.Printf("DEBUG: User entered chatroom - %s", getEmployeeDisplayNameWithCode(reqSOP.Event))
		case "new_message_received_from_thread":
			ctx.JSON(http.StatusOK, "Success")
		default:
			log.Printf("event %s not handled yet!", reqSOP.EventType)
			ctx.JSON(http.StatusOK, "Success")
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// Start QA reminder scheduler
	go startQAReminder()

	// Start cleanup scheduler for old completed reminders
	go startReminderCleanup()

	// Start HTTP server
	go func() {
		// Recover from panics to prevent service crash
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ERROR: Panic in HTTP server goroutine: %v", r)
				// Exit with non-zero code so Render knows to restart
				os.Exit(1)
			}
		}()

		log.Println("starting web, listening on", srv.Addr)
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("ERROR: HTTP server error on %s: %v", srv.Addr, err)
			// Don't use log.Fatalln - let Render handle restart via health checks
			// Exit with non-zero code so Render knows to restart
			os.Exit(1)
		}
	}()

	// Handle shutdown signals - wait for termination signal
	sig := <-c
	log.Printf("INFO: Received signal %v, initiating graceful shutdown", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	log.Println("shutting down web on", srv.Addr)
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("ERROR: failed shutdown server: %v", err)
		// Exit with non-zero code on shutdown failure so Render restarts
		os.Exit(1)
	}
	cancel()
	log.Println("web gracefully stopped")
	os.Exit(0)
}

func validateSignature(ctx *gin.Context) bool {
	r := ctx.Request
	signature := r.Header.Get("signature")

	if signature == "" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "missing signature"})
		return false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return false
	}

	hasher := sha256.New()
	signingSecret := getEnvOrDefault("SEATALK_SIGNING_SECRET", "")
	if signingSecret == "" {
		log.Printf("ERROR: SeaTalk signing secret not configured. Please set SEATALK_SIGNING_SECRET environment variable")
		ctx.JSON(http.StatusForbidden, gin.H{"error": "signing secret not configured"})
		return false
	}
	hasher.Write(append(body, []byte(signingSecret)...))
	targetSignature := hex.EncodeToString(hasher.Sum(nil))

	if signature != targetSignature {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "invalid signature"})
		return false
	}

	// Reset the request body for the next handler
	ctx.Request.Body = io.NopCloser(bytes.NewReader(body))
	return true
}

func WithSOPSignatureValidation() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !validateSignature(ctx) {
			return
		}
		ctx.Next()
	}
}

func GetAppAccessToken() AppAccessToken {
	timeNow := getSingaporeTime().Unix()

	accTokenIsEmpty := appAccessToken == AppAccessToken{}
	accTokenIsExpired := appAccessToken.ExpireTime < uint64(timeNow)

	if accTokenIsEmpty || accTokenIsExpired {
		appID := getEnvOrDefault("SEATALK_APP_ID", "")
		appSecret := getEnvOrDefault("SEATALK_APP_SECRET", "")
		if appID == "" || appSecret == "" {
			log.Printf("ERROR: SeaTalk credentials not configured. Please set SEATALK_APP_ID and SEATALK_APP_SECRET environment variables")
			return appAccessToken
		}
		body := []byte(fmt.Sprintf(`{"app_id": "%s", "app_secret": "%s"}`, appID, appSecret))

		req, err := http.NewRequest("POST", "https://openapi.seatalk.io/auth/app_access_token", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("ERROR: [GetAppAccessToken] failed to create an HTTP request: %v", err)
			return appAccessToken
		}

		req.Header.Add("Content-Type", "application/json")
		client := &http.Client{}

		res, err := client.Do(req)
		if err != nil {
			log.Printf("ERROR: [GetAppAccessToken] failed to make an HTTP call to seatalk openapi.seatalk.io: %v", err)
			return appAccessToken
		}
		defer res.Body.Close()

		responseBody, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			log.Printf("ERROR: [GetAppAccessToken] got non 200 HTTP response status code: %d, body: %s", res.StatusCode, string(responseBody))
			return appAccessToken
		}

		resp := &SOPAuthAppResp{}
		if err := json.NewDecoder(bytes.NewReader(responseBody)).Decode(resp); err != nil {
			log.Printf("ERROR: [GetAppAccessToken] failed to parse response body: %v", err)
			return appAccessToken
		}

		if resp.Code != 0 {
			log.Printf("ERROR: [GetAppAccessToken] response code is not 0, error code %d, please refer to the error code documentation https://open.seatalk.io/docs/reference_server-api-error-code", resp.Code)
			return appAccessToken
		}

		appAccessToken = AppAccessToken{
			AccessToken: resp.AppAccessToken,
			ExpireTime:  resp.Expire,
		}
	}

	return appAccessToken
}

func SendMessageToUser(ctx context.Context, message, employeeCode string) error {
	bodyJson, _ := json.Marshal(SOPSendMessageToUser{
		EmployeeCode: employeeCode,
		Message: SOPMessage{
			Tag: "text",
			Text: &SOPTextMsg{
				Format:  1, // Rich text format (use 2 for plain text)
				Content: message,
			},
		},
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/single_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	// Every SOP API need an authorization, to make sure that our Bot is authorized to call that API. We will use the token that we retrieved on the Step 2.
	accessToken := GetAppAccessToken()
	req.Header.Add("Authorization", "Bearer "+accessToken.AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return fmt.Errorf("something wrong, response code: %v", resp.Code)
	}

	return nil
}

func SendMessageToGroup(ctx context.Context, message, groupID string) (string, error) {
	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
		Message: SOPMessage{
			Tag: "text",
			Text: &SOPTextMsg{
				Format:  1, // Rich text format (use 2 for plain text)
				Content: message,
			},
		},
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}

	if resp.Code != 0 {
		return "", fmt.Errorf("failed to send group message, response code: %v", resp.Code)
	}

	return resp.MessageID, nil
}

func SendMessageToThread(ctx context.Context, message, groupID, threadID string) error {
	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
		Message: SOPMessage{
			Tag: "text",
			Text: &SOPTextMsg{
				Format:  1, // Rich text format (use 2 for plain text)
				Content: message,
			},
			ThreadID: threadID,
		},
	})

	req, _ := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send thread message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send thread message, response code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Read response body to check for API errors
	respBody := &SendMessageToUserResp{}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return fmt.Errorf("failed to decode thread message response: %v", err)
	}

	if respBody.Code != 0 {
		return fmt.Errorf("failed to send thread message, API error code: %v", respBody.Code)
	}

	return nil
}

// Helper function to send interactive messages to group (optionally in thread)
func SendInteractiveMessageToGroup(ctx context.Context, groupID, title, description, buttonID string, threadID ...string) (string, error) {
	// Create the base message structure
	message := SOPMessage{
		Tag: "interactive_message",
		InteractiveMessage: &SOPInteractiveMessage{
			Elements: []SOPInteractiveElement{
				{
					ElementType: "title",
					Title: &SOPInteractiveTitle{
						Text: title,
					},
				},
				{
					ElementType: "description",
					Description: &SOPInteractiveDescription{
						Format: 1,
						Text:   description,
					},
				},
				{
					ElementType: "button",
					Button: &SOPInteractiveButton{
						ButtonType:   "callback",
						Text:         "Complete ✅",
						Value:        "kb_complete_" + buttonID,
						CallbackData: "kb_complete_" + buttonID,
						ActionID:     "kb_complete_" + buttonID,
					},
				},
				{
					ElementType: "button",
					Button: &SOPInteractiveButton{
						ButtonType:   "callback",
						Text:         "Nothing to update 🚫",
						Value:        "kb_cancel_" + buttonID,
						CallbackData: "kb_cancel_" + buttonID,
						ActionID:     "kb_cancel_" + buttonID,
					},
				},
			},
		},
	}

	// Add thread ID if provided
	if len(threadID) > 0 && threadID[0] != "" {
		message.ThreadID = threadID[0]
	}

	// Always use SOPSendMessageToGroup (threading handled by ThreadID in message)
	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
		Message: message,
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}

	if resp.Code != 0 {
		return "", fmt.Errorf("failed to send interactive message, response code: %v", resp.Code)
	}

	return resp.MessageID, nil
}

// Retry function with exponential backoff for API calls
func retryWithBackoff(operation func() error, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if it's a 101 error (rate limiting/auth issue)
		if strings.Contains(err.Error(), "response code: 101") || strings.Contains(err.Error(), "API error code: 101") {
			// Exponential backoff: 1s, 2s, 4s, 8s, 16s
			backoffDuration := time.Duration(1<<uint(i)) * time.Second
			log.Printf("WARN: API error 101, retrying in %v (attempt %d/%d)", backoffDuration, i+1, maxRetries)
			time.Sleep(backoffDuration)
		} else {
			// For other errors, don't retry
			return err
		}
	}

	return fmt.Errorf("operation failed after %d retries, last error: %v", maxRetries, lastErr)
}

func SendMessageToGroupWithRetry(ctx context.Context, message, groupID string) (string, error) {
	var result string
	var err error

	retryErr := retryWithBackoff(func() error {
		result, err = SendMessageToGroup(ctx, message, groupID)
		return err
	}, 3) // Retry up to 3 times

	if retryErr != nil {
		return "", retryErr
	}
	return result, nil
}

// Wrapper functions with retry logic
func SendInteractiveMessageToGroupWithRetry(ctx context.Context, groupID, title, description, buttonID string, threadID ...string) (string, error) {
	var result string
	var err error

	retryErr := retryWithBackoff(func() error {
		result, err = SendInteractiveMessageToGroup(ctx, groupID, title, description, buttonID, threadID...)
		return err
	}, 3) // Retry up to 3 times

	if retryErr != nil {
		return "", retryErr
	}
	return result, nil
}

func SendMessageToThreadWithRetry(ctx context.Context, message, groupID, threadID string) error {
	return retryWithBackoff(func() error {
		return SendMessageToThread(ctx, message, groupID, threadID)
	}, 3) // Retry up to 3 times
}

// Send instructions as thread reply
func sendInstructionsAsThreadReply(groupID, threadID string) error {
	instructions := `📝 **Tasks to consider:**
• Review and update outdated information and data preparation steps
• Add new processes or solutions you've discovered
• Ensure all team knowledge is properly documented and up to date

📊 **Please review and update the knowledge base accordingly:**
https://docs.google.com/spreadsheets/d/1QlBZniYwL5VqKW1KQxjTs4LEGqOJ8YWRFTLhX-MZBtU/edit?gid=0#gid=0`

	return SendMessageToThreadWithRetry(context.Background(), instructions, groupID, threadID)
}

// Send main QA reminder (QA field only, no buttons)
func sendMainQAReminder(qa GroupMember, ticketCount int, isSilent bool) (string, error) {
	// Check if daily message already sent to this member
	if !checkAndMarkDailyMessage(qa.Email) {
		return "", fmt.Errorf("daily message already sent to %s today", qa.Email)
	}

	// Format date for title (e.g., "31 Oct 2025")
	todayFormatted := getSingaporeTime().Format("02 Jan 2006")
	title := fmt.Sprintf("**📚 [%s] Knowledge Base Reminder**", todayFormatted)
	var qaField string
	if !isSilent {
		qaField = fmt.Sprintf("**QA:** <mention-tag target=\"seatalk://user?email=%s\"/>", qa.Email)
	} else {
		qaField = fmt.Sprintf("**QA:** %s", qa.DisplayName)
	}
	message := fmt.Sprintf("%s\n%s\n📊 **Total tickets to review:** %d", title, qaField, ticketCount)

	// Send as plain text message without buttons
	messageID, err := SendMessageToGroupWithRetry(context.Background(), message, groupID)
	if err != nil {
		return "", err
	}

	// Store the main message ID for this QA (for threading)
	// Use a date-specific key format: "main_<qaEmail>_<date>"
	today := getSingaporeTime().Format("2006-01-02")
	mainKey := fmt.Sprintf("main_%s_%s", qa.Email, today)
	reminderMutex.Lock()
	reminder := &QAReminder{
		IssueKey:       mainKey,
		QAName:         qa.DisplayName,
		QAEmail:        qa.Email,
		MessageID:      messageID,
		SentTime:       getSingaporeTime(),
		LastSentTime:   getSingaporeTime(),
		ReminderNumber: 0,                  // Main reminder doesn't have a number
		UpdatedTime:    getSingaporeTime(), // Use current time for main reminder
	}
	qaReminders[mainKey] = reminder
	reminderMutex.Unlock()

	// Save to main_reminders table (only essential fields)
	if dbInstance := db.GetDB(); dbInstance != nil {
		dbReminder := &db.QAReminder{
			IssueKey:  reminder.IssueKey,
			QAEmail:   reminder.QAEmail,
			MessageID: reminder.MessageID,
			SentTime:  reminder.SentTime,
		}
		if err := dbInstance.SaveMainReminder(dbReminder); err != nil {
			log.Printf("WARN: Failed to save main reminder to database: %v", err)
		}
	}

	return messageID, nil
}

// Get next reminder number for a QA member
func getNextReminderNumber(qaEmail string) int {
	qaCountMutex.Lock()
	defer qaCountMutex.Unlock()

	qaReminderCounts[qaEmail]++
	count := qaReminderCounts[qaEmail]

	// Save to database
	if dbInstance := db.GetDB(); dbInstance != nil {
		if err := dbInstance.SaveReminderCount(qaEmail, count); err != nil {
			log.Printf("WARN: Failed to save reminder count to database: %v", err)
		}
	}

	return count
}

// Decrease reminder count when a reminder is completed
func decreaseReminderCount(qaEmail string) {
	qaCountMutex.Lock()
	defer qaCountMutex.Unlock()

	if qaReminderCounts[qaEmail] > 0 {
		qaReminderCounts[qaEmail]--
		count := qaReminderCounts[qaEmail]

		// Save to database
		if dbInstance := db.GetDB(); dbInstance != nil {
			if err := dbInstance.SaveReminderCount(qaEmail, count); err != nil {
				log.Printf("WARN: Failed to save reminder count to database: %v", err)
			}
		}
	}
}

// Send individual ticket reminder as thread reply
func sendTicketReminder(ticket JiraIssue, qa GroupMember, threadID string) error {
	jiraTicketWithTitle := formatJiraTicketWithTitle(&ticket)

	// Get the next reminder number for this QA (but don't commit until success)
	reminderNumber := getNextReminderNumber(qa.Email)
	title := fmt.Sprintf("📚 Knowledge Base Reminder %d", reminderNumber)

	// Parse Jira update time
	updatedTime := parseJiraUpdateTime(ticket.Fields.Updated)

	ticketType := ticket.Fields.Issuetype.Name
	description := fmt.Sprintf(`**Jira (%s):** %s
📅 **Completed Testing recently:** %s

Click the appropriate button below:`,
		ticketType, jiraTicketWithTitle, updatedTime.Format("02 Jan 2006"))

	buttonID := ticket.Key
	messageID, err := SendInteractiveMessageToGroupWithRetry(context.Background(), groupID, title, description, buttonID, threadID)
	if err != nil {
		// If sending fails, decrement the counter to "unuse" the number
		decreaseReminderCount(qa.Email)
		return err
	}

	// Track the reminder
	now := getSingaporeTime()
	reminderMutex.Lock()

	// Get the main message ID for this QA to use as thread ID
	// Use date-specific key format: "main_<qaEmail>_<date>"
	today := getSingaporeTime().Format("2006-01-02")
	mainKey := fmt.Sprintf("main_%s_%s", qa.Email, today)
	mainReminder := qaReminders[mainKey]
	var threadMessageID string
	if mainReminder != nil {
		threadMessageID = mainReminder.MessageID
	} else {
		// Fallback to individual message ID if main not found
		threadMessageID = messageID
		log.Printf("WARN: Main reminder not found for %s, using individual message ID as thread ID", qa.Email)
	}

	reminder := &QAReminder{
		IssueKey:       ticket.Key,
		QAName:         qa.DisplayName,
		QAEmail:        qa.Email,
		MessageID:      threadMessageID, // Store the main message ID for threading
		SentTime:       now,
		LastSentTime:   now,
		ReminderNumber: reminderNumber,
		Summary:        ticket.Fields.Summary,        // Store the Jira ticket summary
		IssueType:      ticket.Fields.Issuetype.Name, // Store the Jira ticket type
		ButtonStatus:   "",                           // Initialize as empty
		UpdatedTime:    updatedTime,                  // Store Jira update time
	}
	qaReminders[ticket.Key] = reminder
	reminderMutex.Unlock()

	// Save to database
	if dbInstance := db.GetDB(); dbInstance != nil {
		dbReminder := &db.QAReminder{
			IssueKey:       reminder.IssueKey,
			QAName:         reminder.QAName,
			QAEmail:        reminder.QAEmail,
			MessageID:      reminder.MessageID,
			SentTime:       reminder.SentTime,
			LastSentTime:   reminder.LastSentTime,
			ReminderNumber: reminder.ReminderNumber,
			Summary:        reminder.Summary,
			IssueType:      reminder.IssueType,
			ButtonStatus:   reminder.ButtonStatus,
			UpdatedTime:    reminder.UpdatedTime,
			CompletedTime:  reminder.CompletedTime,
		}
		if err := dbInstance.SaveReminder(dbReminder); err != nil {
			log.Printf("WARN: Failed to save ticket reminder to database: %v", err)
		}
	}

	return nil
}

// Jira QA Reminder Functions
func makeJiraRequest(method, endpoint string, body []byte) (*http.Response, error) {
	if jiraConfig.BaseURL == "" || jiraConfig.Username == "" || jiraConfig.APIToken == "" {
		return nil, fmt.Errorf("Jira configuration is incomplete, please check your environment variables")
	}

	url := jiraConfig.BaseURL + endpoint

	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		log.Printf("ERROR: Failed to create Jira request: %v", err)
		return nil, err
	}

	// Set Bearer token authentication instead of Basic Auth
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

// searchJiraQATicketsViaService calls the Jira service instead of direct Jira API
func searchJiraQATicketsViaService(qaEmail string) ([]JiraIssue, error) {
	if jiraServiceURL == "" {
		return nil, fmt.Errorf("JIRA_SERVICE_URL not configured")
	}

	// Prepare request body
	requestBody := map[string]string{
		"qa_email": qaEmail,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Make HTTP request to Jira service
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(jiraServiceURL+"/search", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to call Jira service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jira service returned %d: %s", resp.StatusCode, string(body))
	}

	var serviceResp JiraServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&serviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode Jira service response: %v", err)
	}

	if serviceResp.Error != "" {
		return nil, fmt.Errorf("Jira service error: %s", serviceResp.Error)
	}

	return serviceResp.Issues, nil
}

func searchJiraQATickets(qaEmail string) ([]JiraIssue, error) {
	// Use Jira service if configured, otherwise fall back to direct API
	if jiraServiceURL != "" {
		return searchJiraQATicketsViaService(qaEmail)
	}

	// Fallback to direct Jira API (for local development)
	// Calculate the date range for "recently updated" (last 2 business days)
	now := getSingaporeTime()
	var startDate time.Time

	// Calculate 2 business days ago
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
	// This reduces API response size and processing time
	jql := fmt.Sprintf("status in (\"2ND REVIEW\", \"UAT\", \"STAGING\", \"REGRESSION\", \"DELIVERING\", \"LIVE TESTING\", \"DONE\") AND QA in (\"%s\") AND type != \"Bug\" AND updated >= \"%s\"", qaEmail, startDateStr)

	// URL encode the JQL query
	encodedJQL := url.QueryEscape(jql)
	endpoint := fmt.Sprintf("/rest/api/2/search?jql=%s&maxResults=50&fields=status,updated,summary,issuetype,customfield_10001,customfield_10305", encodedJQL)
	resp, err := makeJiraRequest("GET", endpoint, nil)
	if err != nil {
		log.Printf("ERROR: Failed to search Jira tickets for %s: %v", qaEmail, err)
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

		if strings.Contains(contentType, "application/json") {
			log.Printf("ERROR: Jira API returned %d with JSON error: %s", resp.StatusCode, string(bodyBytes))
		} else {
			log.Printf("ERROR: Jira API returned %d with non-JSON response (Content-Type: %s). This suggests wrong endpoint or authentication issue.", resp.StatusCode, contentType)
			log.Printf("ERROR: Response body type: %s", contentType)
		}
		return nil, fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	var result JiraSearchResult
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		log.Printf("ERROR: Failed to decode Jira search response for %s: %v", qaEmail, err)
		return nil, err
	}

	return result.Issues, nil
}

func startQAReminder() {
	log.Println("INFO: Starting QA reminder scheduler")

	for {
		// Recover from panics in each iteration to prevent scheduler crash
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ERROR: Panic in QA reminder scheduler iteration: %v", r)
					// Continue to next iteration instead of crashing
				}
			}()

			// Clean up old daily message records
			cleanupOldDailyMessages()
			// Load Singapore timezone (GMT+8)
			location, err := time.LoadLocation("Asia/Singapore")
			if err != nil {
				location = time.UTC
			}
			now := time.Now().In(location)

			// Calculate next 10:00 AM in GMT+8
			next10am := time.Date(now.Year(), now.Month(), now.Day(), 10, 0, 0, 0, location)
			if now.After(next10am) {
				// If it's already past 10:00 today, schedule for tomorrow
				next10am = next10am.Add(24 * time.Hour)
			}

			// Skip weekends - find next weekday
			for next10am.Weekday() == time.Saturday || next10am.Weekday() == time.Sunday {
				next10am = next10am.Add(24 * time.Hour)
			}

			sleepDuration := next10am.Sub(now)
			log.Printf("INFO: Next QA reminder scheduled for %s GMT+8 (in %s)", next10am.Format("2006-01-02 15:04:05"), sleepDuration)
			time.Sleep(sleepDuration)

			// Skip weekends (already handled in the loop above)
			if next10am.Weekday() == time.Saturday || next10am.Weekday() == time.Sunday {
				return
			}

			log.Println("INFO: Running daily QA reminder check")
			sentCount, err := processQAReminders(false)
			if err != nil {
				log.Printf("ERROR: Failed to process QA reminders: %v", err)
			} else {
				log.Printf("INFO: Daily QA reminder check completed - %d new reminders sent", sentCount)
			}

			// Also check for 24-hour follow-ups
			if followUpCount, err := processFollowUpReminders(); err != nil {
				log.Printf("ERROR: Failed to process follow-up reminders: %v", err)
			} else if followUpCount > 0 {
				log.Printf("INFO: Processed %d follow-up reminders", followUpCount)
			}

			// Sleep for a minute to avoid running multiple times
			time.Sleep(time.Minute)
		}()
	}
}

func processQAReminders(isSilent bool) (int, error) {
	// Get group members
	members := getGroupMembers()
	totalSent := 0
	memberTicketCounts := make(map[string]int) // Track ticket counts per member

	for i, member := range members {
		// Search for Jira tickets assigned to this QA
		tickets, err := searchJiraQATickets(member.Email)
		if err != nil {
			log.Printf("ERROR: Failed to search Jira tickets for %s: %v", member.DisplayName, err)
			// Exit early if the first person's Jira call failed
			if i == 0 {
				return totalSent, fmt.Errorf("failed to search Jira tickets for first member %s: %w", member.DisplayName, err)
			}
			continue
		}
		log.Printf("INFO: Processing %d pre-filtered tickets for QA %s", len(tickets), member.Email)

		// Tickets are already filtered by JQL query (status + date), so we only need to check for existing reminders
		var eligibleTickets []JiraIssue
		skippedTickets := []string{}     // Tickets with Epic Links
		skippedOldDueDates := []string{} // Tickets where QA Due Date - Updated > 1 month
		existingReminders := []string{}  // Tickets that already have reminders

		for _, ticket := range tickets {
			reminderKey := ticket.Key

			// Skip tickets with Epic Link (via EpicLink custom field)
			if ticket.Fields.EpicLink != "" {
				skippedTickets = append(skippedTickets, ticket.Key)
				continue
			}

			// Skip if QA Due Date exists and the gap between QA Due Date and Updated time is more than 1 month
			if ticket.Fields.QADueDate != "" {
				// Parse QA Due Date (format: "2025-11-06")
				qaDueDate, err := time.Parse("2006-01-02", ticket.Fields.QADueDate)
				if err != nil {
					log.Printf("WARN: Failed to parse QA Due Date '%s' for ticket %s: %v", ticket.Fields.QADueDate, ticket.Key, err)
				} else {
					// Parse Updated time (format: "2025-11-11T13:56:44.000+0800")
					// Use same format as existing code (handles both +0800 and -0700)
					updatedTime, err := time.Parse("2006-01-02T15:04:05.999-0700", ticket.Fields.Updated)
					if err != nil {
						// Try alternative format
						updatedTime, err = time.Parse(time.RFC3339, ticket.Fields.Updated)
						if err != nil {
							log.Printf("WARN: Failed to parse Updated time '%s' for ticket %s: %v", ticket.Fields.Updated, ticket.Key, err)
						}
					}
					if err == nil {
						// Calculate the gap (Updated - QA Due Date)
						gap := updatedTime.Sub(qaDueDate)
						oneMonth := 30 * 24 * time.Hour // Approximate 1 month
						if gap > oneMonth {
							skippedOldDueDates = append(skippedOldDueDates, ticket.Key)
							continue
						}
					}
				}
			}

			reminderMutex.RLock()
			existingReminder := qaReminders[reminderKey]
			reminderMutex.RUnlock()

			// Only filter: Skip if reminder was already sent (exists in qaReminders)
			if existingReminder != nil {
				existingReminders = append(existingReminders, ticket.Key)
				continue
			}

			eligibleTickets = append(eligibleTickets, ticket)
		}

		// Log all existing reminders in one line
		if len(existingReminders) > 0 {
			ticketsList := strings.Join(existingReminders, ", ")
			log.Printf("DEBUG: Skipped %d existing reminders for %s: %s", len(existingReminders), member.DisplayName, ticketsList)
		}

		// Log all skipped tickets with Epic Links in one line
		if len(skippedTickets) > 0 {
			ticketsList := strings.Join(skippedTickets, ", ")
			log.Printf("DEBUG: Skipped %d reminders with epic links for %s: %s", len(skippedTickets), member.DisplayName, ticketsList)
		}

		// Log all skipped tickets with old QA Due Dates in one line
		if len(skippedOldDueDates) > 0 {
			ticketsList := strings.Join(skippedOldDueDates, ", ")
			log.Printf("DEBUG: Skipped %d old tickets for %s: %s", len(skippedOldDueDates), member.DisplayName, ticketsList)
		}

		// If no eligible tickets, skip this QA
		if len(eligibleTickets) == 0 {
			continue
		}

		// Check if main reminder already exists for today
		today := getSingaporeTime().Format("2006-01-02")
		mainKey := fmt.Sprintf("main_%s_%s", member.Email, today)
		reminderMutex.RLock()
		existingMainReminder := qaReminders[mainKey]
		reminderMutex.RUnlock()

		var mainMessageID string
		if existingMainReminder != nil {
			// Main reminder already exists, reuse its thread
			mainMessageID = existingMainReminder.MessageID
			log.Printf("INFO: Reusing existing main reminder thread for %s (message ID: %s)", member.DisplayName, mainMessageID)
		} else {
			// Send new main reminder (QA field only, no buttons)
			var err error
			mainMessageID, err = sendMainQAReminder(member, len(eligibleTickets), isSilent)
			if err != nil {
				log.Printf("ERROR: Failed to send main QA reminder to %s: %v", member.DisplayName, err)
				continue
			}

			// Send instructions as thread reply
			if err := sendInstructionsAsThreadReply(groupID, mainMessageID); err != nil {
				log.Printf("ERROR: Failed to send instructions thread reply: %v", err)
			}
		}

		// Send individual ticket reminders as thread replies
		sentCount := 0
		sentTickets := []string{}
		failedTickets := []JiraIssue{}
		for _, ticket := range eligibleTickets {
			if err := sendTicketReminder(ticket, member, mainMessageID); err != nil {
				log.Printf("ERROR: Failed to send ticket reminder for %s to %s: %v", ticket.Key, member.DisplayName, err)
				failedTickets = append(failedTickets, ticket)
			} else {
				sentCount++
				sentTickets = append(sentTickets, ticket.Key)
			}
		}

		// Send summary message if there were failed tickets
		if len(failedTickets) > 0 {
			summaryMsg := fmt.Sprintf("**Updated total tickets to review:** %d\n**Total tickets failed to send:** %d\n\n**Jira tickets:**\n", len(eligibleTickets), len(failedTickets))
			for _, ticket := range failedTickets {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticket.Key)
				summaryMsg += fmt.Sprintf("- %s\n", jiraURL)
			}

			if err := SendMessageToThreadWithRetry(context.Background(), summaryMsg, groupID, mainMessageID); err != nil {
				log.Printf("ERROR: Failed to send summary message for %s: %v", member.DisplayName, err)
			}
		}

		if sentCount > 0 {
			ticketsList := strings.Join(sentTickets, ", ")
			log.Printf("INFO: Sent %d new reminders to %s: %s", sentCount, member.DisplayName, ticketsList)
			memberTicketCounts[member.DisplayName] = sentCount
		}
		totalSent += sentCount
	}

	// Send summary message at the end of the day (only if not silent and reminders were sent)
	if totalSent > 0 {
		today := getSingaporeTime().Format("02 Jan 2006 (Monday)")

		// Build summary message with member breakdown
		summaryMsg := fmt.Sprintf("📚 **%s**\n", today)
		summaryMsg += "🌅 Good morning! "
		summaryMsg += `<mention-tag target="seatalk://user?email=shuang.xiao@shopee.com"/>` + "\n"
		summaryMsg += fmt.Sprintf("**%d** new reminders have been sent today.", totalSent)

		// Add per-member breakdown
		if len(memberTicketCounts) > 0 {
			// Sort member names for consistent ordering
			memberNames := make([]string, 0, len(memberTicketCounts))
			for name := range memberTicketCounts {
				memberNames = append(memberNames, name)
			}
			sort.Strings(memberNames)

			summaryMsg += "\n"
			for _, name := range memberNames {
				summaryMsg += fmt.Sprintf("%s - **%d** tickets\n", name, memberTicketCounts[name])
			}
			// Remove trailing newline
			summaryMsg = strings.TrimSuffix(summaryMsg, "\n")
		}

		if _, err := SendMessageToGroupWithRetry(context.Background(), summaryMsg, groupID); err != nil {
			log.Printf("ERROR: Failed to send daily summary message to boss: %v", err)
		}
	}

	return totalSent, nil
}

func processFollowUpReminders() (int, error) {
	reminderMutex.RLock()
	reminders := make([]*QAReminder, 0, len(qaReminders))
	for _, reminder := range qaReminders {
		reminders = append(reminders, reminder)
	}
	reminderMutex.RUnlock()

	now := getSingaporeTime()

	// Collect eligible reminders for follow-up
	eligibleReminders := make([]*QAReminder, 0)
	for _, reminder := range reminders {
		// Skip completed reminders
		// Check if CompletedTime is zero (0001-01-01 00:00:00 means not completed)
		if !reminder.CompletedTime.IsZero() {
			log.Printf("DEBUG: Skipping follow-up for %s - already completed at %s", reminder.IssueKey, reminder.CompletedTime.Format("2006-01-02 15:04:05"))
			continue
		}

		// Skip "main_" keys (they're not actual Jira tickets)
		if strings.HasPrefix(reminder.IssueKey, "main_") {
			continue
		}

		// Check if 20 hours have passed since last reminder
		timeSinceLastSent := now.Sub(reminder.LastSentTime)
		if timeSinceLastSent >= 20*time.Hour {
			eligibleReminders = append(eligibleReminders, reminder)
			log.Printf("DEBUG: Eligible follow-up for %s - %.1f hours since last sent", reminder.IssueKey, timeSinceLastSent.Hours())
		} else {
			log.Printf("DEBUG: Skipping follow-up for %s - only %.1f hours since last sent (need 20 hours)", reminder.IssueKey, timeSinceLastSent.Hours())
		}
	}

	// Sort by reminder number before sending
	sort.Slice(eligibleReminders, func(i, j int) bool {
		return eligibleReminders[i].ReminderNumber < eligibleReminders[j].ReminderNumber
	})

	// Send follow-up reminders in sorted order
	totalSent := 0
	memberTicketCounts := make(map[string]int) // Track ticket counts per member
	memberTickets := make(map[string][]string) // Track ticket keys per member
	for _, reminder := range eligibleReminders {
		// Create ticket object with key and summary for follow-ups
		ticket := JiraIssue{
			Key: reminder.IssueKey,
			Fields: JiraFields{
				Summary: reminder.Summary,
			},
		}

		member := GroupMember{
			DisplayName: reminder.QAName,
			Email:       reminder.QAEmail,
		}

		// Send follow-up reminder
		if err := sendFollowUpReminder(ticket, member); err != nil {
			log.Printf("ERROR: Failed to send follow-up reminder for %s: %v", reminder.IssueKey, err)
		} else {
			totalSent++
			memberTicketCounts[reminder.QAName]++
			memberTickets[reminder.QAName] = append(memberTickets[reminder.QAName], reminder.IssueKey)
		}
	}

	// Log all follow-up reminders sent per member in one line
	for memberName, tickets := range memberTickets {
		ticketsList := strings.Join(tickets, ", ")
		log.Printf("INFO: Sending %d follow-up reminders to %s: %s", len(tickets), memberName, ticketsList)
	}

	// Send summary message at the end (only if reminders were sent)
	if totalSent > 0 {
		today := getSingaporeTime().Format("02 Jan 2006 (Monday)")

		// Build summary message with member breakdown
		summaryMsg := fmt.Sprintf("**%s**\n", today)
		summaryMsg += "🌅 Good morning! "
		summaryMsg += `<mention-tag target="seatalk://user?email=shuang.xiao@shopee.com"/>` + "\n"
		summaryMsg += fmt.Sprintf("**%d** number of follow up reminders have been sent today.", totalSent)

		// Add per-member breakdown
		if len(memberTicketCounts) > 0 {
			// Sort member names for consistent ordering
			memberNames := make([]string, 0, len(memberTicketCounts))
			for name := range memberTicketCounts {
				memberNames = append(memberNames, name)
			}
			sort.Strings(memberNames)

			summaryMsg += "\n"
			for _, name := range memberNames {
				summaryMsg += fmt.Sprintf("%s - **%d** tickets\n", name, memberTicketCounts[name])
			}
			// Remove trailing newline
			summaryMsg = strings.TrimSuffix(summaryMsg, "\n")
		}

		if _, err := SendMessageToGroupWithRetry(context.Background(), summaryMsg, groupID); err != nil {
			log.Printf("ERROR: Failed to send follow-up summary message to boss: %v", err)
		}
	}

	return totalSent, nil
}

func sendFollowUpReminder(ticket JiraIssue, qa GroupMember) error {
	// This function handles follow-up reminders only
	// Main reminders are handled in the processQAReminders loop

	// Format Jira ticket with title
	jiraTicketWithTitle := formatJiraTicketWithTitle(&ticket)

	// Get the existing reminder for this ticket
	reminderMutex.RLock()
	existingReminder := qaReminders[ticket.Key]
	reminderMutex.RUnlock()

	// Create reminder message with appropriate prefix using the original reminder number
	title := fmt.Sprintf("📚 [Follow-up Required] Knowledge Base Reminder %d", existingReminder.ReminderNumber)

	// Create description for follow-ups (same format as regular reminders, with mention tag)
	ticketType := ticket.Fields.Issuetype.Name
	description := fmt.Sprintf(`**QA:** <mention-tag target="seatalk://user?email=%s"/>
**Jira (%s):** %s
📅 **Completed Testing recently:** %s

Click the appropriate button below:`,
		qa.Email, ticketType, jiraTicketWithTitle, existingReminder.UpdatedTime.Format("02 Jan 2006"))

	// Send as interactive thread reply using the original message ID as thread ID
	buttonID := ticket.Key
	_, err := SendInteractiveMessageToGroup(context.Background(), groupID, title, description, buttonID, existingReminder.MessageID)
	if err != nil {
		log.Printf("ERROR: Failed to send follow-up reminder in thread: %v", err)
		return err
	}

	// Update the LastSentTime for follow-ups, keep original SentTime
	now := getSingaporeTime()
	reminderMutex.Lock()
	existingReminder.LastSentTime = now
	reminderMutex.Unlock()

	// Save to database
	if dbInstance := db.GetDB(); dbInstance != nil {
		dbReminder := &db.QAReminder{
			IssueKey:       existingReminder.IssueKey,
			QAName:         existingReminder.QAName,
			QAEmail:        existingReminder.QAEmail,
			MessageID:      existingReminder.MessageID,
			SentTime:       existingReminder.SentTime,
			LastSentTime:   existingReminder.LastSentTime,
			ReminderNumber: existingReminder.ReminderNumber,
			Summary:        existingReminder.Summary,
			IssueType:      existingReminder.IssueType,
			ButtonStatus:   existingReminder.ButtonStatus,
			UpdatedTime:    existingReminder.UpdatedTime,
			CompletedTime:  existingReminder.CompletedTime,
		}
		if err := dbInstance.SaveReminder(dbReminder); err != nil {
			log.Printf("WARN: Failed to save follow-up reminder to database: %v", err)
		}
	}

	log.Printf("INFO: Follow-up QA reminder sent for %s to %s", ticket.Key, qa.DisplayName)
	return nil
}

// Send a status reminder with interactive buttons to a user privately
func sendStatusReminderToUser(reminder *QAReminder, employeeCode string) error {
	// Create a temporary JiraIssue to reuse formatJiraTicketWithTitle
	tempJiraIssue := JiraIssue{
		Key: reminder.IssueKey,
		Fields: JiraFields{
			Summary: reminder.Summary,
		},
	}
	jiraTicketWithTitle := formatJiraTicketWithTitle(&tempJiraIssue)

	// Use stored Jira update time
	recentlyCompletedTestingDate := reminder.UpdatedTime.Format("02 Jan 2006")

	// Calculate how long ago the reminder was sent (use LastSentTime for follow-ups)
	timeSinceSent := time.Since(reminder.LastSentTime)
	sentAgo := formatDuration(timeSinceSent)

	ticketType := reminder.IssueType
	description := fmt.Sprintf(`**Jira (%s):** %s
📅 **Completed Testing recently:** %s
⏰ **Latest reminder Sent:** %s ago

Click the appropriate button below:`,
		ticketType, jiraTicketWithTitle, recentlyCompletedTestingDate, sentAgo)

	// Create interactive message with buttons (include reminder number to match thread format)
	title := fmt.Sprintf("📚 Knowledge Base Reminder %d", reminder.ReminderNumber)
	// Use ticket key only as button ID (consistent with group reminders)
	buttonID := reminder.IssueKey

	bodyJson, _ := json.Marshal(SOPSendMessageToUser{
		EmployeeCode: employeeCode,
		Message: SOPMessage{
			Tag: "interactive_message",
			InteractiveMessage: &SOPInteractiveMessage{
				Elements: []SOPInteractiveElement{
					{
						ElementType: "title",
						Title: &SOPInteractiveTitle{
							Text: title,
						},
					},
					{
						ElementType: "description",
						Description: &SOPInteractiveDescription{
							Format: 1,
							Text:   description,
						},
					},
					{
						ElementType: "button",
						Button: &SOPInteractiveButton{
							ButtonType:   "callback",
							Text:         "Complete ✅",
							Value:        "kb_complete_" + buttonID,
							CallbackData: "kb_complete_" + buttonID,
							ActionID:     "kb_complete_" + buttonID,
						},
					},
					{
						ElementType: "button",
						Button: &SOPInteractiveButton{
							ButtonType:   "callback",
							Text:         "Nothing to update 🚫",
							Value:        "kb_cancel_" + buttonID,
							CallbackData: "kb_cancel_" + buttonID,
							ActionID:     "kb_cancel_" + buttonID,
						},
					},
				},
			},
		},
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/single_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return fmt.Errorf("failed to send interactive message to user, response code: %v", resp.Code)
	}

	log.Printf("INFO: Status reminder sent to user for ticket %s", reminder.IssueKey)
	return nil
}

func handlePrivateMessage(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	message := reqSOP.Event.Message.Text.Content
	if message == "" {
		message = reqSOP.Event.Message.Text.PlainText
	}

	displayName := getEmployeeDisplayNameWithCode(reqSOP.Event)
	log.Printf("INFO: private message received: %s, from: %s", message, displayName)

	messageLower := strings.ToLower(message)

	// Handle private message commands
	switch {
	case strings.Contains(messageLower, "debug") || strings.Contains(messageLower, "groupid"):
		debugMsg := `🔧 **Debug Info:**

📍 **Current Context:** Private Message
👤 **Your Employee Code:** ` + reqSOP.Event.EmployeeCode + `

💡 **To get group ID, mention me in the group with "debug"`

		if err := SendMessageToUser(ctx, debugMsg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send debug message: %v", err)
		}

	case strings.Contains(messageLower, "list"):
		// Generate the knowledge base list
		listMsg := generateKnowledgeBaseList()

		if err := SendMessageToUser(ctx, listMsg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send list message: %v", err)
		}

	case strings.Contains(messageLower, "status"):
		log.Printf("INFO: Status command received from: %s", getEmployeeDisplayNameWithCode(reqSOP.Event))

		// Get all incomplete reminders for this user
		reminderMutex.RLock()
		var userReminders []*QAReminder
		for key, reminder := range qaReminders {
			// Skip main keys (they're not actual Jira tickets)
			if strings.HasPrefix(key, "main_") {
				continue
			}

			if reminder.CompletedTime.IsZero() && (reminder.QAEmail == reqSOP.Event.Email || strings.Contains(reqSOP.Event.Email, reminder.QAEmail)) {
				userReminders = append(userReminders, reminder)
			}
		}
		reminderMutex.RUnlock()

		if len(userReminders) == 0 {
			noRemindersMsg := "✅ You have no pending QA reminders. Great job! 🎉"
			if err := SendMessageToUser(ctx, noRemindersMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send no reminders message: %v", err)
			}
		} else {
			// Sort reminders by reminder number before sending
			sort.Slice(userReminders, func(i, j int) bool {
				return userReminders[i].ReminderNumber < userReminders[j].ReminderNumber
			})

			// Send interactive message for each reminder
			for _, reminder := range userReminders {
				if err := sendStatusReminderToUser(reminder, reqSOP.Event.EmployeeCode); err != nil {
					log.Printf("ERROR: Failed to send status reminder for %s: %v", reminder.IssueKey, err)
				}
			}

			summaryMsg := fmt.Sprintf("📋 You have **%d** pending QA reminder(s). Please review and update accordingly.", len(userReminders))
			if err := SendMessageToUser(ctx, summaryMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send summary message: %v", err)
			}
		}

	case strings.Contains(messageLower, "sjira"):
		log.Printf("INFO: Silent Jira testing mode triggered by: %s", getEmployeeDisplayNameWithCode(reqSOP.Event))

		sentCount, err := processQAReminders(true)
		if err != nil {
			log.Printf("ERROR: Silent Jira testing failed: %v", err)
			errorMsg := "❌ Silent testing failed. Please check:\n• Jira service is accessible\n• Jira API credentials are set correctly\n📖 Please refer to the ENV_SETUP file for configuration instructions"
			if err := SendMessageToUser(ctx, errorMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			// Also process follow-up reminders in silent mode
			followUpCount := 0
			if count, err := processFollowUpReminders(); err != nil {
				log.Printf("ERROR: Failed to process follow-up reminders in silent mode: %v", err)
			} else {
				followUpCount = count
			}

			var confirmMsg string
			if sentCount == 0 && followUpCount == 0 {
				confirmMsg = "🔇 **Silent Testing Mode** - No new reminders found. All eligible tickets already have reminders."
				log.Printf("INFO: Silent Jira testing completed - no new reminders found")
			} else {
				confirmMsg = fmt.Sprintf("🔇 **Silent Testing Mode** - Found %d eligible ticket(s) that would have triggered reminders.", sentCount)
				if followUpCount > 0 {
					confirmMsg += fmt.Sprintf("\n📋 **Follow-up reminders:** %d reminder(s) sent.", followUpCount)
				}
				confirmMsg += "\n\n**Note:** No notifications were sent to the group."
				log.Printf("INFO: Silent Jira testing completed - %d eligible tickets found, %d follow-up reminders sent", sentCount, followUpCount)
			}

			if err := SendMessageToUser(ctx, confirmMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send confirmation: %v", err)
			}
		}

	case strings.Contains(messageLower, "jira"):
		log.Printf("INFO: Manual QA reminder trigger detected from: %s", getEmployeeDisplayNameWithCode(reqSOP.Event))

		sentCount, err := processQAReminders(false)
		if err != nil {
			log.Printf("ERROR: Manual QA reminder processing failed: %v", err)
			errorMsg := "❌ Failed to query Jira. Please check:\n• Jira service is accessible\n• Jira API credentials are set correctly\n📖 Please refer to the ENV_SETUP file for configuration instructions"
			if err := SendMessageToUser(ctx, errorMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			// Also process follow-up reminders
			followUpCount := 0
			if count, err := processFollowUpReminders(); err != nil {
				log.Printf("ERROR: Failed to process follow-up reminders: %v", err)
			} else {
				followUpCount = count
			}

			var confirmMsg string
			if sentCount == 0 && followUpCount == 0 {
				confirmMsg = "ℹ️ No new reminders to send. All eligible tickets already have reminders."
				log.Printf("INFO: Manual QA reminder check completed - no new reminders sent")
			} else {
				confirmMsg = fmt.Sprintf("✅ Successfully sent %d new QA reminder(s)!", sentCount)
				if followUpCount > 0 {
					confirmMsg += fmt.Sprintf("\n📋 **Follow-up reminders:** %d reminder(s) sent.", followUpCount)
				}
				confirmMsg += "\n\nCheck the group for the reminders."
				log.Printf("INFO: Manual QA reminder processing completed - %d reminders sent, %d follow-up reminders sent", sentCount, followUpCount)
			}

			if err := SendMessageToUser(ctx, confirmMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send confirmation: %v", err)
			}
		}

	case strings.Contains(messageLower, "help"):
		helpMsg := `🤖 **Knowledge Base Bot Commands**

**Private Messages:**
• "help" - Show this help message
• "debug" - Show debug information
• "list" - View all completed and pending reminders for the team
• "status" - View all your pending QA reminders with action buttons
• "jira" - Manually trigger QA Jira queries check
• "sjira" - Silent testing mode (check Jira without sending notifications)

**Group Messages:**
• "@KnowledgeBot debug" - Show group ID and debug info
• "@KnowledgeBot list" - Show completed (this week) and all pending QA reminders

**General Functions:**
- Only queries Jira tickets that have been moved past 2nd review recently within 2 working days (skips tickets with epic links)
- Will not send duplicated reminders with every trigger
- Will re-trigger in same thread with tags every 20 hours if reminder is not completed
- Auto-triggered every working day at 10am
- All data is persisted to database (survives service restarts)

**Cleanup Schedule:**
- Monthly cleanup (1st of each month at 12am):
  • Removes all completed reminders
  • Removes main reminders older than 7 days

**For Manager:**
- Can manually trigger Jira ticket queries via bot with "jira"
- Can check all pending QA reminders via bot with "list" to see all pending and completed reminders

**For Members:**
- Members can see their pending reminders via bot with "status" and can complete actions from there
- Members can only click on their own pending actions
- Members can switch buttons but can only click once`

		if err := SendMessageToUser(ctx, helpMsg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send help message: %v", err)
		}
	default:
		// Default response for other messages
		if err := SendMessageToUser(ctx, "Hello! Send 'help' to see available commands, 'alert' to trigger a knowledge base reminder, or 'qa' to manually check for QA reminders.", reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: something wrong when send message to user, error: %v", err)
		}
	}
}

func handleGroupMessage(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	message := reqSOP.Event.Message.Text.Content
	if message == "" {
		message = reqSOP.Event.Message.Text.PlainText
	}

	log.Printf("INFO: group message received: %s, in group: %s", message, reqSOP.Event.GroupID)

	messageLower := strings.ToLower(message)

	// Handle group message commands
	switch {
	case strings.Contains(messageLower, "debug") || strings.Contains(messageLower, "groupid"):
		debugMsg := `🔧 **Debug Info:**
🏢 **This Group ID:** ` + reqSOP.Event.GroupID

		if _, err := SendMessageToGroup(ctx, debugMsg, reqSOP.Event.GroupID); err != nil {
			log.Printf("ERROR: Failed to send debug message to group: %v", err)
		}

	case strings.Contains(messageLower, "list"):
		// Generate the knowledge base list
		listMsg := generateKnowledgeBaseList()

		if _, err := SendMessageToGroup(ctx, listMsg, reqSOP.Event.GroupID); err != nil {
			log.Printf("ERROR: Failed to send list message to group: %v", err)
		}
	default:
		// Respond to unrecognized commands with available options
		helpMsg := `🤖 **Knowledge Base Bot Commands**

**Available Commands:**
• "@KnowledgeBot list" - Show completed (this week) and all pending QA reminders
• "@KnowledgeBot debug" - Show group ID and debug info

**Private Commands:**
• Send me "help" privately for more commands

**Interactive Features:**
• Click "Complete" button to confirm knowledge base updated
• Click "Nothing to update" button if knowledge base is already clean and sleek`

		if _, err := SendMessageToGroup(ctx, helpMsg, reqSOP.Event.GroupID); err != nil {
			log.Printf("ERROR: Failed to send default help message to group: %v", err)
		}
	}
}

func handleButtonClick(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	// Extract message ID and button type from the button value
	var messageID, buttonType string
	if strings.Contains(reqSOP.Event.Value, "kb_complete_") {
		messageID = strings.TrimPrefix(reqSOP.Event.Value, "kb_complete_")
		buttonType = "complete"
	} else if strings.Contains(reqSOP.Event.Value, "kb_cancel_") {
		messageID = strings.TrimPrefix(reqSOP.Event.Value, "kb_cancel_")
		buttonType = "cancel"
	} else {
		log.Printf("WARNING: Unknown button value: '%s'", reqSOP.Event.Value)
		return
	}

	// Extract ticket key from messageID
	// Format can be either:
	//   - SPB-12345 (new format without timestamp)
	//   - SPB-12345_timestamp (old format with timestamp for backward compatibility)
	ticketKey := messageID
	if strings.Contains(messageID, "_") {
		// For regular reminders with timestamp, take the first part
		ticketKey = strings.Split(messageID, "_")[0]
	}

	// Check user's previous responses to this alert FIRST (before au@thorization)
	// This handles duplicate clicks gracefully
	responseMutex.Lock()
	if alertResponses[messageID] == nil {
		alertResponses[messageID] = make(map[string][]string)
	}

	userResponses := alertResponses[messageID][reqSOP.Event.EmployeeCode]

	// Check if user has already pressed both buttons
	hasComplete := slices.Contains(userResponses, "complete")
	hasCancel := slices.Contains(userResponses, "cancel")

	if hasComplete && hasCancel {
		responseMutex.Unlock()
		displayName := getEmployeeDisplayNameWithCode(reqSOP.Event)
		log.Printf("INFO: User %s has already used both buttons for alert %s, blocking further clicks", displayName, ticketKey)

		// Send private message to inform the user
		msg := fmt.Sprintf("⚠️ You have already responded to this reminder for ticket %s with both actions (Complete and Nothing to update). No further actions are possible.", ticketKey)
		if err := SendMessageToUser(ctx, msg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send blocked button click message to user: %v", err)
		}
		return
	}

	// Check if user is clicking the same button again
	if slices.Contains(userResponses, buttonType) {
		responseMutex.Unlock()
		displayName := getEmployeeDisplayNameWithCode(reqSOP.Event)
		log.Printf("INFO: User %s already clicked %s button for alert %s, ignoring duplicate", displayName, buttonType, ticketKey)

		// Send private message to inform the user
		var actionText string
		if buttonType == "complete" {
			actionText = "Complete"
		} else {
			actionText = "Nothing to update"
		}
		msg := fmt.Sprintf("ℹ️ You have already clicked the \"%s\" button for ticket %s. No further action is needed.", actionText, ticketKey)
		if err := SendMessageToUser(ctx, msg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send duplicate button click message to user: %v", err)
		}
		return
	}
	responseMutex.Unlock()

	// Check if the user clicking is the intended QA recipient for this specific ticket
	clickerEmail := reqSOP.Event.Email

	reminderMutex.RLock()
	var authorizedReminder *QAReminder
	if ticketKey != "" {
		reminder, exists := qaReminders[ticketKey]
		if exists {
			// Check if clicker email matches the assigned QA email (allow even if completed)
			if reminder.QAEmail == clickerEmail || strings.Contains(clickerEmail, reminder.QAEmail) {
				authorizedReminder = reminder
			}
		}
	}
	reminderMutex.RUnlock()

	if authorizedReminder == nil {
		// Send a private message to inform them
		unauthorizedMsg := fmt.Sprintf("⚠️ The reminder for %s is assigned to a specific QA team member. Only the assigned QA can respond to that reminder.", ticketKey)
		if err := SendMessageToUser(ctx, unauthorizedMsg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send unauthorized message: %v", err)
		}
		return
	}

	// Add this button type to user's response history
	responseMutex.Lock()
	alertResponses[messageID][reqSOP.Event.EmployeeCode] = append(userResponses, buttonType)
	isSecondButton := len(userResponses) > 0 // This will be the second button press
	responseMutex.Unlock()

	// Determine the group ID to send response to
	// If button was clicked from group, use that groupID
	// If clicked from private message (status command), use the configured groupID
	targetGroupID := reqSOP.Event.GroupID
	if targetGroupID == "" {
		targetGroupID = groupID // Use the configured group ID
	}

	// Use the main reminder message ID as thread ID for proper threading
	// This follows the SeaTalk pattern: "define thread_id as the message_id of the root message"
	threadID := ""
	// Get the main reminder message ID for this QA from qaReminders
	// We need to find the main reminder for the same date as the ticket reminder
	reminderMutex.RLock()
	for key, reminder := range qaReminders {
		if strings.HasPrefix(key, "main_") && reminder.QAEmail == authorizedReminder.QAEmail {
			// Check if this main reminder is from the same date as the ticket reminder
			if reminder.SentTime.Format("2006-01-02") == authorizedReminder.SentTime.Format("2006-01-02") {
				threadID = reminder.MessageID
				break
			}
		}
	}
	reminderMutex.RUnlock()

	// Process the button click
	switch buttonType {
	case "complete":
		// Mark as completed first so CompletedTime is available for response time calculation
		markQAReminderCompleted(ticketKey, "completed", reqSOP.Event)
		handleKnowledgeBaseComplete(ctx, reqSOP.Event, targetGroupID, threadID, isSecondButton, ticketKey)
	case "cancel":
		// Mark as completed first so CompletedTime is available for response time calculation
		markQAReminderCompleted(ticketKey, "nothing_to_update", reqSOP.Event)
		handleKnowledgeBaseCancel(ctx, reqSOP.Event, targetGroupID, threadID, isSecondButton, ticketKey)
	}
}

func handleKnowledgeBaseComplete(ctx *gin.Context, event Event, groupID, threadID string, isSecondButton bool, ticketKey string) {
	displayName := getEmployeeDisplayName(event) // For user-facing messages (no employee code)

	// Find the reminder for this specific ticket to get the sent time and issue type
	reminderMutex.RLock()
	var reminderSentTime time.Time
	var completedTime time.Time
	var ticketType string
	if reminder, exists := qaReminders[ticketKey]; exists {
		reminderSentTime = reminder.SentTime
		completedTime = reminder.CompletedTime
		ticketType = reminder.IssueType
	}
	reminderMutex.RUnlock()

	// Calculate duration and motivational message using only database values
	var durationMsg string
	var cheerMessage string
	if !reminderSentTime.IsZero() && !completedTime.IsZero() {
		duration := completedTime.Sub(reminderSentTime)
		durationMsg = fmt.Sprintf("\n⏱️ **Response Time:** %s", formatDuration(duration))
		cheerMessage = fmt.Sprintf("\n%s", getCheerMessage(duration))
	} else {
		// Show error if database values are missing
		durationMsg = "\n⏱️ **Response Time:** Unable to calculate"
	}

	// Add [Updated] prefix if this is the second button press
	titlePrefix := ""
	if isSecondButton {
		titlePrefix = "[Updated] "
	}

	// Use simple Jira URL without API call
	jiraTicketWithTitle := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticketKey)

	// Send confirmation message with timestamps
	completedTimeStr := "N/A"
	if !completedTime.IsZero() {
		completedTimeStr = completedTime.Format("2006-01-02 15:04:05")
	}
	reminderSentTimeStr := "N/A"
	if !reminderSentTime.IsZero() {
		reminderSentTimeStr = reminderSentTime.Format("2006-01-02 15:04:05")
	}

	confirmMsg := fmt.Sprintf(`✅ **%sKnowledge base is updated by %s**

🎫 **Jira (%s):** %s
📅 **Reminder Sent:** %s
📅 **Completed:** %s%s%s`,
		titlePrefix,
		displayName,
		ticketType,
		jiraTicketWithTitle,
		reminderSentTimeStr,
		completedTimeStr,
		durationMsg,
		cheerMessage,
	)

	// Send response in thread if threadID is available, otherwise send as regular group message
	if threadID != "" {
		if err := SendMessageToThreadWithRetry(ctx, confirmMsg, groupID, threadID); err != nil {
			log.Printf("ERROR: Failed to send completion confirmation to thread: %v", err)
		}
	}

	// If clicked from private message, also send confirmation to user privately
	if event.GroupID == "" {
		if err := SendMessageToUser(ctx, confirmMsg, event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send completion confirmation to user privately: %v", err)
		}
	}
}

func handleKnowledgeBaseCancel(ctx *gin.Context, event Event, groupID, threadID string, isSecondButton bool, ticketKey string) {
	displayName := getEmployeeDisplayName(event) // For user-facing messages (no employee code)

	// Find the reminder for this specific ticket to get the sent time and issue type
	reminderMutex.RLock()
	var reminderSentTime time.Time
	var cancelledTime time.Time
	var ticketType string
	if reminder, exists := qaReminders[ticketKey]; exists {
		reminderSentTime = reminder.SentTime
		cancelledTime = reminder.CompletedTime
		ticketType = reminder.IssueType
	}
	reminderMutex.RUnlock()

	// Calculate duration using only database values
	var durationMsg string
	if !reminderSentTime.IsZero() && !cancelledTime.IsZero() {
		duration := cancelledTime.Sub(reminderSentTime)
		durationMsg = fmt.Sprintf("\n⏱️ **Response Time:** %s", formatDuration(duration))
	} else {
		// Show error if database values are missing
		durationMsg = "\n⏱️ **Response Time:** Unable to calculate (missing timestamp data)"
	}

	// Add [Updated] prefix if this is the second button press
	titlePrefix := ""
	if isSecondButton {
		titlePrefix = "[Updated] "
	}

	// Use simple Jira URL without API call
	jiraTicketWithTitle := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticketKey)

	// Send cancellation message
	cancelledTimeStr := "N/A"
	if !cancelledTime.IsZero() {
		cancelledTimeStr = cancelledTime.Format("2006-01-02 15:04:05")
	}
	reminderSentTimeStr := "N/A"
	if !reminderSentTime.IsZero() {
		reminderSentTimeStr = reminderSentTime.Format("2006-01-02 15:04:05")
	}

	cancelMsg := fmt.Sprintf(`🚫 **%s%s acknowledged that knowledge base does not require update for this Jira ticket**

🎫 **Jira (%s):** %s
📅 **Reminder Sent:** %s
📅 **Acknowledged:** %s%s`,
		titlePrefix,
		displayName,
		ticketType,
		jiraTicketWithTitle,
		reminderSentTimeStr,
		cancelledTimeStr,
		durationMsg,
	)

	// Send response in thread if threadID is available, otherwise send as regular group message
	if threadID != "" {
		if err := SendMessageToThreadWithRetry(ctx, cancelMsg, groupID, threadID); err != nil {
			log.Printf("ERROR: Failed to send cancellation confirmation to thread: %v", err)
		}
	}

	// If clicked from private message, also send confirmation to user privately
	if event.GroupID == "" {
		if err := SendMessageToUser(ctx, cancelMsg, event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send cancellation confirmation to user privately: %v", err)
		}
	}
}

func markQAReminderCompleted(ticketKey, buttonStatus string, event Event) {
	reminderMutex.Lock()
	defer reminderMutex.Unlock()

	// Find the QA reminder by ticket key
	if reminder, exists := qaReminders[ticketKey]; exists {
		reminder.ButtonStatus = buttonStatus
		reminder.CompletedTime = getSingaporeTime() // Set the actual completion time

		// Log who completed it with employee code
		displayName := getEmployeeDisplayNameWithCode(event)
		log.Printf("INFO: QA reminder for %s marked as completed by %s with status: %s", ticketKey, displayName, buttonStatus)

		// Save to database
		if dbInstance := db.GetDB(); dbInstance != nil {
			dbReminder := &db.QAReminder{
				IssueKey:       reminder.IssueKey,
				QAName:         reminder.QAName,
				QAEmail:        reminder.QAEmail,
				MessageID:      reminder.MessageID,
				SentTime:       reminder.SentTime,
				LastSentTime:   reminder.LastSentTime,
				ReminderNumber: reminder.ReminderNumber,
				Summary:        reminder.Summary,
				IssueType:      reminder.IssueType,
				ButtonStatus:   reminder.ButtonStatus,
				UpdatedTime:    reminder.UpdatedTime,
				CompletedTime:  reminder.CompletedTime,
			}
			if err := dbInstance.SaveReminder(dbReminder); err != nil {
				log.Printf("WARN: Failed to save completed reminder to database: %v", err)
			}
		}

		// Decrease the reminder count for this QA
		decreaseReminderCount(reminder.QAEmail)
	} else {
		log.Printf("WARN: No reminder found for ticket %s when trying to mark as completed", ticketKey)
	}
}

// Start cleanup scheduler to remove completed reminders every month on the 1st at 12am
func startReminderCleanup() {
	// Recover from panics to prevent scheduler crash
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: Panic in reminder cleanup scheduler: %v", r)
			// Restart the scheduler after a delay
			time.Sleep(1 * time.Hour)
			go startReminderCleanup()
		}
	}()

	log.Println("INFO: Starting reminder cleanup scheduler (runs every month on the 1st at 12am)")

	for {
		now := getSingaporeTime()

		// Calculate next 1st of the month at 12am (midnight)
		nextFirst := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		if now.After(nextFirst) || now.Equal(nextFirst) {
			// Already past or at the 1st this month, schedule for next month
			nextFirst = nextFirst.AddDate(0, 1, 0)
		}

		// Wait until next 1st of the month at midnight
		sleepDuration := nextFirst.Sub(now)
		log.Printf("INFO: Next cleanup scheduled for %s GMT+8 (in %s)", nextFirst.Format("2006-01-02 15:04:05"), sleepDuration)
		time.Sleep(sleepDuration)

		// Run cleanup on the 1st of the month
		log.Println("INFO: Running monthly reminder cleanup (1st of month 12am)")
		if err := cleanupOldReminders(); err != nil {
			log.Printf("ERROR: Failed to cleanup old reminders: %v", err)
		}

		// Sleep for a minute to avoid running multiple times
		time.Sleep(time.Minute)
	}
}

// Remove all completed reminders
func cleanupOldReminders() error {
	reminderMutex.Lock()
	defer reminderMutex.Unlock()

	removedCount := 0
	for issueKey, reminder := range qaReminders {
		// Remove all completed reminders
		if !reminder.CompletedTime.IsZero() {
			delete(qaReminders, issueKey)
			removedCount++

			// Also remove from database
			if dbInstance := db.GetDB(); dbInstance != nil {
				if err := dbInstance.DeleteReminder(issueKey); err != nil {
					log.Printf("WARN: Failed to delete reminder %s from database: %v", issueKey, err)
				}
			}

			log.Printf("INFO: Removed completed reminder for %s (completed on %s)", issueKey, reminder.CompletedTime.Format("2006-01-02 15:04"))
		}
	}

	log.Printf("INFO: Cleanup complete. Removed %d completed reminders", removedCount)

	// Also cleanup old main reminders (older than 7 days)
	// Main reminders are only needed for threading recent reminders
	if dbInstance := db.GetDB(); dbInstance != nil {
		if err := dbInstance.DeleteOldMainReminders(7); err != nil {
			log.Printf("WARN: Failed to delete old main reminders from database: %v", err)
		} else {
			log.Printf("INFO: Cleaned up main reminders older than 7 days")
		}
	}

	return nil
}

func getEmployeeDisplayName(event Event) string {
	// Try to create a nice name from email
	if event.Email != "" {
		return formatEmailAsName(event.Email)
	}

	// Fallback to employee code
	return event.EmployeeCode
}

// getEmployeeDisplayNameWithCode returns display name with employee code in format "DisplayName (EmployeeCode)"
func getEmployeeDisplayNameWithCode(event Event) string {
	displayName := getEmployeeDisplayName(event)
	if event.EmployeeCode != "" {
		return fmt.Sprintf("%s (%s)", displayName, event.EmployeeCode)
	}
	return displayName
}

func formatEmailAsName(email string) string {
	// Extract name part from email (before @)
	// john.smith@company.com -> john.smith
	parts := strings.Split(email, "@")
	if len(parts) == 0 {
		return email
	}

	namePart := parts[0]

	// Convert dots and underscores to spaces and capitalize
	// john.smith -> John Smith
	namePart = strings.ReplaceAll(namePart, ".", " ")
	namePart = strings.ReplaceAll(namePart, "_", " ")

	// Capitalize each word
	words := strings.Fields(namePart)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "< 1s"
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string

	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 && days == 0 { // Only show seconds if less than a day
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	if len(parts) == 0 {
		return "< 1s"
	}

	return strings.Join(parts, "")
}

// Format Jira ticket with title
func formatJiraTicketWithTitle(issue *JiraIssue) string {
	jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, issue.Key)
	if issue.Fields.Summary != "" {
		return fmt.Sprintf("%s\n%s", jiraURL, issue.Fields.Summary)
	}
	return jiraURL
}

func getCheerMessage(duration time.Duration) string {
	hours := duration.Hours()
	// Seed the random number generator with current time
	rand.Seed(getSingaporeTime().UnixNano())

	switch {
	case hours <= 24: // Within a day
		messages := []string{
			"🚀 **Lightning fast!** You're on fire today! 🔥",
			"⚡ **Super speedy!** The team appreciates your quick action! 👏",
			"🌟 **Amazing response time!** You're a knowledge base hero! 🦸‍♂️",
			"💨 **Wow, that was quick!** Thanks for keeping our docs fresh! 📚✨",
			"🎯 **Bullseye!** Swift and efficient - just how we like it! 🏆",
		}
		return messages[rand.Intn(len(messages))]

	case hours <= 72: // Within 3 days
		messages := []string{
			"👍 **Great job!** Thanks for taking care of our knowledge base! 🙌",
			"📈 **Solid work!** Your contribution keeps the team informed! 💪",
			"🎉 **Well done!** The documentation is in good hands with you! 📖",
			"✨ **Nice work!** Every update makes our knowledge base better! 🌟",
			"🤝 **Team player!** Thanks for maintaining our shared knowledge! 🏅",
		}
		return messages[rand.Intn(len(messages))]

	case hours <= 168: // Within a week
		messages := []string{
			"🌱 **Better late than never!** Thanks for updating our docs! 📝",
			"🔄 **Good to see this completed!** Every update counts! 💯",
			"📚 **Knowledge preserved!** Thanks for keeping our docs current! 🛡️",
			"🎯 **Mission accomplished!** The team benefits from your effort! 🚀",
			"💡 **Great contribution!** Our knowledge base is stronger now! 🏗️",
		}
		return messages[rand.Intn(len(messages))]

	default: // More than a week
		messages := []string{
			"🎊 **Finally updated!** Better late than never - thanks! 🙏",
			"📖 **Knowledge restored!** Thanks for bringing this back to life! 🔄",
			"🌟 **Persistence pays off!** Great to see this completed! 💪",
			"🏆 **Victory at last!** The knowledge base thanks you! 📚",
			"🎉 **Worth the wait!** Thanks for not giving up on our docs! 🚀",
		}
		return messages[rand.Intn(len(messages))]
	}
}

func getGroupMembers() []GroupMember {
	members := []GroupMember{
		{
			Email:       "zhenyang.he@shopee.com",
			DisplayName: formatEmailAsName("zhenyang.he@shopee.com"),
		},
		{
			Email:       "vijay.krishnamraju@shopee.com",
			DisplayName: formatEmailAsName("vijay.krishnamraju@shopee.com"),
		},
		{
			Email:       "allyson.turiano@shopee.com",
			DisplayName: formatEmailAsName("allyson.turiano@shopee.com"),
		},
		{
			Email:       "ayush.bansal@shopee.com",
			DisplayName: formatEmailAsName("ayush.bansal@shopee.com"),
		},
		{
			Email:       "jingrui.hu@shopee.com",
			DisplayName: formatEmailAsName("jingrui.hu@shopee.com"),
		},
		{
			Email:       "joey.chengxy@shopee.com",
			DisplayName: formatEmailAsName("joey.chengxy@shopee.com"),
		},
		{
			Email:       "kangloon.ng@shopee.com",
			DisplayName: formatEmailAsName("kangloon.ng@shopee.com"),
		},
		{
			Email:       "shaoyun.tan@shopee.com",
			DisplayName: formatEmailAsName("shaoyun.tan@shopee.com"),
		},
	}

	return members
}

// Helper function to get environment variable with default value
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getSingaporeTime returns current time in Singapore timezone (GMT+8)
func getSingaporeTime() time.Time {
	location, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		// Fallback to UTC if Singapore timezone is not available
		return time.Now().UTC()
	}
	return time.Now().In(location)
}

// parseJiraUpdateTime parses Jira update time string and converts to Singapore time
func parseJiraUpdateTime(updatedStr string) time.Time {
	if updatedStr == "" {
		return getSingaporeTime() // Fallback to current time
	}

	// Parse the Jira timestamp
	t, err := time.Parse("2006-01-02T15:04:05.999-0700", updatedStr)
	if err != nil {
		// Try alternative format
		t, err = time.Parse(time.RFC3339, updatedStr)
		if err != nil {
			log.Printf("WARN: Failed to parse Jira update time %s: %v", updatedStr, err)
			return getSingaporeTime() // Fallback to current time
		}
	}

	// Convert to Singapore time
	location, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		return t // Return as-is if Singapore timezone not available
	}
	return t.In(location)
}

// checkAndMarkDailyMessage checks if a message was already sent to a member today
func checkAndMarkDailyMessage(email string) bool {
	today := getSingaporeTime().Format("2006-01-02")

	dailyMessageMutex.Lock()
	defer dailyMessageMutex.Unlock()

	// Check if message already sent today
	if lastSentDate, exists := dailyMessagesSent[email]; exists && lastSentDate == today {
		log.Printf("INFO: Daily message already sent to %s today, skipping", email)
		return false
	}

	// Mark message as sent today
	dailyMessagesSent[email] = today

	// Save to database
	if dbInstance := db.GetDB(); dbInstance != nil {
		if err := dbInstance.SaveDailyMessage(email, today); err != nil {
			log.Printf("WARN: Failed to save daily message to database: %v", err)
		}
	}

	return true
}

// cleanupOldDailyMessages removes old daily message records to prevent memory leaks
func cleanupOldDailyMessages() {
	today := getSingaporeTime().Format("2006-01-02")

	dailyMessageMutex.Lock()
	defer dailyMessageMutex.Unlock()

	// Remove records older than today
	for email, date := range dailyMessagesSent {
		if date != today {
			delete(dailyMessagesSent, email)
		}
	}
	// Also remove from database
	if dbInstance := db.GetDB(); dbInstance != nil {
		if err := dbInstance.DeleteOldDailyMessages(today); err != nil {
			log.Printf("WARN: Failed to delete old daily messages from database: %v", err)
		}
	}
}

// loadAllFromDB loads all data from database into memory
func loadAllFromDB() error {
	dbInstance := db.GetDB()
	if dbInstance == nil || !dbInstance.IsAvailable() {
		return fmt.Errorf("database not initialized")
	}

	// Load reminders
	reminders, err := dbInstance.LoadAllReminders()
	if err != nil {
		return fmt.Errorf("failed to load reminders: %w", err)
	}

	reminderMutex.Lock()
	for _, r := range reminders {
		qaReminders[r.IssueKey] = &QAReminder{
			IssueKey:       r.IssueKey,
			QAName:         r.QAName,
			QAEmail:        r.QAEmail,
			MessageID:      r.MessageID,
			SentTime:       r.SentTime,
			LastSentTime:   r.LastSentTime,
			ReminderNumber: r.ReminderNumber,
			Summary:        r.Summary,
			IssueType:      r.IssueType,
			ButtonStatus:   r.ButtonStatus,
			UpdatedTime:    r.UpdatedTime,
			CompletedTime:  r.CompletedTime,
		}
	}
	reminderMutex.Unlock()

	// Load main reminders (for threading purposes)
	mainReminders, err := dbInstance.LoadAllMainReminders()
	if err != nil {
		return fmt.Errorf("failed to load main reminders: %w", err)
	}

	reminderMutex.Lock()
	for _, r := range mainReminders {
		// Main reminders only store essential fields, set defaults for others
		qaReminders[r.IssueKey] = &QAReminder{
			IssueKey:       r.IssueKey,
			QAName:         formatEmailAsName(r.QAEmail), // Derive name from email
			QAEmail:        r.QAEmail,
			MessageID:      r.MessageID,
			SentTime:       r.SentTime,
			LastSentTime:   r.SentTime, // Use sent_time as last_sent_time
			ReminderNumber: 0,          // Main reminders don't have numbers
			Summary:        "",         // Not applicable
			IssueType:      "",         // Not applicable
			ButtonStatus:   "",         // Not applicable
			UpdatedTime:    r.SentTime,
			CompletedTime:  time.Time{}, // Never completed
		}
	}
	reminderMutex.Unlock()

	// Load reminder counts
	counts, err := dbInstance.LoadAllReminderCounts()
	if err != nil {
		return fmt.Errorf("failed to load reminder counts: %w", err)
	}

	qaCountMutex.Lock()
	maps.Copy(qaReminderCounts, counts)
	qaCountMutex.Unlock()

	// Load daily messages
	messages, err := dbInstance.LoadAllDailyMessages()
	if err != nil {
		return fmt.Errorf("failed to load daily messages: %w", err)
	}

	dailyMessageMutex.Lock()
	maps.Copy(dailyMessagesSent, messages)
	dailyMessageMutex.Unlock()

	return nil
}
