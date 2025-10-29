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
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

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
	IssueKey       string
	QAName         string
	QAEmail        string
	MessageID      string
	SentTime       time.Time
	LastSentTime   time.Time
	Completed      bool
	ReminderNumber int
	Summary        string    // Store Jira ticket summary for easy access
	ButtonStatus   string    // Track button click status: "completed", "nothing_to_update", or ""
	UpdatedTime    time.Time // Store Jira ticket update time
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
	groupID        = "ODQ0ODgxNzk2Mjg5"                   // big group: ODQ0ODgxNzk2Mjg5, small group: OTIzMTMwNjE4MTI4
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
	// Get all reminders
	reminderMutex.RLock()
	var completedReminders []*QAReminder
	var pendingReminders []*QAReminder

	for key, reminder := range qaReminders {
		// Skip main keys (they're not actual Jira tickets)
		if strings.HasPrefix(key, "main_") {
			continue
		}

		if reminder.Completed {
			completedReminders = append(completedReminders, reminder)
		} else {
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

	// Completed section (shows all completed reminders until next Monday cleanup)
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
				completedTime := reminder.LastSentTime.Format("Mon 3:04 PM")

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
	r := gin.Default()

	// Health check endpoint for uptime monitoring (no signature validation needed)
	healthHandler := func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"bot":    "knowledgebot",
			"time":   getSingaporeTime().Format("2006-01-02 15:04:05 GMT+8"),
		})
	}

	// Support both GET and HEAD requests for health checks
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
			log.Printf("DEBUG: User entered chatroom - %s", getEmployeeDisplayName(reqSOP.Event))
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

	go func() {
		log.Println("starting web, listening on", srv.Addr)
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalln("failed starting web on", srv.Addr, err)
		}
	}()

	for {
		<-c
		log.Println("terminate service")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		log.Println("shutting down web on", srv.Addr)
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalln("failed shutdown server", err)
		}
		cancel()
		log.Println("web gracefully stopped")
		os.Exit(0)
	}
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

	title := "**📚 Knowledge Base Reminder**"
	var qaField string
	if !isSilent {
		qaField = fmt.Sprintf("**QA:** <mention-tag target=\"seatalk://user?email=%s\"/> (cc: <mention-tag target=\"seatalk://user?email=shuang.xiao@shopee.com\"/>)", qa.Email)
	} else {
		qaField = fmt.Sprintf("**QA:** %s", qa.DisplayName)
	}
	message := fmt.Sprintf("%s\n%s\n📊 **Total tickets to review:** %d", title, qaField, ticketCount)

	// Send as plain text message without buttons
	messageID, err := SendMessageToGroup(context.Background(), message, groupID)
	if err != nil {
		return "", err
	}

	// Store the main message ID for this QA (for threading)
	// Use a date-specific key format: "main_<qaEmail>_<date>"
	today := getSingaporeTime().Format("2006-01-02")
	mainKey := fmt.Sprintf("main_%s_%s", qa.Email, today)
	reminderMutex.Lock()
	qaReminders[mainKey] = &QAReminder{
		IssueKey:       mainKey,
		QAName:         qa.DisplayName,
		QAEmail:        qa.Email,
		MessageID:      messageID,
		SentTime:       getSingaporeTime(),
		LastSentTime:   getSingaporeTime(),
		Completed:      false,
		ReminderNumber: 0,                  // Main reminder doesn't have a number
		UpdatedTime:    getSingaporeTime(), // Use current time for main reminder
	}
	reminderMutex.Unlock()

	return messageID, nil
}

// Get next reminder number for a QA member
func getNextReminderNumber(qaEmail string) int {
	qaCountMutex.Lock()
	defer qaCountMutex.Unlock()

	qaReminderCounts[qaEmail]++
	return qaReminderCounts[qaEmail]
}

// Decrease reminder count when a reminder is completed
func decreaseReminderCount(qaEmail string) {
	qaCountMutex.Lock()
	defer qaCountMutex.Unlock()

	if qaReminderCounts[qaEmail] > 0 {
		qaReminderCounts[qaEmail]--
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

	description := fmt.Sprintf(`**Jira Ticket:** %s
📅 **Completed Testing recently:** %s

Click the appropriate button below when done:`,
		jiraTicketWithTitle, updatedTime.Format("02 Jan 2006"))

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

	qaReminders[ticket.Key] = &QAReminder{
		IssueKey:       ticket.Key,
		QAName:         qa.DisplayName,
		QAEmail:        qa.Email,
		MessageID:      threadMessageID, // Store the main message ID for threading
		SentTime:       now,
		LastSentTime:   now,
		Completed:      false,
		ReminderNumber: reminderNumber,
		Summary:        ticket.Fields.Summary, // Store the Jira ticket summary
		ButtonStatus:   "",                    // Initialize as empty
		UpdatedTime:    updatedTime,           // Store Jira update time
	}
	reminderMutex.Unlock()

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

	endpoint := fmt.Sprintf("/rest/api/2/search?jql=%s&maxResults=50&fields=status,updated,summary,issuetype", encodedJQL)
	resp, err := makeJiraRequest("GET", endpoint, nil)
	if err != nil {
		log.Printf("ERROR: Failed to search Jira tickets for %s: %v", qaEmail, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Check if response is JSON or HTML
		body, _ := io.ReadAll(resp.Body)
		contentType := resp.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			log.Printf("ERROR: Jira API returned %d with JSON error: %s", resp.StatusCode, string(body))
		} else {
			log.Printf("ERROR: Jira API returned %d with non-JSON response (Content-Type: %s). This suggests wrong endpoint or authentication issue.", resp.StatusCode, contentType)
			log.Printf("ERROR: Response body type: %s", contentType)
		}
		return nil, fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	var result JiraSearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("ERROR: Failed to decode Jira search response for %s: %v", qaEmail, err)
		return nil, err
	}

	return result.Issues, nil
}

func startQAReminder() {
	log.Println("INFO: Starting QA reminder scheduler")

	for {
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
			continue
		}

		log.Println("INFO: Running daily QA reminder check")
		sentCount, err := processQAReminders(false)
		if err != nil {
			log.Printf("ERROR: Failed to process QA reminders: %v", err)
		} else {
			log.Printf("INFO: Daily QA reminder check completed - %d new reminders sent", sentCount)
		}

		// Also check for 24-hour follow-ups
		if err := processFollowUpReminders(); err != nil {
			log.Printf("ERROR: Failed to process follow-up reminders: %v", err)
		}

		// Sleep for a minute to avoid running multiple times
		time.Sleep(time.Minute)
	}
}

func processQAReminders(isSilent bool) (int, error) {
	// Get group members
	members := getGroupMembers()
	totalSent := 0
	errorCount := 0

	for _, member := range members {
		// Search for Jira tickets assigned to this QA
		tickets, err := searchJiraQATickets(member.Email)
		if err != nil {
			log.Printf("ERROR: Failed to search Jira tickets for %s: %v", member.DisplayName, err)
			errorCount++
			continue
		}

		// Tickets are already filtered by JQL query (status + date), so we only need to check for existing reminders
		var eligibleTickets []JiraIssue
		log.Printf("DEBUG: Processing %d pre-filtered tickets for QA %s", len(tickets), member.Email)
		for _, ticket := range tickets {
			reminderKey := ticket.Key
			log.Printf("DEBUG: Checking ticket %s (Status: %s, Updated: %s)", ticket.Key, ticket.Fields.Status.Name, ticket.Fields.Updated)

			reminderMutex.RLock()
			existingReminder := qaReminders[reminderKey]
			reminderMutex.RUnlock()

			// Only filter: Skip if reminder was already sent (exists in qaReminders)
			if existingReminder != nil {
				log.Printf("DEBUG: Ticket %s already has reminder, skipping", ticket.Key)
				continue
			}

			eligibleTickets = append(eligibleTickets, ticket)
		}

		// If no eligible tickets, skip this QA
		if len(eligibleTickets) == 0 {
			continue
		}

		// Send main reminder (QA field only, no buttons)
		mainMessageID, err := sendMainQAReminder(member, len(eligibleTickets), isSilent)
		if err != nil {
			log.Printf("ERROR: Failed to send main QA reminder to %s: %v", member.DisplayName, err)
			continue
		}

		// Send instructions as thread reply
		if err := sendInstructionsAsThreadReply(groupID, mainMessageID); err != nil {
			log.Printf("ERROR: Failed to send instructions thread reply: %v", err)
		}

		// Send individual ticket reminders as thread replies
		sentCount := 0
		failedTickets := []JiraIssue{}
		for _, ticket := range eligibleTickets {
			if err := sendTicketReminder(ticket, member, mainMessageID); err != nil {
				log.Printf("ERROR: Failed to send ticket reminder for %s to %s: %v", ticket.Key, member.DisplayName, err)
				failedTickets = append(failedTickets, ticket)
			} else {
				sentCount++
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
			log.Printf("INFO: Sent %d new reminders to %s", sentCount, member.DisplayName)
		}
		totalSent += sentCount
	}

	// If all members had errors, return an error
	if errorCount > 0 && errorCount == len(members) {
		return totalSent, fmt.Errorf("failed to query Jira for all team members")
	}

	return totalSent, nil
}

func processFollowUpReminders() error {
	reminderMutex.RLock()
	reminders := make([]*QAReminder, 0, len(qaReminders))
	for _, reminder := range qaReminders {
		reminders = append(reminders, reminder)
	}
	reminderMutex.RUnlock()

	now := getSingaporeTime()

	for _, reminder := range reminders {
		// Skip completed reminders
		if reminder.Completed {
			continue
		}

		// Check if 24 hours have passed since last reminder
		if now.Sub(reminder.LastSentTime) >= 24*time.Hour {
			log.Printf("INFO: Sending 24-hour follow-up reminder for %s to %s", reminder.IssueKey, reminder.QAName)

			// Create a minimal ticket object with just the key (status doesn't matter for follow-ups)
			ticket := JiraIssue{
				Key: reminder.IssueKey,
			}

			member := GroupMember{
				DisplayName: reminder.QAName,
				Email:       reminder.QAEmail,
			}

			// Send follow-up reminder
			if err := sendFollowUpReminder(ticket, member); err != nil {
				log.Printf("ERROR: Failed to send follow-up reminder for %s: %v", reminder.IssueKey, err)
			}
		}
	}

	return nil
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

	// Create description for follow-ups
	description := fmt.Sprintf(`**Jira Ticket:** %s
📅 **Completed Testing recently:** %s

Click the appropriate button below when done:`,
		jiraTicketWithTitle, existingReminder.UpdatedTime.Format("02 Jan 2006"))

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

	log.Printf("INFO: Follow-up QA reminder sent for %s to %s", ticket.Key, qa.DisplayName)
	return nil
}

// Send a status reminder with interactive buttons to a user privately
func sendStatusReminderToUser(reminder *QAReminder, employeeCode string) error {
	// Use simple Jira URL without API call
	jiraTicketWithTitle := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)

	// Use stored Jira update time
	recentlyCompletedTestingDate := reminder.UpdatedTime.Format("02 Jan 2006")

	// Calculate how long ago the reminder was sent
	timeSinceSent := time.Since(reminder.SentTime)
	sentAgo := formatDuration(timeSinceSent)

	// Create description
	description := fmt.Sprintf(`🎫 **Jira Ticket:** %s
📅 **Completed Testing recently:** %s
⏰ **Reminder Sent:** %s ago

Please review and update the knowledge base accordingly.

Click the appropriate button when done:`, jiraTicketWithTitle, recentlyCompletedTestingDate, sentAgo)

	// Create interactive message with buttons
	title := fmt.Sprintf("📚 Knowledge Base Reminder: %s", reminder.IssueKey)
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

	displayName := getEmployeeDisplayName(reqSOP.Event)
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
		log.Printf("INFO: Status command received from: %s (%s)", displayName, reqSOP.Event.Email)

		// Get all incomplete reminders for this user
		reminderMutex.RLock()
		var userReminders []*QAReminder
		for key, reminder := range qaReminders {
			// Skip main keys (they're not actual Jira tickets)
			if strings.HasPrefix(key, "main_") {
				continue
			}

			if !reminder.Completed && (reminder.QAEmail == reqSOP.Event.Email || strings.Contains(reqSOP.Event.Email, reminder.QAEmail)) {
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
		log.Printf("INFO: Silent Jira testing mode triggered by: %s", displayName)

		sentCount, err := processQAReminders(true)
		if err != nil {
			log.Printf("ERROR: Silent Jira testing failed: %v", err)
			errorMsg := "❌ Silent testing failed. Please check:\n• Jira service is accessible\n• Jira API credentials are set correctly\n📖 Please refer to the ENV_SETUP file for configuration instructions"
			if err := SendMessageToUser(ctx, errorMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			var confirmMsg string
			if sentCount == 0 {
				confirmMsg = "🔇 **Silent Testing Mode** - No new reminders found. All eligible tickets already have reminders."
				log.Printf("INFO: Silent Jira testing completed - no new reminders found")
			} else {
				confirmMsg = fmt.Sprintf("🔇 **Silent Testing Mode** - Found %d eligible ticket(s) that would have triggered reminders.\n\n**Note:** No notifications were sent to the group.", sentCount)
				log.Printf("INFO: Silent Jira testing completed - %d eligible tickets found", sentCount)
			}

			if err := SendMessageToUser(ctx, confirmMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send confirmation: %v", err)
			}
		}

	case strings.Contains(messageLower, "jira"):
		log.Printf("INFO: Manual QA reminder trigger detected from: %s", displayName)

		sentCount, err := processQAReminders(false)
		if err != nil {
			log.Printf("ERROR: Manual QA reminder processing failed: %v", err)
			errorMsg := "❌ Failed to query Jira. Please check:\n• Jira service is accessible\n• Jira API credentials are set correctly\n📖 Please refer to the ENV_SETUP file for configuration instructions"
			if err := SendMessageToUser(ctx, errorMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			var confirmMsg string
			if sentCount == 0 {
				confirmMsg = "ℹ️ No new reminders to send. All eligible tickets already have reminders."
				log.Printf("INFO: Manual QA reminder check completed - no new reminders sent")
			} else {
				confirmMsg = fmt.Sprintf("✅ Successfully sent %d new QA reminder(s)! Check the group for the reminders.", sentCount)
				log.Printf("INFO: Manual QA reminder processing completed - %d reminders sent", sentCount)
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

**General Functions:**
- only query member's jira tickets that have been moved past 2nd review recently within 2 working days
- will not send duplicated reminders with every trigger
- will re-trigger in same thread with tags every 24hrs if reminder is not completed
- cleanup (happens every 2 weeks) will remove completed reminders older than 2 working days

**For Manager:**
- can manually trigger query jira tickets via bot with "jira" or auto triggered every working day at 10am GMT+8
- can check all pending qa reminders via bot with "list" to see all pending and completed reminders for the past and current week

**For Members:**
- members can see their pending reminders via bot with "status" and can complete action from there
- members only able to click on their pending actions
- members can switch buttons click only once`

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
• Click Complete button to confirm knowledge base updated
• Click Nothing to update button if knowledge base is already clean and sleek`

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
	hasComplete := contains(userResponses, "complete")
	hasCancel := contains(userResponses, "cancel")

	if hasComplete && hasCancel {
		responseMutex.Unlock()
		log.Printf("INFO: User %s has already used both buttons for alert %s, blocking further clicks", reqSOP.Event.EmployeeCode, messageID)
		return
	}

	// Check if user is clicking the same button again
	if contains(userResponses, buttonType) {
		responseMutex.Unlock()
		log.Printf("INFO: User %s already clicked %s button for alert %s, ignoring duplicate", reqSOP.Event.EmployeeCode, buttonType, messageID)
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
	log.Printf("DEBUG: Button click - threadID: %s, targetGroupID: %s", threadID, targetGroupID)

	// Process the button click
	var buttonStatus string
	switch buttonType {
	case "complete":
		handleKnowledgeBaseComplete(ctx, reqSOP.Event, targetGroupID, threadID, isSecondButton, ticketKey)
		buttonStatus = "completed"
	case "cancel":
		handleKnowledgeBaseCancel(ctx, reqSOP.Event, targetGroupID, threadID, isSecondButton, ticketKey)
		buttonStatus = "nothing_to_update"
	}

	// Mark QA reminder as completed for both button types
	markQAReminderCompleted(reqSOP.Event.EmployeeCode, ticketKey, buttonStatus)
}

func markQAReminderCompleted(employeeCode, ticketKey, buttonStatus string) {
	reminderMutex.Lock()
	defer reminderMutex.Unlock()

	// Find the QA reminder by ticket key
	if reminder, exists := qaReminders[ticketKey]; exists {
		reminder.Completed = true
		reminder.ButtonStatus = buttonStatus
		displayName := getEmployeeDisplayName(Event{EmployeeCode: employeeCode})
		log.Printf("INFO: QA reminder for %s marked as completed by %s with status: %s", ticketKey, displayName, buttonStatus)

		// Decrease the reminder count for this QA
		decreaseReminderCount(reminder.QAEmail)
	} else {
		log.Printf("WARN: No reminder found for ticket %s when trying to mark as completed", ticketKey)
	}
}

func handleKnowledgeBaseComplete(ctx *gin.Context, event Event, groupID, threadID string, isSecondButton bool, ticketKey string) {
	displayName := getEmployeeDisplayName(event)
	completedTime := getSingaporeTime()

	// Find the reminder for this user/ticket to get the sent time
	reminderMutex.RLock()
	var reminderSentTime time.Time
	for _, reminder := range qaReminders {
		if reminder.QAEmail == event.Email || strings.Contains(event.Email, reminder.QAEmail) {
			reminderSentTime = reminder.SentTime
			break
		}
	}
	reminderMutex.RUnlock()

	// Calculate duration and motivational message if reminder was sent
	var durationMsg string
	var cheerMessage string
	if !reminderSentTime.IsZero() {
		duration := completedTime.Sub(reminderSentTime)
		durationMsg = fmt.Sprintf("\n⏱️ **Response Time:** %s", formatDuration(duration))
		cheerMessage = fmt.Sprintf("\n%s", getCheerMessage(duration))
	}

	// Add [Updated] prefix if this is the second button press
	titlePrefix := ""
	if isSecondButton {
		titlePrefix = "[Updated] "
	}

	// Use simple Jira URL without API call
	jiraTicketWithTitle := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticketKey)

	// Send confirmation message with timestamps
	confirmMsg := fmt.Sprintf(`✅ **%sKnowledge base is updated by %s**

🎫 **Jira Ticket:** %s
📅 **Reminder Sent:** %s
📅 **Completed:** %s%s%s`,
		titlePrefix,
		displayName,
		jiraTicketWithTitle,
		reminderSentTime.Format("2006-01-02 15:04:05"),
		completedTime.Format("2006-01-02 15:04:05"),
		durationMsg,
		cheerMessage,
	)

	// Send response in thread if threadID is available, otherwise send as regular group message
	log.Printf("DEBUG: Sending completion confirmation - threadID: %s, groupID: %s", threadID, groupID)
	if threadID != "" {
		if err := SendMessageToThreadWithRetry(ctx, confirmMsg, groupID, threadID); err != nil {
			log.Printf("ERROR: Failed to send completion confirmation to thread: %v", err)
		}
	} else {
		if _, err := SendMessageToGroup(ctx, confirmMsg, groupID); err != nil {
			log.Printf("ERROR: Failed to send completion confirmation: %v", err)
		}
	}
}

func handleKnowledgeBaseCancel(ctx *gin.Context, event Event, groupID, threadID string, isSecondButton bool, ticketKey string) {
	displayName := getEmployeeDisplayName(event)
	cancelledTime := getSingaporeTime()

	// Find the reminder for this user/ticket to get the sent time
	reminderMutex.RLock()
	var reminderSentTime time.Time
	for _, reminder := range qaReminders {
		if reminder.QAEmail == event.Email || strings.Contains(event.Email, reminder.QAEmail) {
			reminderSentTime = reminder.SentTime
			break
		}
	}
	reminderMutex.RUnlock()

	// Calculate duration if reminder was sent
	var durationMsg string
	if !reminderSentTime.IsZero() {
		duration := cancelledTime.Sub(reminderSentTime)
		durationMsg = fmt.Sprintf("\n⏱️ **Response Time:** %s", formatDuration(duration))
	}

	// Add [Updated] prefix if this is the second button press
	titlePrefix := ""
	if isSecondButton {
		titlePrefix = "[Updated] "
	}

	// Use simple Jira URL without API call
	jiraTicketWithTitle := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticketKey)

	// Send cancellation message
	cancelMsg := fmt.Sprintf(`🚫 **%s%s acknowledged that knowledge base does not require update for this Jira ticket**

🎫 **Jira Ticket:** %s
📅 **Reminder Sent:** %s
📅 **Acknowledged:** %s%s`,
		titlePrefix,
		displayName,
		jiraTicketWithTitle,
		reminderSentTime.Format("2006-01-02 15:04:05"),
		cancelledTime.Format("2006-01-02 15:04:05"),
		durationMsg,
	)

	// Send response in thread if threadID is available, otherwise send as regular group message
	if threadID != "" {
		if err := SendMessageToThreadWithRetry(ctx, cancelMsg, groupID, threadID); err != nil {
			log.Printf("ERROR: Failed to send cancellation confirmation to thread: %v", err)
		}
	} else {
		if _, err := SendMessageToGroup(ctx, cancelMsg, groupID); err != nil {
			log.Printf("ERROR: Failed to send cancellation confirmation: %v", err)
		}
	}
}

// Helper function to check if slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Start cleanup scheduler to remove completed reminders every 2 weeks on Monday at 12am
func startReminderCleanup() {
	log.Println("INFO: Starting reminder cleanup scheduler (runs every 2 weeks on Monday at 12am)")

	// Track if we've run cleanup this cycle
	cleanupRun := false

	for {
		now := getSingaporeTime()

		// Calculate next Monday at 12am (midnight)
		daysUntilMonday := (8 - int(now.Weekday())) % 7
		if daysUntilMonday == 0 {
			// It's Monday, check if we're past midnight
			nextMonday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
			if now.After(nextMonday) {
				// Already past midnight, schedule for next Monday
				daysUntilMonday = 7
			}
		}

		nextMonday := now.AddDate(0, 0, daysUntilMonday)
		nextMonday = time.Date(nextMonday.Year(), nextMonday.Month(), nextMonday.Day(), 0, 0, 0, 0, nextMonday.Location())

		// Wait until next Monday at midnight
		sleepDuration := nextMonday.Sub(now)
		time.Sleep(sleepDuration)

		// Only run cleanup every 2 weeks (alternate Mondays)
		if !cleanupRun {
			log.Println("INFO: Running bi-weekly reminder cleanup (Monday 12am)")
			if err := cleanupOldReminders(); err != nil {
				log.Printf("ERROR: Failed to cleanup old reminders: %v", err)
			}
			cleanupRun = true
		} else {
			cleanupRun = false
		}

		// Sleep for a minute to avoid running multiple times
		time.Sleep(time.Minute)
	}
}

// Remove completed reminders older than 2 business days
func cleanupOldReminders() error {
	now := getSingaporeTime()

	// Calculate cutoff time: 2 business days ago
	var cutoffTime time.Time
	switch now.Weekday() {
	case time.Monday:
		// Monday: go back to last Wednesday
		cutoffTime = now.AddDate(0, 0, -5)
	case time.Tuesday:
		// Tuesday: go back to last Thursday
		cutoffTime = now.AddDate(0, 0, -5)
	case time.Wednesday:
		// Wednesday: go back to last Friday
		cutoffTime = now.AddDate(0, 0, -5)
	case time.Thursday:
		// Thursday: go back to last Monday
		cutoffTime = now.AddDate(0, 0, -3)
	case time.Friday:
		// Friday: go back to last Tuesday
		cutoffTime = now.AddDate(0, 0, -3)
	case time.Saturday:
		// Saturday: go back to last Thursday
		cutoffTime = now.AddDate(0, 0, -2)
	case time.Sunday:
		// Sunday: go back to last Thursday
		cutoffTime = now.AddDate(0, 0, -3)
	}

	reminderMutex.Lock()
	defer reminderMutex.Unlock()

	removedCount := 0
	for issueKey, reminder := range qaReminders {
		if reminder.Completed && reminder.LastSentTime.Before(cutoffTime) {
			delete(qaReminders, issueKey)
			removedCount++
			log.Printf("INFO: Removed completed reminder for %s (completed on %s)", issueKey, reminder.LastSentTime.Format("2006-01-02 15:04"))
		}
	}

	log.Printf("INFO: Cleanup complete. Removed %d completed reminders older than 2 business days", removedCount)
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
}
