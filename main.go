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
	Status  JiraStatus `json:"status"`
	Updated string     `json:"updated"`
}

type JiraStatus struct {
	Name string `json:"name"`
}

type JiraSearchResult struct {
	Issues []JiraIssue `json:"issues"`
	Total  int         `json:"total"`
}

// QA Reminder tracking
type QAReminder struct {
	IssueKey     string
	QAName       string
	QAEmail      string
	MessageID    string
	SentTime     time.Time
	LastSentTime time.Time
	Completed    bool
}

// Group member info
type GroupMember struct {
	EmployeeCode string `json:"employee_code"`
	DisplayName  string `json:"display_name"`
	Email        string `json:"email"`
}

type SOPEventVerificationResp struct {
	SeatalkChallenge string `json:"seatalk_challenge"`
}

type Event struct {
	SeatalkChallenge string          `json:"seatalk_challenge"`
	EmployeeCode     string          `json:"employee_code"`
	EmployeeName     string          `json:"employee_name"`
	UserName         string          `json:"user_name"`
	DisplayName      string          `json:"display_name"`
	FullName         string          `json:"full_name"`
	Email            string          `json:"email"`
	GroupID          string          `json:"group_id"`
	Message          Message         `json:"message"`
	InteractiveData  InteractiveData `json:"interactive_data"`
	MessageID        string          `json:"message_id"`
	Value            string          `json:"value"`
	SeatalkID        string          `json:"seatalk_id"`
	ThreadID         string          `json:"thread_id"`
}

type InteractiveData struct {
	ActionID     string `json:"action_id"`
	Value        string `json:"value"`
	ButtonValue  string `json:"button_value"`
	CallbackData string `json:"callback_data"`
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

type SOPSendThreadMessage struct {
	GroupID         string     `json:"group_id"`
	Message         SOPMessage `json:"message"`
	QuotedMessageID string     `json:"quoted_message_id"`
}

type SOPMessage struct {
	Tag                string                 `json:"tag"`
	Text               *SOPTextMsg            `json:"text,omitempty"`
	InteractiveMessage *SOPInteractiveMessage `json:"interactive_message,omitempty"`
	QuotedMessageID    string                 `json:"quoted_message_id,omitempty"`
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
	groupID        = "OTIzMTMwNjE4MTI4"                   // small group: OTIzMTMwNjE4MTI4
	alertResponses = make(map[string]map[string][]string) // messageID -> employeeCode -> [button_types_pressed]
	responseMutex  sync.RWMutex

	// Jira configuration (loaded from environment variables)
	jiraConfig = JiraConfig{
		BaseURL:  getEnvOrDefault("JIRA_BASE_URL", "https://jira.shopee.io"),
		Username: getEnvOrDefault("JIRA_USERNAME", ""),
		APIToken: getEnvOrDefault("JIRA_API_TOKEN", ""),
	}

	// QA Reminder tracking
	qaReminders   = make(map[string]*QAReminder) // issueKey -> QAReminder
	reminderMutex sync.RWMutex
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	r := gin.Default()

	// Health check endpoint for uptime monitoring (no signature validation needed)
	healthHandler := func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"bot":    "knowledgebot",
			"time":   time.Now().Format("2006-01-02 15:04:05"),
		})
	}

	// Support both GET and HEAD requests for health checks
	r.GET("/health", healthHandler)
	r.HEAD("/health", healthHandler)

	// Root path handler for uptime monitors that hit "/"
	r.GET("/", healthHandler)
	r.HEAD("/", healthHandler)

	// Callback endpoint with signature validation
	r.POST("/callback", WithSOPSignatureValidation(), func(ctx *gin.Context) {
		var reqSOP SOPEventCallbackReq
		if err := ctx.ShouldBindJSON(&reqSOP); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}
		log.Printf("INFO: received event with event_type %s", reqSOP.EventType)

		switch reqSOP.EventType {
		case "event_verification":
			ctx.JSON(http.StatusOK, SOPEventVerificationResp{SeatalkChallenge: reqSOP.Event.SeatalkChallenge})
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

func WithSOPSignatureValidation() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		signature := r.Header.Get("signature")

		if signature == "" {
			ctx.JSON(http.StatusForbidden, nil)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}

		hasher := sha256.New()
		signingSecret := getEnvOrDefault("SEATALK_SIGNING_SECRET", "")
		if signingSecret == "" {
			log.Printf("ERROR: SeaTalk signing secret not configured. Please set SEATALK_SIGNING_SECRET environment variable")
			ctx.JSON(http.StatusForbidden, nil)
			return
		}
		hasher.Write(append(body, []byte(signingSecret)...))
		targetSignature := hex.EncodeToString(hasher.Sum(nil))

		if signature != targetSignature {
			ctx.JSON(http.StatusForbidden, nil)
			return
		}

		r.Body = io.NopCloser(bytes.NewBuffer(body))
		ctx.Next()
	}
}

func GetAppAccessToken() AppAccessToken {
	timeNow := time.Now().Unix()

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
				Format:  2, //plain text message
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

func SendMessageToGroup(ctx context.Context, message, groupID string) error {
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
		return fmt.Errorf("failed to send group message, response code: %v", resp.Code)
	}

	return nil
}

func SendMessageToThread(ctx context.Context, message, groupID, threadID string) error {
	bodyJson, _ := json.Marshal(SOPSendThreadMessage{
		GroupID: groupID,
		Message: SOPMessage{
			Tag: "text",
			Text: &SOPTextMsg{
				Format:  1, // Rich text format (use 2 for plain text)
				Content: message,
			},
			QuotedMessageID: "", // Should be empty for threading
			ThreadID:        threadID,
		},
	})

	req, _ := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	// Debug the thread message request
	log.Printf("DEBUG: SendMessageToThread - Request body: %s", string(bodyJson))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send thread message: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("DEBUG: SendMessageToThread - Response body: %s", string(body))

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to send thread message, response code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Helper function to send interactive messages to group
func SendInteractiveMessageToGroup(ctx context.Context, groupID, title, description, buttonID string) (string, error) {
	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
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

func searchJiraQATickets(qaEmail string) ([]JiraIssue, error) {
	// Query tickets in any status from the QA workflow (2ND REVIEW, UAT, STAGING, REGRESSION, DELIVERING, LIVE TESTING, DONE)
	jql := fmt.Sprintf("status in (\"2ND REVIEW\", \"UAT\", \"STAGING\", \"REGRESSION\", \"DELIVERING\", \"LIVE TESTING\", \"DONE\") AND QA in (\"%s\")", qaEmail)

	// URL encode the JQL query
	encodedJQL := url.QueryEscape(jql)

	endpoint := fmt.Sprintf("/rest/api/2/search?jql=%s&maxResults=50&fields=status,updated", encodedJQL)
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
		now := time.Now()

		// Calculate next 10am
		next10am := time.Date(now.Year(), now.Month(), now.Day(), 10, 0, 0, 0, now.Location())
		if now.After(next10am) {
			next10am = next10am.Add(24 * time.Hour)
		}

		// Wait until 10am
		sleepDuration := next10am.Sub(now)
		log.Printf("INFO: Next QA reminder scheduled for %s (in %s)", next10am.Format("2006-01-02 15:04:05"), sleepDuration)
		time.Sleep(sleepDuration)

		// Skip weekends
		if next10am.Weekday() == time.Saturday || next10am.Weekday() == time.Sunday {
			continue
		}

		log.Println("INFO: Running daily QA reminder check")
		sentCount, err := processQAReminders()
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

func processQAReminders() (int, error) {
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

		// Send reminders for each ticket
		// tickets = tickets[:1] - used for debugging
		sentCount := 0
		for _, ticket := range tickets {
			reminderKey := ticket.Key

			// Filter 1: Check if ticket has completed testing within last 2 business days
			if !completedTestingRecently(&ticket) {
				continue
			}

			reminderMutex.RLock()
			existingReminder := qaReminders[reminderKey]
			reminderMutex.RUnlock()

			// Filter 2: Skip if reminder was already sent (exists in qaReminders)
			if existingReminder != nil {
				continue
			}

			// Send reminder for new tickets
			if err := sendQAReminder(ticket, member, false); err != nil {
				log.Printf("ERROR: Failed to send QA reminder for %s to %s: %v", ticket.Key, member.DisplayName, err)
			} else {
				sentCount++
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

	now := time.Now()

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
			if err := sendQAReminder(ticket, member, false); err != nil {
				log.Printf("ERROR: Failed to send follow-up reminder for %s: %v", reminder.IssueKey, err)
			}
		}
	}

	return nil
}

func getJiraIssue(issueKey string) (*JiraIssue, error) {
	resp, err := makeJiraRequest("GET", "/rest/api/2/issue/"+issueKey+"?fields=status,updated", nil)
	if err != nil {
		log.Printf("ERROR: Failed to fetch Jira issue %s: %v", issueKey, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: Jira issue API error for %s: %d - %s", issueKey, resp.StatusCode, string(body))
		return nil, fmt.Errorf("Jira API error: %d - %s", resp.StatusCode, string(body))
	}

	var issue JiraIssue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		log.Printf("ERROR: Failed to decode Jira issue response for %s: %v", issueKey, err)
		return nil, err
	}

	return &issue, nil
}

// This is used to determine if a ticket completed testing recently
func recentlyCompletedTestingTime(issue *JiraIssue) (time.Time, error) {
	// Use the updated time from the Jira ticket
	if issue.Fields.Updated == "" {
		return time.Time{}, fmt.Errorf("no updated time found")
	}

	// Parse the Jira timestamp
	t, err := time.Parse("2006-01-02T15:04:05.999-0700", issue.Fields.Updated)
	if err != nil {
		// Try alternative format
		t, err = time.Parse(time.RFC3339, issue.Fields.Updated)
		if err != nil {
			log.Printf("WARN: Failed to parse updated date %s: %v", issue.Fields.Updated, err)
			return time.Time{}, err
		}
	}
	return t, nil
}

// This is used to display when a ticket completed testing recently
func getRecentlyCompletedTestingDate(issue *JiraIssue) string {
	reviewTime, err := recentlyCompletedTestingTime(issue)
	if err != nil {
		// Fallback to current time if not found
		return time.Now().Format("02 Jan 2006")
	}
	// Format as "02 Jan 2006"
	return reviewTime.Format("02 Jan 2006")
}

// Check if ticket completed testing today or previous business day
func completedTestingRecently(issue *JiraIssue) bool {
	reviewTime, err := recentlyCompletedTestingTime(issue)
	if err != nil {
		return false
	}

	now := time.Now()

	// Get review date (day only, ignore time)
	reviewYear, reviewMonth, reviewDay := reviewTime.Date()
	todayYear, todayMonth, todayDay := now.Date()

	// Check if review was today
	if reviewYear == todayYear && reviewMonth == todayMonth && reviewDay == todayDay {
		return true
	}

	// Calculate previous business day
	var previousBusinessDay time.Time
	switch now.Weekday() {
	case time.Monday:
		// Previous business day is Friday
		previousBusinessDay = now.AddDate(0, 0, -3)
	case time.Sunday:
		// Previous business day is Friday
		previousBusinessDay = now.AddDate(0, 0, -2)
	default:
		// Previous business day is yesterday
		previousBusinessDay = now.AddDate(0, 0, -1)
	}

	// Check if review was on previous business day
	prevYear, prevMonth, prevDay := previousBusinessDay.Date()
	return reviewYear == prevYear && reviewMonth == prevMonth && reviewDay == prevDay
}

func sendQAReminder(ticket JiraIssue, qa GroupMember, isMock bool) error {
	// Create Jira ticket URL
	jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticket.Key)

	// Get the date when ticket recently completed testing
	recentlyCompletedTestingDate := getRecentlyCompletedTestingDate(&ticket)

	// Check if this is a follow-up (reminder already exists)
	reminderMutex.RLock()
	existingReminder := qaReminders[ticket.Key]
	isFollowUp := existingReminder != nil
	reminderMutex.RUnlock()

	// Create reminder message with appropriate prefix
	title := "📚 Knowledge Base Reminder"
	if isMock {
		title = "📚 [MOCK] Knowledge Base Reminder"
	} else if isFollowUp {
		title = "📚 [Follow-up Required] Knowledge Base Reminder"
	}

	var qaField string
	if isMock {
		qaField = "**QA:** MockQA"
	} else {
		qaField = fmt.Sprintf("**QA:** <mention-tag target=\"seatalk://user?email=%s\"/> (cc: <mention-tag target=\"seatalk://user?email=shuang.xiao@shopee.com\"/>)", qa.Email)
	}

	description := fmt.Sprintf(`
%s
**Jira Ticket:** %s
**Completed testing recently:** %s

📝 **Tasks to consider:**
• Review and update outdated information and data preparation steps
• Add new processes or solutions you've discovered
• Ensure all team knowledge is properly documented and up to date

📊 **Please review and update the knowledge base accordingly:**
https://docs.google.com/spreadsheets/d/1QlBZniYwL5VqKW1KQxjTs4LEGqOJ8YWRFTLhX-MZBtU/edit?gid=0#gid=0

Click the appropriate button below when done:`,
		qaField,
		jiraURL,
		recentlyCompletedTestingDate)

	// For follow-ups, send as a thread reply instead of a new interactive message
	var messageID string
	var err error

	if isFollowUp && !isMock {
		// Send as thread reply using the original message ID as thread ID
		if err := SendMessageToThread(context.Background(), description, groupID, existingReminder.MessageID); err != nil {
			log.Printf("ERROR: Failed to send follow-up reminder in thread: %v", err)
			return err
		}
		// For follow-ups, we don't need a new messageID since we're replying in thread
		messageID = existingReminder.MessageID
	} else {
		// For new reminders, send as interactive message with buttons
		buttonID := ticket.Key
		if isMock {
			buttonID = "MOCK_" + ticket.Key
		}
		messageID, err = SendInteractiveMessageToGroup(context.Background(), groupID, title, description, buttonID)
		if err != nil {
			log.Printf("ERROR: Failed to send QA reminder: %v", err)
			return err
		}
	}

	// Track the reminder
	now := time.Now()
	reminderMutex.Lock()

	if isFollowUp && !isMock {
		// Update only the LastSentTime for follow-ups, keep original SentTime
		existingReminder.LastSentTime = now
		log.Printf("INFO: Follow-up QA reminder sent for %s to %s", ticket.Key, qa.DisplayName)
	} else {
		// Create new reminder entry (for new reminders or mock reminders)
		qaReminders[ticket.Key] = &QAReminder{
			IssueKey:     ticket.Key,
			QAName:       qa.DisplayName,
			QAEmail:      qa.Email,
			MessageID:    messageID,
			SentTime:     now,
			LastSentTime: now,
			Completed:    false,
		}
		if !isMock {
			log.Printf("INFO: QA reminder sent and tracked for %s to %s", ticket.Key, qa.DisplayName)
		}
	}

	reminderMutex.Unlock()
	return nil
}

// Send a status reminder with interactive buttons to a user privately
func sendStatusReminderToUser(reminder *QAReminder, employeeCode string) error {
	// Get ticket details
	ticket, err := getJiraIssue(reminder.IssueKey)
	if err != nil {
		log.Printf("ERROR: Failed to get Jira issue %s for status: %v", reminder.IssueKey, err)
		return err
	}

	// Create Jira ticket URL
	jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)

	// Get the date when ticket recently completed testing
	recentlyCompletedTestingDate := getRecentlyCompletedTestingDate(ticket)

	// Calculate how long ago the reminder was sent
	timeSinceSent := time.Since(reminder.SentTime)
	sentAgo := formatDuration(timeSinceSent)

	// Create description
	description := fmt.Sprintf(`🎫 **Jira Ticket:** %s
📅 **Completed Testing recently:** %s
⏰ **Reminder Sent:** %s ago

Please review and update the knowledge base accordingly.

Click the appropriate button when done:`, jiraURL, recentlyCompletedTestingDate, sentAgo)

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
		// Get all reminders
		reminderMutex.RLock()
		var completedReminders []*QAReminder
		var pendingReminders []*QAReminder

		for _, reminder := range qaReminders {
			if reminder.Completed {
				completedReminders = append(completedReminders, reminder)
			} else {
				pendingReminders = append(pendingReminders, reminder)
			}
		}
		reminderMutex.RUnlock()

		// Build the list message
		var listMsg strings.Builder
		listMsg.WriteString("📋 **Knowledge Base Status List**\n\n")

		// Completed section (shows all completed reminders until next Monday cleanup)
		listMsg.WriteString("✅ **Completed reminders this week:**\n")
		if len(completedReminders) == 0 {
			listMsg.WriteString("• None\n")
		} else {
			for _, reminder := range completedReminders {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)
				completedTime := reminder.LastSentTime.Format("Mon 3:04 PM")
				listMsg.WriteString(fmt.Sprintf("• %s - by %s (%s)\n", jiraURL, reminder.QAName, completedTime))
			}
		}

		listMsg.WriteString("\n⏳ **All pending reminders:**\n")
		if len(pendingReminders) == 0 {
			listMsg.WriteString("• None\n")
		} else {
			for _, reminder := range pendingReminders {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)
				listMsg.WriteString(fmt.Sprintf("• %s - by %s\n", jiraURL, reminder.QAName))
			}
		}

		if err := SendMessageToUser(ctx, listMsg.String(), reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send list message: %v", err)
		}

	case strings.Contains(messageLower, "status"):
		log.Printf("INFO: Status command received from: %s (%s)", displayName, reqSOP.Event.Email)

		// Get all incomplete reminders for this user
		reminderMutex.RLock()
		var userReminders []*QAReminder
		for _, reminder := range qaReminders {
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

	case strings.Contains(messageLower, "jira"):
		log.Printf("INFO: Manual QA reminder trigger detected from: %s", displayName)

		sentCount, err := processQAReminders()
		if err != nil {
			log.Printf("ERROR: Manual QA reminder processing failed: %v", err)
			errorMsg := "❌ Failed to query Jira. Please check:\n• Jira service is accessible\n• Jira API credentials are set correctly\n📖 Please refer to the ENV_SETUP file for configuration instructions"
			if err := SendMessageToUser(ctx, errorMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			var confirmMsg string
			if sentCount == 0 {
				confirmMsg = "ℹ️ No new reminders to send. All eligible tickets already have reminders.\n\n💡 **Tip:** Send 'mock' to trigger a test reminder."
				log.Printf("INFO: Manual QA reminder check completed - no new reminders sent")
			} else {
				confirmMsg = fmt.Sprintf("✅ Successfully sent %d new QA reminder(s)! Check the group for the reminders.", sentCount)
				log.Printf("INFO: Manual QA reminder processing completed - %d reminders sent", sentCount)
			}

			if err := SendMessageToUser(ctx, confirmMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send confirmation: %v", err)
			}
		}

	case strings.Contains(messageLower, "mock"):
		log.Printf("INFO: Mock reminder trigger detected from: %s", displayName)

		if err := sendQAReminder(JiraIssue{Key: "MOCK-12345"}, GroupMember{}, true); err != nil {
			log.Printf("ERROR: Failed to send mock reminder: %v", err)
			errorMsg := "❌ Failed to send mock reminder. Please check the bot logs."
			if err := SendMessageToUser(ctx, errorMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			confirmMsg := "✅ Mock reminder sent successfully! Check the group for the test reminder."
			log.Printf("INFO: Mock reminder sent successfully")
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
• "mock" - Send a test reminder to verify bot functionality

**Automated Features:**
• Daily 10am Jira QA reminders for tickets moved to 2nd review past 2 days
• 24-hour follow-up reminders until completion
• Bi-weekly cleanup (every 2 weeks on Mondays 12am) removes all completed reminders

**Group Messages:**
• "@KnowledgeBot debug" - Show group ID and debug info

**Interactive Features:**
• Click Complete button to confirm knowledge base updated
• Click Nothing to update button if knowledge base is already clean and sleek`

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

		if err := SendMessageToGroup(ctx, debugMsg, reqSOP.Event.GroupID); err != nil {
			log.Printf("ERROR: Failed to send debug message to group: %v", err)
		}

	case strings.Contains(messageLower, "list"):
		// Get all reminders
		reminderMutex.RLock()
		var completedReminders, pendingReminders []QAReminder
		for _, reminder := range qaReminders {
			if reminder.Completed {
				completedReminders = append(completedReminders, *reminder)
			} else {
				pendingReminders = append(pendingReminders, *reminder)
			}
		}
		reminderMutex.RUnlock()

		// Build the list message
		var listMsg strings.Builder
		listMsg.WriteString("📋 **Knowledge Base Status List**\n\n")

		// Completed section (shows all completed reminders until next Monday cleanup)
		listMsg.WriteString("✅ **Completed reminders this week:**\n")
		if len(completedReminders) == 0 {
			listMsg.WriteString("• None\n")
		} else {
			for _, reminder := range completedReminders {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)
				completedTime := reminder.LastSentTime.Format("Mon 3:04 PM")
				listMsg.WriteString(fmt.Sprintf("• %s - by %s (%s)\n", jiraURL, reminder.QAName, completedTime))
			}
		}

		listMsg.WriteString("\n⏳ **All pending reminders:**\n")
		if len(pendingReminders) == 0 {
			listMsg.WriteString("• None\n")
		} else {
			for _, reminder := range pendingReminders {
				jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, reminder.IssueKey)
				listMsg.WriteString(fmt.Sprintf("• %s - by %s\n", jiraURL, reminder.QAName))
			}
		}

		if err := SendMessageToGroup(ctx, listMsg.String(), reqSOP.Event.GroupID); err != nil {
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

		if err := SendMessageToGroup(ctx, helpMsg, reqSOP.Event.GroupID); err != nil {
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
	//   - MOCK_SPB-12345 (mock reminder format)
	ticketKey := messageID
	if strings.HasPrefix(messageID, "MOCK_") {
		// For mock reminders, remove the MOCK_ prefix
		ticketKey = strings.TrimPrefix(messageID, "MOCK_")
	} else if strings.Contains(messageID, "_") {
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

	// Use the stored MessageID as thread ID for proper threading
	// This follows the SeaTalk pattern: "define thread_id as the message_id of the root message"
	threadID := authorizedReminder.MessageID

	// Process the button click
	switch buttonType {
	case "complete":
		handleKnowledgeBaseComplete(ctx, reqSOP.Event, targetGroupID, threadID, isSecondButton, ticketKey)
	case "cancel":
		handleKnowledgeBaseCancel(ctx, reqSOP.Event, targetGroupID, threadID, isSecondButton, ticketKey)
	}

	// Mark QA reminder as completed for both button types
	markQAReminderCompleted(reqSOP.Event.EmployeeCode, messageID)
}

func markQAReminderCompleted(employeeCode, messageID string) {
	reminderMutex.Lock()
	defer reminderMutex.Unlock()

	// Find the QA reminder by checking if messageID contains the issue key
	for issueKey, reminder := range qaReminders {
		if strings.Contains(messageID, "qa_reminder_"+issueKey) ||
			strings.Contains(reminder.MessageID, messageID) {
			reminder.Completed = true
			log.Printf("INFO: QA reminder for %s marked as completed by %s", issueKey, employeeCode)
			break
		}
	}
}

func handleKnowledgeBaseComplete(ctx *gin.Context, event Event, groupID, threadID string, isSecondButton bool, ticketKey string) {
	displayName := getEmployeeDisplayName(event)
	completedTime := time.Now()

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

	// Create Jira ticket link
	jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticketKey)

	// Send confirmation message with timestamps
	confirmMsg := fmt.Sprintf(`✅ **%sKnowledge base is updated by %s**

🎫 **Jira Ticket:** %s
📅 **Reminder Sent:** %s
📅 **Completed:** %s%s%s`,
		titlePrefix,
		displayName,
		jiraURL,
		reminderSentTime.Format("2006-01-02 15:04:05"),
		completedTime.Format("2006-01-02 15:04:05"),
		durationMsg,
		cheerMessage,
	)

	// Send response in thread if threadID is available, otherwise send as regular group message
	if threadID != "" {
		if err := SendMessageToThread(ctx, confirmMsg, groupID, threadID); err != nil {
			log.Printf("ERROR: Failed to send completion confirmation to thread: %v", err)
		}
	} else {
		if err := SendMessageToGroup(ctx, confirmMsg, groupID); err != nil {
			log.Printf("ERROR: Failed to send completion confirmation: %v", err)
		}
	}
}

func handleKnowledgeBaseCancel(ctx *gin.Context, event Event, groupID, threadID string, isSecondButton bool, ticketKey string) {
	displayName := getEmployeeDisplayName(event)
	cancelledTime := time.Now()

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

	// Create Jira ticket link
	jiraURL := fmt.Sprintf("%s/browse/%s", jiraConfig.BaseURL, ticketKey)

	// Send cancellation message
	cancelMsg := fmt.Sprintf(`🚫 **%s%s acknowledged that knowledge base does not require update for this Jira ticket**

🎫 **Jira Ticket:** %s
📅 **Reminder Sent:** %s
📅 **Acknowledged:** %s%s`,
		titlePrefix,
		displayName,
		jiraURL,
		reminderSentTime.Format("2006-01-02 15:04:05"),
		cancelledTime.Format("2006-01-02 15:04:05"),
		durationMsg,
	)

	// Send response in thread if threadID is available, otherwise send as regular group message
	if threadID != "" {
		if err := SendMessageToThread(ctx, cancelMsg, groupID, threadID); err != nil {
			log.Printf("ERROR: Failed to send cancellation confirmation to thread: %v", err)
		}
	} else {
		if err := SendMessageToGroup(ctx, cancelMsg, groupID); err != nil {
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
		now := time.Now()

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
	now := time.Now()

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

func getCheerMessage(duration time.Duration) string {
	hours := duration.Hours()
	// Seed the random number generator with current time
	rand.Seed(time.Now().UnixNano())

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
