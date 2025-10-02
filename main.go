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
	"os"
	"os/signal"
	"strings"
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

type SOPMessage struct {
	Tag                string                 `json:"tag"`
	Text               *SOPTextMsg            `json:"text,omitempty"`
	InteractiveMessage *SOPInteractiveMessage `json:"interactive_message,omitempty"`
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
	Code int `json:"code"`
}

// Global variables
var (
	appAccessToken AppAccessToken
	groupID        = "OTIzMTMwNjE4MTI4" // small group: OTIzMTMwNjE4MTI4
	alertSentTime  time.Time            // Track when alert was sent
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
		default:
			log.Printf("ERROR: event %s not handled yet!", reqSOP.EventType)
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
		signingSecret := "g_RKjOATWhUt5FFWP1lztCjvFlW5tngl" // Replace this with your Bot Signing Secret
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
		body := []byte(fmt.Sprintf(`{"app_id": "%s", "app_secret": "%s"}`, "MTcyNzE5ODkyMzg1", "HSFa831gq2ojDXZLVoVkHLBSkymoW-Tz"))

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

		if res.StatusCode != 200 {
			log.Printf("ERROR: [GetAppAccessToken] got non 200 HTTP response status code: %v", err)
			return appAccessToken
		}

		resp := &SOPAuthAppResp{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
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

func SendKnowledgeBaseAlert(ctx context.Context, groupID string) error {
	messageID := fmt.Sprintf("%d", time.Now().Unix())
	alertTime := time.Now().Format("2006-01-02 15:04:05")

	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
		Message: SOPMessage{
			Tag: "interactive_message",
			InteractiveMessage: &SOPInteractiveMessage{
				Elements: []SOPInteractiveElement{
					{
						ElementType: "title",
						Title: &SOPInteractiveTitle{
							Text: "📚 [Reminder] Knowledge Base Update",
						},
					},
					{
						ElementType: "description",
						Description: &SOPInteractiveDescription{
							Format: 1,
							Text: fmt.Sprintf(`📖 **Time to update our knowledge base!**

Our documentation needs some love to stay current and helpful for the team. Please take a moment to:
• Review and update outdated information
• Add new processes or solutions you've discovered
• Ensure all team knowledge is properly documented and up to date

📅 **Alert Time:** %s

Click **Complete** below once you've finished updating the knowledge base. Thank you for keeping our documentation fresh! 🙏`, alertTime),
						},
					},
					{
						ElementType: "button",
						Button: &SOPInteractiveButton{
							ButtonType:   "callback",
							Text:         "Complete ✅",
							Value:        "kb_complete_" + messageID,
							CallbackData: "kb_complete_" + messageID,
							ActionID:     "kb_complete_" + messageID,
						},
					},
				},
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
		return fmt.Errorf("failed to send interactive message, response code: %v", resp.Code)
	}

	return nil
}

func handlePrivateMessage(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	message := reqSOP.Event.Message.Text.Content
	if message == "" {
		message = reqSOP.Event.Message.Text.PlainText
	}

	displayName := getEmployeeDisplayName(reqSOP.Event)
	log.Printf("INFO: private message received: %s, from: %s", message, displayName)

	// Handle private message commands
	if strings.Contains(strings.ToLower(message), "debug") || strings.Contains(strings.ToLower(message), "groupid") {
		debugMsg := `🔧 **Debug Info:**

📍 **Current Context:** Private Message
👤 **Your Employee Code:** ` + reqSOP.Event.EmployeeCode + `

💡 **To get group ID, mention me in the group with "debug"`

		if err := SendMessageToUser(ctx, debugMsg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send debug message: %v", err)
		}
	} else if strings.Contains(strings.ToLower(message), "alert") {
		log.Printf("INFO: Alert trigger detected from: %s", displayName)

		// Record the time when alert is sent
		alertSentTime = time.Now()
		if err := SendKnowledgeBaseAlert(ctx, groupID); err != nil {
			log.Printf("ERROR: Failed to send alert: %v", err)
			if err := SendMessageToUser(ctx, "❌ Failed to send alert to group", reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			// Send confirmation to the person who triggered it
			confirmMsg := "✅ Alert sent successfully to the group!"
			if err := SendMessageToUser(ctx, confirmMsg, reqSOP.Event.EmployeeCode); err != nil {
				log.Printf("ERROR: Failed to send confirmation: %v", err)
			}
		}
	} else if strings.Contains(strings.ToLower(message), "help") {
		helpMsg := `🤖 **Knowledge Base Bot Commands**

**Private Messages:**
• "help" - Show this help message
• "debug" - Show debug information
• "alert" - Send knowledge base alert to group

**Group Messages:**
• "@KnowledgeBot debug" - Show group ID and debug info

**Interactive Features:**
• Alert system with built-in Complete button
• Click Complete button to confirm knowledge base updated`

		if err := SendMessageToUser(ctx, helpMsg, reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: Failed to send help message: %v", err)
		}
	} else {
		// Default response for other messages
		if err := SendMessageToUser(ctx, "Hello! Send 'help' to see available commands or 'alert' to trigger an alert with Complete button.", reqSOP.Event.EmployeeCode); err != nil {
			log.Printf("ERROR: something wrong when send message to user, error: %v", err)
		}
	}
}

func handleGroupMessage(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	message := reqSOP.Event.Message.Text.Content
	if message == "" {
		message = reqSOP.Event.Message.Text.PlainText
	}

	displayName := getEmployeeDisplayName(reqSOP.Event)
	log.Printf("INFO: group message received: %s, from: %s, in group: %s", message, displayName, reqSOP.Event.GroupID)

	// Handle group message commands
	if strings.Contains(strings.ToLower(message), "debug") || strings.Contains(strings.ToLower(message), "groupid") {
		debugMsg := `🔧 **Debug Info:**

📍 **Current Context:** Group Chat
🏢 **This Group ID:** ` + reqSOP.Event.GroupID + `
👤 **Your Employee Code:** ` + reqSOP.Event.EmployeeCode + `

💡 **To use this group for alerts, set alertGroupID = "` + reqSOP.Event.GroupID + `"`

		if err := SendMessageToGroup(ctx, debugMsg, reqSOP.Event.GroupID); err != nil {
			log.Printf("ERROR: Failed to send debug message to group: %v", err)
		}
	} else if strings.Contains(strings.ToLower(message), "help") {
		helpMsg := `🤖 **Knowledge Base Bot Commands**

**Group Commands:**
• "@KnowledgeBot debug" - Show group ID and debug info
• "@KnowledgeBot help" - Show this help message

**Private Commands:**
• Send me "alert" privately to trigger alerts with Complete button
• Send me "help" privately for more commands

**Interactive Features:**
• Alert system with built-in Complete button
• Click Complete button to confirm issue resolution`

		if err := SendMessageToGroup(ctx, helpMsg, reqSOP.Event.GroupID); err != nil {
			log.Printf("ERROR: Failed to send help message to group: %v", err)
		}
	}
}

func handleButtonClick(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	// Check if this is a complete button click
	// If interactive data is empty, assume it's our complete button (since we only have one button)
	if strings.Contains(reqSOP.Event.InteractiveData.CallbackData, "kb_complete") ||
		strings.Contains(reqSOP.Event.InteractiveData.Value, "kb_complete") ||
		strings.Contains(reqSOP.Event.InteractiveData.ActionID, "kb_complete") ||
		(reqSOP.Event.InteractiveData.CallbackData == "" && reqSOP.Event.InteractiveData.Value == "" && reqSOP.Event.InteractiveData.ActionID == "") {

		handleKnowledgeBaseComplete(ctx, reqSOP.Event, reqSOP.Event.GroupID)
	}
}

func handleKnowledgeBaseComplete(ctx *gin.Context, event Event, groupID string) {
	displayName := getEmployeeDisplayName(event)
	completedTime := time.Now()

	// Calculate duration and motivational message if alert was sent
	var durationMsg string
	var cheerMessage string
	if !alertSentTime.IsZero() {
		duration := completedTime.Sub(alertSentTime)
		durationMsg = fmt.Sprintf("\n⏱️ **Response Time:** %s", formatDuration(duration))
		cheerMessage = fmt.Sprintf("\n%s", getCheerMessage(duration))
	}

	// Send confirmation message with timestamps
	confirmMsg := fmt.Sprintf(`✅ **Knowledge base is updated by %s**

📅 **Alert Sent:** %s
📅 **Completed:** %s%s%s`,
		displayName,
		alertSentTime.Format("2006-01-02 15:04:05"),
		completedTime.Format("2006-01-02 15:04:05"),
		durationMsg,
		cheerMessage,
	)

	if err := SendMessageToGroup(ctx, confirmMsg, groupID); err != nil {
		log.Printf("ERROR: Failed to send completion confirmation: %v", err)
	}
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
