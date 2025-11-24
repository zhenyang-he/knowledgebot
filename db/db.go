package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// DB holds the database connection
type DB struct {
	conn *sql.DB
}

var (
	instance *DB
	once     sync.Once
)

// GetDB returns the singleton database instance
func GetDB() *DB {
	return instance
}

// Init initializes the database connection and creates tables if needed
func Init() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL not set")
	}

	var err error
	var conn *sql.DB
	conn, err = sql.Open("postgres", dbURL)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := conn.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create tables if they don't exist
	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS reminders (
		issue_key TEXT PRIMARY KEY,
		qa_name TEXT NOT NULL,
		qa_email TEXT NOT NULL,
		message_id TEXT,
		sent_time TIMESTAMP NOT NULL,
		last_sent_time TIMESTAMP NOT NULL,
		reminder_number INTEGER NOT NULL DEFAULT 0,
		summary TEXT,
		issue_type TEXT,
		button_status TEXT DEFAULT '',
		updated_time TIMESTAMP,
		completed_time TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS reminder_counts (
		qa_email TEXT PRIMARY KEY,
		count INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS daily_messages (
		email TEXT,
		date TEXT,
		PRIMARY KEY (email, date)
	);

	CREATE TABLE IF NOT EXISTS main_reminders (
		issue_key TEXT PRIMARY KEY,
		qa_email TEXT NOT NULL,
		message_id TEXT NOT NULL,
		sent_time TIMESTAMP NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_reminders_qa_email ON reminders(qa_email);
	CREATE INDEX IF NOT EXISTS idx_reminders_completed_time ON reminders(completed_time);
	CREATE INDEX IF NOT EXISTS idx_reminders_last_sent_time ON reminders(last_sent_time);
	CREATE INDEX IF NOT EXISTS idx_main_reminders_qa_email ON main_reminders(qa_email);
	`

	if _, err := conn.Exec(createTablesSQL); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	once.Do(func() {
		instance = &DB{conn: conn}
	})

	return nil
}

// IsAvailable returns true if database is initialized
func (db *DB) IsAvailable() bool {
	return db != nil && db.conn != nil
}

// QAReminder represents a QA reminder in the database
type QAReminder struct {
	IssueKey       string
	QAName         string
	QAEmail        string
	MessageID      string
	SentTime       time.Time
	LastSentTime   time.Time
	ReminderNumber int
	Summary        string
	IssueType      string
	ButtonStatus   string
	UpdatedTime    time.Time
	CompletedTime  time.Time
}

// SaveReminder saves a reminder to the database
func (db *DB) SaveReminder(reminder *QAReminder) error {
	if !db.IsAvailable() {
		return nil // Database not available, skip
	}

	_, err := db.conn.Exec(`
		INSERT INTO reminders (
			issue_key, qa_name, qa_email, message_id, sent_time, last_sent_time,
			reminder_number, summary, issue_type, button_status, updated_time, completed_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (issue_key) DO UPDATE SET
			qa_name = EXCLUDED.qa_name,
			qa_email = EXCLUDED.qa_email,
			message_id = EXCLUDED.message_id,
			sent_time = EXCLUDED.sent_time,
			last_sent_time = EXCLUDED.last_sent_time,
			reminder_number = EXCLUDED.reminder_number,
			summary = EXCLUDED.summary,
			issue_type = EXCLUDED.issue_type,
			button_status = EXCLUDED.button_status,
			updated_time = EXCLUDED.updated_time,
			completed_time = EXCLUDED.completed_time
	`,
		reminder.IssueKey,
		reminder.QAName,
		reminder.QAEmail,
		reminder.MessageID,
		reminder.SentTime,
		reminder.LastSentTime,
		reminder.ReminderNumber,
		reminder.Summary,
		reminder.IssueType,
		reminder.ButtonStatus,
		reminder.UpdatedTime,
		reminder.CompletedTime,
	)

	return err
}

// SaveReminderCount saves reminder count for a QA
func (db *DB) SaveReminderCount(qaEmail string, count int) error {
	if !db.IsAvailable() {
		return nil
	}

	_, err := db.conn.Exec(`
		INSERT INTO reminder_counts (qa_email, count) VALUES ($1, $2)
		ON CONFLICT (qa_email) DO UPDATE SET count = EXCLUDED.count
	`, qaEmail, count)

	return err
}

// SaveDailyMessage saves daily message record
func (db *DB) SaveDailyMessage(email, date string) error {
	if !db.IsAvailable() {
		return nil
	}

	_, err := db.conn.Exec(`
		INSERT INTO daily_messages (email, date) VALUES ($1, $2)
		ON CONFLICT (email, date) DO NOTHING
	`, email, date)

	return err
}

// SaveMainReminder saves a main reminder to the database (only essential fields)
func (db *DB) SaveMainReminder(reminder *QAReminder) error {
	if !db.IsAvailable() {
		return nil // Database not available, skip
	}

	_, err := db.conn.Exec(`
		INSERT INTO main_reminders (
			issue_key, qa_email, message_id, sent_time
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (issue_key) DO UPDATE SET
			qa_email = EXCLUDED.qa_email,
			message_id = EXCLUDED.message_id,
			sent_time = EXCLUDED.sent_time
	`,
		reminder.IssueKey,
		reminder.QAEmail,
		reminder.MessageID,
		reminder.SentTime,
	)

	return err
}

// LoadAllReminders loads all reminders from database
func (db *DB) LoadAllReminders() ([]*QAReminder, error) {
	if !db.IsAvailable() {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := db.conn.Query(`
		SELECT issue_key, qa_name, qa_email, message_id, sent_time, last_sent_time,
		       reminder_number, summary, issue_type, button_status, updated_time, completed_time
		FROM reminders
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query reminders: %w", err)
	}
	defer rows.Close()

	var reminders []*QAReminder
	for rows.Next() {
		var r QAReminder
		err := rows.Scan(
			&r.IssueKey,
			&r.QAName,
			&r.QAEmail,
			&r.MessageID,
			&r.SentTime,
			&r.LastSentTime,
			&r.ReminderNumber,
			&r.Summary,
			&r.IssueType,
			&r.ButtonStatus,
			&r.UpdatedTime,
			&r.CompletedTime,
		)
		if err != nil {
			log.Printf("WARN: Failed to scan reminder: %v", err)
			continue
		}
		reminders = append(reminders, &r)
	}

	return reminders, nil
}

// LoadAllReminderCounts loads all reminder counts from database
func (db *DB) LoadAllReminderCounts() (map[string]int, error) {
	if !db.IsAvailable() {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := db.conn.Query("SELECT qa_email, count FROM reminder_counts")
	if err != nil {
		return nil, fmt.Errorf("failed to query reminder counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var email string
		var count int
		if err := rows.Scan(&email, &count); err != nil {
			log.Printf("WARN: Failed to scan reminder count: %v", err)
			continue
		}
		counts[email] = count
	}

	return counts, nil
}

// LoadAllDailyMessages loads all daily messages from database
func (db *DB) LoadAllDailyMessages() (map[string]string, error) {
	if !db.IsAvailable() {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := db.conn.Query("SELECT email, date FROM daily_messages")
	if err != nil {
		return nil, fmt.Errorf("failed to query daily messages: %w", err)
	}
	defer rows.Close()

	messages := make(map[string]string)
	for rows.Next() {
		var email, date string
		if err := rows.Scan(&email, &date); err != nil {
			log.Printf("WARN: Failed to scan daily message: %v", err)
			continue
		}
		messages[email] = date
	}

	return messages, nil
}

// LoadAllMainReminders loads all main reminders from the database (only essential fields)
func (db *DB) LoadAllMainReminders() ([]QAReminder, error) {
	if !db.IsAvailable() {
		return nil, fmt.Errorf("database not available")
	}

	rows, err := db.conn.Query(`
		SELECT issue_key, qa_email, message_id, sent_time
		FROM main_reminders
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reminders []QAReminder
	for rows.Next() {
		var r QAReminder
		if err := rows.Scan(
			&r.IssueKey,
			&r.QAEmail,
			&r.MessageID,
			&r.SentTime,
		); err != nil {
			return nil, err
		}
		// Set default values for fields not stored in main_reminders
		r.ReminderNumber = 0
		r.LastSentTime = r.SentTime
		reminders = append(reminders, r)
	}

	return reminders, rows.Err()
}

// DeleteReminder deletes a reminder from database
func (db *DB) DeleteReminder(issueKey string) error {
	if !db.IsAvailable() {
		return nil
	}

	_, err := db.conn.Exec("DELETE FROM reminders WHERE issue_key = $1", issueKey)
	return err
}

// DeleteOldDailyMessages deletes daily messages older than the specified date
func (db *DB) DeleteOldDailyMessages(date string) error {
	if !db.IsAvailable() {
		return nil
	}

	_, err := db.conn.Exec("DELETE FROM daily_messages WHERE date != $1", date)
	return err
}
