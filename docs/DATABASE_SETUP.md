# Database Persistence Setup

The knowledgebot now supports database persistence to prevent data loss when the service restarts or spins down.

## Why Database Persistence?

When Render (or other free hosting) spins down your service, all in-memory data is lost:
- All reminder tracking
- Reminder counts
- Daily message deduplication
- Button click tracking

With database persistence, all this data is saved and automatically restored when the service restarts.

## Setup Instructions

### Option 1: Supabase (Recommended - Free)

1. **Sign up at [supabase.com](https://supabase.com)**
   - Create a new project
   - Wait for database to be provisioned (~2 minutes)

2. **Get your connection string**
   - Go to Project Settings → Database
   - Find "Connection string" → "URI"
   - Copy the connection string (looks like: `postgresql://postgres:[YOUR-PASSWORD]@db.xxx.supabase.co:5432/postgres`)

3. **Add to Render environment variables**
   - Go to your Render service dashboard
   - Navigate to Environment tab
   - Add new variable:
     - **Key**: `DATABASE_URL`
     - **Value**: Your Supabase connection string

4. **Deploy**
   - The bot will automatically connect to the database on startup
   - Tables will be created automatically
   - Existing data will be loaded from database

### Option 2: Neon (Free PostgreSQL)

1. **Sign up at [neon.tech](https://neon.tech)**
2. **Create a new project**
3. **Copy the connection string**
4. **Add `DATABASE_URL` to Render environment variables**

### Option 3: Railway PostgreSQL

1. **Sign up at [railway.app](https://railway.app)**
2. **Create a new PostgreSQL service**
3. **Copy the connection string from the service**
4. **Add `DATABASE_URL` to Render environment variables**

## How It Works

### Automatic Features

1. **On Startup**: 
   - Bot connects to database
   - Loads all reminders, counts, and daily messages
   - Continues with in-memory if database unavailable

2. **On Data Changes**:
   - All reminders are automatically saved to database
   - Reminder counts are saved
   - Daily messages are saved

3. **On Cleanup**:
   - Old reminders are removed from both memory and database

### Database Schema

The bot creates 3 tables automatically:

1. **`reminders`** - Stores all QA reminders
2. **`reminder_counts`** - Stores reminder counts per QA
3. **`daily_messages`** - Stores daily message deduplication

## Testing

1. **Check logs on startup**:
   ```
   INFO: Database connection established
   INFO: Loaded X reminders from database
   ```

2. **If database not configured**:
   ```
   WARN: Database not available (continuing with in-memory only)
   INFO: To enable persistence, set DATABASE_URL environment variable
   ```

3. **Test persistence**:
   - Create a reminder
   - Restart the service
   - Check that the reminder still exists

## Troubleshooting

### Database connection fails
- Check `DATABASE_URL` is set correctly
- Verify database is accessible (not paused)
- Check firewall/network settings

### Data not persisting
- Check logs for database errors
- Verify tables were created (check database directly)
- Ensure `DATABASE_URL` is set in environment variables

### Performance concerns
- Database operations are async and non-blocking
- Errors are logged but don't stop the bot
- Bot continues with in-memory if database fails

## Migration from In-Memory Only

If you already have reminders in memory:
1. Set up database
2. Restart the service
3. Old in-memory data will be lost, but new data will persist
4. Future reminders will be saved to database

## Notes

- Database is **optional** - bot works without it (in-memory only)
- All database operations are **non-blocking**
- Errors are **logged but don't crash** the bot
- Database connection is **tested on startup**
- Tables are **created automatically** if they don't exist

