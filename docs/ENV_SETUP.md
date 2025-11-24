# Environment Variables Setup

## Required Environment Variables

Before running the bot, set the following environment variables:

### SeaTalk Configuration
```bash
export SEATALK_APP_ID="your_seatalk_app_id"
export SEATALK_APP_SECRET="your_seatalk_app_secret"
export SEATALK_SIGNING_SECRET="your_seatalk_signing_secret"
```

### Jira Configuration
```bash
export JIRA_BASE_URL="https://jira.shopee.io"
export JIRA_USERNAME="your.email@shopee.com"
export JIRA_API_TOKEN="your_jira_api_token_here"
```

### Server Configuration (Optional)
```bash
export PORT="8080"  # Default is 8080
```

## How to Get SeaTalk Credentials

1. Go to your SeaTalk Developer Console
2. Find your bot application
3. Copy the following values:
   - **App ID**: Found in app settings
   - **App Secret**: Found in app settings  
   - **Signing Secret**: Found in webhook settings

## How to Get Jira API Token

1. Go to https://jira.shopee.io
2. Click on your profile icon → Settings
3. Navigate to Security → API Tokens
4. Click "Create API Token"
5. Copy the generated token

## Running the Bot

```bash
# Set environment variables
export SEATALK_APP_ID="your_seatalk_app_id"
export SEATALK_APP_SECRET="your_seatalk_app_secret"
export SEATALK_SIGNING_SECRET="your_seatalk_signing_secret"
export JIRA_USERNAME="zhenyang.he@shopee.com"
export JIRA_API_TOKEN="your_actual_token"

# Run the bot
go run main.go
```

## Using .env file (Optional)

You can create a `.env` file (don't commit this!):

```bash
# .env
SEATALK_APP_ID=your_seatalk_app_id
SEATALK_APP_SECRET=your_seatalk_app_secret
SEATALK_SIGNING_SECRET=your_seatalk_signing_secret
JIRA_BASE_URL=https://jira.shopee.io
JIRA_USERNAME=your.email@shopee.com
JIRA_API_TOKEN=your_jira_api_token_here
PORT=8080
```

Then load it before running:
```bash
export $(cat .env | xargs) && go run main.go
```
