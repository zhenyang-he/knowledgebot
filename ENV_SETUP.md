# Environment Variables Setup

## Required Environment Variables

Before running the bot, set the following environment variables:

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

## How to Get Jira API Token

1. Go to https://jira.shopee.io
2. Click on your profile icon → Settings
3. Navigate to Security → API Tokens
4. Click "Create API Token"
5. Copy the generated token

## Running the Bot

```bash
# Set environment variables
export JIRA_USERNAME="zhenyang.he@shopee.com"
export JIRA_API_TOKEN="your_actual_token"

# Run the bot
go run main.go
```

## Using .env file (Optional)

You can create a `.env` file (don't commit this!):

```bash
# .env
JIRA_BASE_URL=https://jira.shopee.io
JIRA_USERNAME=your.email@shopee.com
JIRA_API_TOKEN=your_jira_api_token_here
PORT=8080
```

Then load it before running:
```bash
export $(cat .env | xargs) && go run main.go
```
