#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
    echo "📝 Loading environment variables from .env..."
    export $(cat .env | grep -v '^#' | xargs)
    echo "✅ Environment variables loaded!"
    echo "   SEATALK_APP_ID: ${SEATALK_APP_ID:0:8}..."
    echo "   SEATALK_APP_SECRET: ${SEATALK_APP_SECRET:0:8}..."
    echo "   SEATALK_SIGNING_SECRET: ${SEATALK_SIGNING_SECRET:0:8}..."
    echo "   JIRA_BASE_URL: $JIRA_BASE_URL"
    echo "   JIRA_USERNAME: $JIRA_USERNAME"
else
    echo "❌ Error: .env file not found!"
    exit 1
fi

# Run the bot
echo "🚀 Starting KnowledgeBot..."
go run main.go

