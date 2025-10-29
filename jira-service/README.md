# Jira Service

A microservice that provides Jira API access through a VPN connection for the Knowledge Bot.

## Purpose

This service acts as a bridge between the Knowledge Bot (deployed on Render) and Shopee's internal Jira instance. Since the bot runs on external infrastructure without VPN access, this service runs on a server with VPN connectivity to access Jira.

## Architecture

```
Render Bot → HTTP API → Jira Service (with VPN) → Shopee Jira
```

## Setup

### 1. Environment Variables

Create a `.env` file with the following variables:

```bash
# Jira Configuration
JIRA_BASE_URL=https://jira.shopee.io
JIRA_USERNAME=your-username
JIRA_API_TOKEN=your-api-token

# Server Configuration
PORT=8082
```

### 2. Build and Run

```bash
# Download dependencies
go mod tidy

# Build the service
go build -o jira-service main.go

# Run the service
./jira-service
```

### 3. Test the Service

```bash
# Health check
curl http://localhost:8082/health

# Search for tickets
curl -X POST http://localhost:8082/search \
  -H "Content-Type: application/json" \
  -d '{"qa_email": "test@shopee.com"}'
```

## API Endpoints

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

### POST /search
Search for Jira tickets by QA email.

**Request:**
```json
{
  "qa_email": "qa@shopee.com"
}
```

**Response:**
```json
{
  "issues": [
    {
      "key": "PROJ-123",
      "fields": {
        "summary": "Ticket Summary",
        "status": {
          "name": "DONE"
        },
        "issuetype": {
          "name": "Story"
        },
        "updated": "2025-10-29T10:00:00.000+0800"
      }
    }
  ]
}
```

## Deployment

### On Shopee VM with VPN

1. **Set up VPN connection** to Shopee network
2. **Configure environment variables** with Jira credentials
3. **Run the service** on port 8082
4. **Use ngrok** to expose the service publicly
5. **Configure Render bot** to use the ngrok URL

### On External Server with VPN

1. **Deploy to external server** (AWS, DigitalOcean, etc.)
2. **Install VPN client** (Cisco AnyConnect, OpenVPN)
3. **Connect to Shopee VPN**
4. **Run the service** with public access
5. **Configure Render bot** to use the server URL

## Security

- **VPN required** for Jira access
- **CORS enabled** for cross-origin requests
- **No authentication** (relies on network security)
- **HTTPS recommended** for production

## Monitoring

- **Health check endpoint** for uptime monitoring
- **Structured logging** for debugging
- **Error handling** for API failures
