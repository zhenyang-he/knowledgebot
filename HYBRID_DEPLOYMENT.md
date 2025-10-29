# Hybrid Deployment Guide

Deploy your Knowledge Bot using a hybrid architecture with a separate Jira service.

## Architecture Overview

```
Render Bot (Public) → HTTP API → Jira Service (VPN) → Shopee Jira
```

## Components

1. **Knowledge Bot** - Deployed on Render (handles SeaTalk webhooks)
2. **Jira Service** - Deployed on VPN-enabled server (handles Jira API calls)
3. **ngrok** - Exposes Jira service publicly (optional)

## Step 1: Deploy Jira Service

### Option A: On Shopee VM with ngrok

1. **Set up Jira service** on your Shopee VM:
   ```bash
   cd jira-service
   go mod tidy
   go build -o jira-service main.go
   ```

2. **Configure environment variables**:
   ```bash
   # Create .env file
   cat > .env << EOF
   JIRA_BASE_URL=https://jira.shopee.io
   JIRA_USERNAME=your-username
   JIRA_API_TOKEN=your-api-token
   PORT=8082
   EOF
   ```

3. **Run the service**:
   ```bash
   source .env
   ./jira-service
   ```

4. **Set up ngrok**:
   ```bash
   # Install ngrok
   wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
   tar -xzf ngrok-v3-stable-linux-amd64.tgz
   sudo mv ngrok /usr/local/bin/
   
   # Create tunnel
   ngrok http 8082
   ```

5. **Note the ngrok URL** (e.g., `https://abc123.ngrok.io`)

### Option B: On External Server with VPN

1. **Deploy to external server** (AWS, DigitalOcean, etc.)
2. **Install VPN client** (Cisco AnyConnect, OpenVPN)
3. **Connect to Shopee VPN**
4. **Deploy Jira service** with public access
5. **Note the server URL** (e.g., `https://your-server.com:8082`)

## Step 2: Deploy Knowledge Bot to Render

1. **Create Render account** at [render.com](https://render.com)

2. **Create new Web Service**:
   - **Build Command**: `go build -o knowledgebot main.go`
   - **Start Command**: `./knowledgebot`
   - **Environment**: `Go`

3. **Set environment variables**:
   ```bash
   # SeaTalk Configuration
   SEATALK_APP_ID=your-app-id
   SEATALK_APP_SECRET=your-app-secret
   SEATALK_SIGNING_SECRET=your-signing-secret
   
   # Server Configuration
   PORT=8080
   
   # Jira Service Configuration (use ngrok URL or server URL)
   JIRA_SERVICE_URL=https://abc123.ngrok.io
   
   # VPN Configuration (disabled for hybrid)
   VPN_ENABLED=false
   ```

4. **Deploy the service**

## Step 3: Configure SeaTalk

1. **Update webhook URL** to your Render service:
   ```
   https://your-app.onrender.com/webhook
   ```

2. **Test the webhook** using SeaTalk's verification

## Step 4: Test the Setup

### Test Jira Service
```bash
# Health check
curl https://abc123.ngrok.io/health

# Search tickets
curl -X POST https://abc123.ngrok.io/search \
  -H "Content-Type: application/json" \
  -d '{"qa_email": "test@shopee.com"}'
```

### Test Knowledge Bot
```bash
# Health check
curl https://your-app.onrender.com/health

# Test webhook
curl -X POST https://your-app.onrender.com/callback \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "event_verification",
    "event": {
      "seatalk_challenge": "test123"
    }
  }'
```

## Troubleshooting

### Common Issues

1. **Jira service not accessible**:
   - Check if ngrok is running
   - Verify VPN connection
   - Check firewall settings

2. **Render bot can't reach Jira service**:
   - Verify JIRA_SERVICE_URL is correct
   - Check if ngrok URL is accessible
   - Test with curl commands

3. **SeaTalk webhook fails**:
   - Check if Render service is running
   - Verify webhook URL in SeaTalk
   - Check logs for errors

### Monitoring

1. **Jira Service Logs**:
   ```bash
   # On VM or server
   tail -f jira-service.log
   ```

2. **Render Service Logs**:
   - Check Render dashboard
   - View service logs

3. **ngrok Logs**:
   ```bash
   # Check ngrok status
   ngrok status
   ```

## Security Considerations

1. **VPN Access**: Jira service must have VPN access to Shopee network
2. **HTTPS**: Use HTTPS for all external communications
3. **API Keys**: Keep Jira API tokens secure
4. **Network**: Consider using private networks for production

## Cost Optimization

1. **Free Tier**: Use Render free tier for bot
2. **ngrok**: Free tier for testing, paid for production
3. **Server**: Use free tier VPS (AWS, Oracle Cloud) for Jira service
4. **Monitoring**: Use free monitoring tools

## Scaling

1. **Multiple Jira Services**: Deploy multiple instances for high availability
2. **Load Balancer**: Use load balancer for Jira services
3. **Caching**: Add Redis caching for Jira responses
4. **Monitoring**: Add comprehensive monitoring and alerting
