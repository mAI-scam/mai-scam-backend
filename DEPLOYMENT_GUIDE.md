# MAI Scam Detection API - Deployment Guide

## 🚀 Overview

This guide explains how to deploy the MAI Scam Detection API with JWT and API key authentication, ensuring only authorized clients (web extensions, chatbots, etc.) can access the endpoints.

## 🔐 Security Features

### Authentication Methods

- **JWT Tokens**: Stateless authentication for web extensions and mobile apps
- **API Keys**: Long-term authentication for chatbots and third-party integrations
- **Rate Limiting**: Prevents abuse with configurable limits per client type
- **Permission-Based Access**: Granular control over what each client can access

### Security Headers

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- Content-Security-Policy: default-src 'self'

## 📋 Prerequisites

### Required Software

- Python 3.8+
- MongoDB (for data storage)
- Redis (optional, for rate limiting in production)

### Required Packages

```bash
pip install -r requirements.txt
```

## 🔧 Environment Configuration

### 1. Environment Variables

Create a `.env` file in your project root:

```env
# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRY_HOURS=24

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/maiscam-db

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=False

# Security Configuration
ALLOWED_HOSTS=localhost,127.0.0.1,your-domain.com
CORS_ORIGINS=chrome-extension://*,moz-extension://*,http://localhost:3000,https://your-domain.com
```

### 2. Production Security Checklist

- [ ] Change `JWT_SECRET_KEY` to a strong, random key
- [ ] Set `DEBUG=False` in production
- [ ] Configure `ALLOWED_HOSTS` with your domain
- [ ] Set up HTTPS with SSL certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring and logging

## 🚀 Deployment Steps

### 1. Local Development Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd mai-scam-backend

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Start the application
python router.py
```

### 2. Production Deployment

#### Option A: Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "router:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:

```bash
docker build -t mai-scam-api .
docker run -p 8000:8000 --env-file .env mai-scam-api
```

#### Option B: Direct Server Deployment

```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip nginx

# Clone and setup application
git clone <your-repo-url>
cd mai-scam-backend
pip3 install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env

# Run with gunicorn
pip3 install gunicorn
gunicorn router:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### 3. Nginx Configuration

Create `/etc/nginx/sites-available/mai-scam-api`:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/mai-scam-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 🔑 Authentication Setup

### 1. Creating API Keys for Different Clients

#### Web Extension

```bash
curl -X POST "https://your-domain.com/api/v1/auth/api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "web_extension_v1",
    "client_type": "web_extension",
    "description": "Web browser extension for real-time scam detection"
  }'
```

#### Chatbot Integration

```bash
curl -X POST "https://your-domain.com/api/v1/auth/api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "chatbot_v1",
    "client_type": "chatbot",
    "description": "Chatbot integration for email analysis"
  }'
```

#### Mobile App

```bash
curl -X POST "https://your-domain.com/api/v1/auth/api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "mobile_app_v1",
    "client_type": "mobile_app",
    "description": "Mobile application for scam detection"
  }'
```

### 2. Creating JWT Tokens

```bash
curl -X POST "https://your-domain.com/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "web_extension_v1",
    "client_type": "web_extension"
  }'
```

## 📱 Client Integration Examples

### 1. Web Extension Integration

```javascript
// Store API key securely in extension storage
const API_KEY = "mai_abc123...";

// Make authenticated requests
async function analyzeEmail(emailContent) {
  const response = await fetch("https://your-domain.com/api/v1/email/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
    },
    body: JSON.stringify({
      subject: emailContent.subject,
      content: emailContent.body,
      from_email: emailContent.from,
    }),
  });

  return await response.json();
}
```

### 2. Chatbot Integration

```python
import requests

API_KEY = 'mai_xyz789...'
BASE_URL = 'https://your-domain.com/api/v1'

def analyze_email_for_chatbot(email_content):
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY
    }

    data = {
        'subject': email_content['subject'],
        'content': email_content['body'],
        'from_email': email_content['from']
    }

    response = requests.post(
        f'{BASE_URL}/email/analyze',
        headers=headers,
        json=data
    )

    return response.json()
```

### 3. Mobile App Integration

```swift
// iOS Swift example
let apiKey = "mai_def456..."
let baseURL = "https://your-domain.com/api/v1"

func analyzeEmail(subject: String, content: String, fromEmail: String) async throws -> [String: Any] {
    let url = URL(string: "\(baseURL)/email/analyze")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")

    let body = [
        "subject": subject,
        "content": content,
        "from_email": fromEmail
    ]
    request.httpBody = try JSONSerialization.data(withJSONObject: body)

    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONSerialization.jsonObject(with: data) as! [String: Any]
}
```

## 🔍 Monitoring and Logging

### 1. Application Logs

The API includes comprehensive logging:

```bash
# View application logs
tail -f /var/log/mai-scam-api/app.log

# View nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

### 2. Health Monitoring

```bash
# Check API health
curl https://your-domain.com/health

# Check authentication service health
curl https://your-domain.com/api/v1/auth/health
```

### 3. Rate Limiting Monitoring

Monitor rate limiting with:

```bash
# Check current rate limit status
curl -H "X-API-Key: your-api-key" https://your-domain.com/debug/auth
```

## 🛡️ Security Best Practices

### 1. API Key Management

- Store API keys securely (never in client-side code)
- Rotate API keys regularly
- Use different keys for different environments
- Monitor API key usage

### 2. JWT Token Management

- Set appropriate expiration times
- Use HTTPS for all token transmission
- Implement token refresh mechanisms
- Monitor token usage patterns

### 3. Rate Limiting

- Configure appropriate limits for each client type
- Monitor for abuse patterns
- Implement progressive rate limiting
- Set up alerts for rate limit violations

### 4. Network Security

- Use HTTPS everywhere
- Implement proper CORS policies
- Set up firewall rules
- Use WAF (Web Application Firewall)

## 🔧 Troubleshooting

### Common Issues

1. **Authentication Errors**

   - Check API key format (must start with `mai_`)
   - Verify JWT token expiration
   - Ensure correct headers are set

2. **Rate Limiting Issues**

   - Check client type configuration
   - Verify rate limit settings
   - Monitor request patterns

3. **CORS Errors**
   - Verify allowed origins in configuration
   - Check browser extension permissions
   - Ensure HTTPS is used

### Debug Endpoints

For development, use the debug endpoint:

```bash
curl -H "X-API-Key: your-api-key" https://your-domain.com/debug/auth
```

**Note**: Remove debug endpoints in production.

## 📊 Performance Optimization

### 1. Database Optimization

- Index frequently queried fields
- Use connection pooling
- Implement caching strategies

### 2. API Optimization

- Enable response compression
- Implement request caching
- Use async/await patterns
- Optimize LLM calls

### 3. Monitoring

- Set up application performance monitoring
- Monitor database performance
- Track API response times
- Monitor error rates

## 🔄 Updates and Maintenance

### 1. Regular Updates

- Keep dependencies updated
- Monitor security advisories
- Update SSL certificates
- Backup data regularly

### 2. Scaling

- Use load balancers for high traffic
- Implement horizontal scaling
- Use CDN for static content
- Consider microservices architecture

## 📞 Support

For issues and questions:

1. Check the logs for error messages
2. Verify configuration settings
3. Test with the debug endpoints
4. Review the API documentation at `/docs`

## 🎯 Next Steps

1. Set up monitoring and alerting
2. Implement automated backups
3. Set up CI/CD pipeline
4. Configure production logging
5. Set up SSL certificates
6. Configure firewall rules
7. Set up monitoring dashboards

---

**Remember**: Security is an ongoing process. Regularly review and update your security measures, monitor for threats, and keep your system updated.
