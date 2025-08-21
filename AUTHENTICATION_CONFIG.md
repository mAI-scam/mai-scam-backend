# 🔐 Authentication Configuration Guide

## Overview

This guide explains how to control which endpoints are protected by API key and/or JWT authentication in your MAI Scam Detection API.

## 🎯 Central Configuration Location

All authentication settings are centrally controlled in **`utils/constant.py`**:

### 1. **Public Endpoints** (No Authentication Required)

```python
PUBLIC_ENDPOINTS = [
    "/docs",           # API documentation
    "/redoc",          # Alternative API docs
    "/openapi.json",   # OpenAPI specification
    "/health",         # Health check
    "/",               # Root endpoint
    "/debug/auth",     # Debug authentication
    "/auth/token",     # JWT token creation
    "/auth/api-key",   # API key creation
    "/auth/verify"     # Authentication verification
]
```

### 2. **Authentication Required Endpoints**

```python
AUTH_REQUIRED_ENDPOINTS = [
    "/email/v1/analyze",
    "/email/v1/translate",
    "/socialmedia/v1/analyze",
    "/socialmedia/v1/translate",
    "/website/v1/analyze",
    "/website/v1/translate"
]
```

### 3. **Permission-Protected Endpoints**

```python
PERMISSION_PROTECTED_ENDPOINTS = {
    "/email/v1/analyze": ["email_analysis"],
    "/email/v1/translate": ["email_analysis"],
    "/socialmedia/v1/analyze": ["social_media_analysis"],
    "/socialmedia/v1/translate": ["social_media_analysis"],
    "/website/v1/analyze": ["website_analysis"],
    "/website/v1/translate": ["website_analysis"]
}
```

### 4. **Admin-Only Endpoints**

```python
ADMIN_ENDPOINTS = [
    "/auth/keys",
    "/auth/keys/{key_id}",
    "/debug/admin"
]
```

## 🔧 How to Modify Endpoint Protection

### **Make an Endpoint Public**

Add the endpoint path to `PUBLIC_ENDPOINTS`:

```python
PUBLIC_ENDPOINTS = [
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/",
    "/debug/auth",
    "/auth/token",
    "/auth/api-key",
    "/auth/verify",
    "/your-new-public-endpoint"  # ← Add here
]
```

### **Require Authentication (Any Valid Token/Key)**

Add the endpoint to `AUTH_REQUIRED_ENDPOINTS`:

```python
AUTH_REQUIRED_ENDPOINTS = [
    "/email/v1/analyze",
    "/email/v1/translate",
    "/your-new-protected-endpoint"  # ← Add here
]
```

### **Require Specific Permissions**

Add the endpoint to `PERMISSION_PROTECTED_ENDPOINTS`:

```python
PERMISSION_PROTECTED_ENDPOINTS = {
    "/email/v1/analyze": ["email_analysis"],
    "/your-new-permission-endpoint": ["email_analysis", "website_analysis"]  # ← Add here
}
```

### **Make Admin-Only**

Add the endpoint to `ADMIN_ENDPOINTS`:

```python
ADMIN_ENDPOINTS = [
    "/auth/keys",
    "/auth/keys/{key_id}",
    "/debug/admin",
    "/your-new-admin-endpoint"  # ← Add here
]
```

## 🚀 Usage Examples

### **In Your API Files**

```python
from middleware.auth_middleware import require_auth, require_permission, require_admin

# Option 1: Use automatic endpoint-based protection (recommended)
# The middleware will automatically check permissions based on utils/constant.py

# Option 2: Manual dependency injection
@router.post("/v1/analyze")
async def analyze_endpoint(
    request: Request,
    auth: dict = Depends(require_auth)  # Any authentication
):
    pass

@router.post("/v1/analyze")
async def analyze_endpoint(
    request: Request,
    auth: dict = Depends(require_permission("email_analysis"))  # Specific permission
):
    pass

@router.post("/admin/endpoint")
async def admin_endpoint(
    request: Request,
    auth: dict = Depends(require_admin)  # Admin only
):
    pass
```

## 🔑 Client Types and Permissions

### **Available Client Types**

```python
CLIENT_TYPES = {
    "web_extension": {
        "rate_limit": {"requests": 100, "window": 3600},
        "default_permissions": ["email_analysis", "website_analysis", "social_media_analysis"]
    },
    "chatbot": {
        "rate_limit": {"requests": 1000, "window": 3600},
        "default_permissions": ["email_analysis", "website_analysis", "social_media_analysis"]
    },
    "mobile_app": {
        "rate_limit": {"requests": 50, "window": 3600},
        "default_permissions": ["email_analysis", "website_analysis", "social_media_analysis"]
    },
    "admin": {
        "rate_limit": {"requests": 10000, "window": 3600},
        "default_permissions": ["*"]  # All permissions
    }
}
```

### **Available Permissions**

- `email_analysis` - Access to email analysis endpoints
- `website_analysis` - Access to website analysis endpoints
- `social_media_analysis` - Access to social media analysis endpoints
- `*` - Admin access to all endpoints

## 🛡️ Security Best Practices

### **1. Default Security**

- All endpoints are protected by default
- Only explicitly listed endpoints in `PUBLIC_ENDPOINTS` are public

### **2. Permission Granularity**

- Use specific permissions rather than admin access when possible
- Group related endpoints under the same permission

### **3. Rate Limiting**

- Each client type has different rate limits
- Monitor usage and adjust limits as needed

### **4. API Key Management**

- Rotate API keys regularly
- Use different keys for different environments
- Monitor key usage patterns

## 🔍 Testing Authentication

### **Test Public Endpoints**

```bash
curl http://localhost:8000/health
```

### **Test Protected Endpoints**

```bash
# With JWT token
curl -X POST "http://localhost:8000/email/v1/analyze" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "content": "Hello"}'

# With API key
curl -X POST "http://localhost:8000/email/v1/analyze" \
  -H "X-API-Key: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "content": "Hello"}'
```

### **Test Permission Requirements**

```bash
# This will fail if the token doesn't have email_analysis permission
curl -X POST "http://localhost:8000/email/v1/analyze" \
  -H "Authorization: Bearer <token-without-email-permission>" \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "content": "Hello"}'
```

## 📝 Summary

- **Central Control**: All authentication settings in `utils/constant.py`
- **Default Security**: All endpoints protected unless in `PUBLIC_ENDPOINTS`
- **Granular Permissions**: Use `PERMISSION_PROTECTED_ENDPOINTS` for specific access
- **Admin Access**: Use `ADMIN_ENDPOINTS` for admin-only functionality
- **Easy Management**: Just modify the lists in `utils/constant.py` to change protection

This centralized approach makes it easy to manage authentication across your entire API while maintaining security and flexibility.
