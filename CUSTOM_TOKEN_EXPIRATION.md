# Custom Token Expiration Control

## Overview

The `[HttpPost("Get AAD Token")]` endpoint now supports manual control over token expiration time intervals, allowing you to implement custom token refresh cycles for enhanced security.

## What This Feature Provides

### 1. Custom Expiration Time Control
- Set custom expiration intervals from 1 minute to 24 hours (1440 minutes)
- Default expiration: 60 minutes if not specified
- Forces manual token regeneration at specified intervals

### 2. Enhanced Response Information
The API response now includes detailed expiration information:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "https://graph.microsoft.com/.default",
  "expires_at": "2025-09-11T15:30:00.000Z",
  "issued_at": "2025-09-11T14:30:00.000Z",
  "expires_in_human": "59 minute(s), 59 second(s)",
  "custom_expires_in_minutes": 60,
  "custom_expires_at": "2025-09-11T15:30:00.000Z",
  "token_refresh_guidance": "Recommended to refresh token after 60 minutes for security"
}
```

## Usage Examples

### Example 1: Default Expiration (60 minutes)

**Request:**
```json
POST /Token/Get AAD Token
Content-Type: application/json

{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scope": "https://graph.microsoft.com/.default"
}
```

### Example 2: Custom 30-minute Expiration

**Request:**
```json
POST /Token/Get AAD Token
Content-Type: application/json

{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in_minutes": 30
}
```

### Example 3: High Security - 15-minute Expiration

**Request:**
```json
POST /Token/Get AAD Token
Content-Type: application/json

{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in_minutes": 15
}
```

## Implementation Strategy

### 1. Automatic Token Refresh Cycle

Implement a timer in your client application:

```javascript
// Example JavaScript implementation
class TokenManager {
    constructor(clientId, clientSecret, expirationMinutes = 60) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.expirationMinutes = expirationMinutes;
        this.token = null;
        this.refreshTimer = null;
    }

    async generateToken() {
        const response = await fetch('/Token/Get AAD Token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: this.clientId,
                client_secret: this.clientSecret,
                expires_in_minutes: this.expirationMinutes
            })
        });

        const tokenData = await response.json();
        this.token = tokenData.access_token;
        
        // Schedule next refresh
        this.scheduleRefresh();
        
        return tokenData;
    }

    scheduleRefresh() {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
        }
        
        // Refresh 1 minute before expiration
        const refreshTime = (this.expirationMinutes - 1) * 60 * 1000;
        this.refreshTimer = setTimeout(() => {
            this.generateToken();
        }, refreshTime);
    }
}
```

### 2. Security Recommendations

| Use Case | Recommended Expiration | Rationale |
|----------|----------------------|-----------|
| High Security Applications | 15-30 minutes | Minimizes exposure window |
| Standard Applications | 60 minutes | Balances security and usability |
| Batch Processing | 120-240 minutes | Reduces token refresh overhead |
| Development/Testing | 60 minutes | Standard for testing purposes |

### 3. Response Field Explanations

| Field | Description |
|-------|-------------|
| `expires_in` | Azure AD token lifetime in seconds (from Azure AD) |
| `expires_at` | When the Azure AD token expires (UTC) |
| `issued_at` | When the token was issued (UTC) |
| `expires_in_human` | Human-readable format of Azure AD expiration |
| `custom_expires_in_minutes` | Your custom expiration setting |
| `custom_expires_at` | When you should manually refresh (UTC) |
| `token_refresh_guidance` | Recommendation based on your settings |

## Important Notes

### 1. Azure AD vs Custom Expiration
- Azure AD tokens have their own expiration (typically 1 hour)
- Your custom expiration is for **when you should refresh**, not the actual token validity
- If your custom expiration > Azure AD expiration, you'll get guidance to refresh before Azure AD expiration

### 2. Validation Rules
- Minimum: 1 minute
- Maximum: 1440 minutes (24 hours)
- Invalid values return HTTP 400 with error details

### 3. Error Handling

**Invalid Expiration Time:**
```json
{
  "error": "invalid_request",
  "error_description": "expires_in_minutes must be between 1 and 1440 (24 hours)"
}
```

## Best Practices

1. **Choose appropriate expiration times** based on your security requirements
2. **Implement automatic refresh** 1-2 minutes before your custom expiration
3. **Store tokens securely** and never log them
4. **Handle refresh failures** gracefully with retry logic
5. **Monitor token usage** to optimize expiration times

## Integration with Existing Code

This feature is backward compatible. Existing code will continue to work with the default 60-minute expiration setting. The enhanced response fields provide additional information without breaking existing integrations.