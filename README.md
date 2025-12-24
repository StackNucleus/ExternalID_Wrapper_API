# OIDC External ID API

A streamlined ASP.NET Core Web API for managing Azure AD users through Microsoft Graph API. This API provides secure user management operations with Azure AD token-based authentication.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Getting Started](#getting-started)
- [Usage Examples](#usage-examples)
- [Swagger UI](#swagger-ui)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This API enables secure user management operations in Azure AD External Identities through Microsoft Graph API integration. It supports user retrieval, updates, and deletion operations using flexible identifier types (Object ID, UPN, or Email).

### Key Features

- **Azure AD token generation** for Microsoft Graph API access
- **User management operations** (Get, Update, Delete)
- **Flexible user identification** (Object ID, UPN, Email)
- **JWT Bearer token authentication**
- **Comprehensive Swagger/OpenAPI documentation**
- **Built with .NET 8.0** and C#

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/Token/getAAD-Token/v1.0` | Generate Azure AD access token |
| GET | `/Graph/getUserByIdentifier/v1.0` | Retrieve user details by identifier |
| PATCH | `/Graph/updateUserByIdentifier/v1.0` | Update user attributes by identifier |
| PATCH | `/Graph/updateUserAttributesByIdentifier/v1.0` | Update specific user attributes |
| DELETE | `/Graph/deleteUserByIdentifier/v1.0` | Delete user by identifier |
| GET | `/DGraph/getUserByIdentifier/v1.0` | Retrieve user details (delegated permissions) |
| PATCH | `/DGraph/updateUserByIdentifier/v1.0` | Update user attributes (delegated permissions) |
| DELETE | `/DGraph/deleteUserByIdentifier/v1.0` | Delete user (delegated permissions) |

## 🏗️ Architecture

### API Flow Diagram

```
┌─────────────────┐    1. Generate Token     ┌──────────────────┐
│   Client App    │ ───────────────────────▶ │   Token Endpoint │
└─────────────────┘                          └──────────────────┘
         │                                           │
         │    2. Include Bearer Token                │
         ▼                                           ▼
┌─────────────────┐    3. API Request      ┌──────────────────┐
│   Client App    │ ───────────────────────▶ │  Graph Endpoints │
└─────────────────┘                          └──────────────────┘
         │                                           │
         │    4. Microsoft Graph API Call            │
         ▼                                           ▼
┌─────────────────┐    5. Response         ┌──────────────────┐
│   Client App    │ ◀─────────────────────── │  Microsoft Graph │
└─────────────────┘                          └──────────────────┘
```

### Authentication Flow

1. **Token Generation**: Client requests Azure AD token using client credentials
2. **Token Validation**: API validates the Azure AD token
3. **Microsoft Graph Access**: API uses service credentials to access Microsoft Graph
4. **Response**: API returns user data to client

### Technology Stack

- **Framework**: ASP.NET Core 8.0
- **Authentication**: JWT Bearer Tokens + Azure AD
- **API Documentation**: Swagger/OpenAPI
- **HTTP Client**: HttpClient with factory pattern
- **Logging**: Microsoft.Extensions.Logging
- **Configuration**: JSON configuration files

## 🔐 Authentication

### Azure AD Token Generation

The API uses Azure AD tokens for authentication. Tokens are generated using the client credentials flow.

#### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_id` | string | Your Azure AD application client ID |
| `client_secret` | string | Your Azure AD application client secret |
| `scope` | string | OAuth2 scope (default: `https://graph.microsoft.com/.default`) |
| `expires_in_minutes` | int | Custom expiration time (1-1440 minutes, default: 60) |

#### Example Request

```json
POST /Token/getAAD-Token/v1.0
Content-Type: application/json

{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in_minutes": 60
}
```

#### Example Response

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1Q...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "https://graph.microsoft.com/.default",
  "expires_at": "2025-09-11T15:30:00.000Z",
  "issued_at": "2025-09-11T14:30:00.000Z",
  "expires_in_human": "59 minute(s), 59 second(s)",
  "custom_expires_in_minutes": 60,
  "custom_expires_at": "2025-09-11T15:30:00.000Z",
  "token_refresh_guidance": "Recommended to refresh token after 60 minutes for security"
}
```

### Using the Token in Requests

Include the token in the Authorization header:

```http
GET /Graph/getUserByIdentifier/v1.0?identifier=user@domain.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1Q...
```

### Token Expiration

- **Azure AD tokens** expire after 1 hour by default
- **Custom expiration** allows you to set shorter refresh cycles for enhanced security
- **Automatic refresh** recommended 1-2 minutes before expiration

## 📡 API Endpoints

### 1. Generate Azure AD Token

**Endpoint**: `POST /Token/getAAD-Token/v1.0`

Generates an Azure AD access token using client credentials flow.

**Request Parameters**:
- `client_id` (required): Azure AD application client ID
- `client_secret` (required): Azure AD application client secret
- `scope` (optional): OAuth2 scope (default: `https://graph.microsoft.com/.default`)
- `expires_in_minutes` (optional): Custom expiration time (1-1440 minutes)

**Response Fields**:
- `access_token`: The Azure AD access token
- `token_type`: Always "Bearer"
- `expires_in`: Token expiration in seconds
- `scope`: Granted OAuth2 scope
- `expires_at`: Absolute expiration time (UTC)
- `issued_at`: Token issue time (UTC)
- `expires_in_human`: Human-readable expiration duration
- `custom_expires_in_minutes`: Your custom expiration setting
- `custom_expires_at`: Recommended refresh time (UTC)
- `token_refresh_guidance`: Refresh guidance message

### 2. Get User by Identifier

**Endpoint**: `GET /Graph/getUserByIdentifier/v1.0`

Retrieves user details from Microsoft Graph API using flexible identifier types.

**Query Parameters**:
- `identifier` (required): User Object ID, UPN, or Email address

**Response Example**:
```json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "userPrincipalName": "user@domain.com",
  "displayName": "John Doe",
  "givenName": "John",
  "surname": "Doe",
  "mail": "user@domain.com",
  "jobTitle": "Software Engineer",
  "officeLocation": "Building 1",
  "mobilePhone": "+1 555-123-4567",
  "businessPhones": ["+1 555-987-6543"],
  "accountEnabled": true
}
```

### 3. Update User by Identifier

**Endpoint**: `PATCH /Graph/updateUserByIdentifier/v1.0`

Updates user attributes using flexible identifier types.

**Query Parameters**:
- `identifier` (required): User Object ID, UPN, or Email address

**Request Body**:
```json
{
  "displayName": "Jane Smith",
  "jobTitle": "Senior Software Engineer",
  "department": "Engineering",
  "mobilePhone": "+1 555-555-5555"
}
```

**Response Example**:
```json
{
  "message": "User updated successfully",
  "userId": "12345678-1234-1234-1234-123456789012"
}
```

### 4. Update User Attributes by Identifier

**Endpoint**: `PATCH /Graph/updateUserAttributesByIdentifier/v1.0`

Updates specific user attributes using a structured model.

**Query Parameters**:
- `identifier` (required): User Object ID, UPN, or Email address

**Request Body**:
```json
{
  "firstName": "John",
  "lastName": "Smith",
  "DisplayName": "John Smith"
}
```

### 5. Delete User by Identifier

**Endpoint**: `DELETE /Graph/deleteUserByIdentifier/v1.0`

Deletes a user from Microsoft Graph API.

**Query Parameters**:
- `identifier` (required): User Object ID, UPN, or Email address

**Response Example**:
```json
{
  "message": "User deleted successfully",
  "userId": "12345678-1234-1234-1234-123456789012"
}
```

### 6. DGraphController Endpoints (Delegated Permissions)

The DGraphController provides the same endpoints as GraphController but uses delegated permissions with the authenticated user's token directly.

**Available Endpoints**:
- `GET /DGraph/getUserByIdentifier/v1.0`
- `PATCH /DGraph/updateUserByIdentifier/v1.0`
- `DELETE /DGraph/deleteUserByIdentifier/v1.0`

**Key Differences**:
- Uses the authenticated user's access token directly with Microsoft Graph API
- Supports delegated permissions model
- Requires user-level permissions instead of application permissions

## ⚙️ Configuration

### Required Configuration

The API requires Azure AD configuration in `appsettings.json`:

```json
{
  "AzureAd": {
    "TenantId": "yourdomain.onmicrosoft.com",
    "ClientId": "your-azure-ad-client-id",
    "ClientSecret": "your-azure-ad-client-secret"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

### Configuration Values Explained

| Setting | Description |
|---------|-------------|
| `TenantId` | Your Azure AD tenant identifier (domain name or GUID) |
| `ClientId` | Application ID from your Azure AD app registration |
| `ClientSecret` | Client secret from your Azure AD app registration |

### Azure AD App Registration Setup

1. **Register Application**: In Azure Portal, register a new application
2. **Generate Client Secret**: Create a client secret for authentication
3. **Configure API Permissions**: Add Microsoft Graph permissions
4. **Grant Admin Consent**: Approve permissions for your tenant

### Required Microsoft Graph Permissions

| Permission | Type | Description |
|------------|------|-------------|
| `User.Read.All` | Application | Read all users' full profiles |
| `User.ReadWrite.All` | Application | Read and write all users' full profiles |
| `Directory.Read.All` | Application | Read directory data |

## 🚀 Getting Started

### Prerequisites

- .NET 8.0 SDK
- Azure AD tenant with appropriate permissions
- Microsoft Graph API access

### Installation Steps

#### 1. Clone the Repository

```bash
git clone <repository-url>
cd Wrapper-API-Modifications
```

#### 2. Restore NuGet Packages

```bash
dotnet restore
```

#### 3. Configure Azure AD Settings

Update `appsettings.json` with your Azure AD configuration:

```json
{
  "AzureAd": {
    "TenantId": "yourdomain.onmicrosoft.com",
    "ClientId": "your-azure-ad-client-id",
    "ClientSecret": "your-azure-ad-client-secret"
  }
}
```

#### 4. Build the Project

```bash
dotnet build
```

#### 5. Run the API

```bash
dotnet run
```

The API will start on `https://localhost:7110` by default.

### Making Your First API Call

#### Step 1: Generate an Azure AD Token

```bash
curl -X POST "https://localhost:7110/Token/getAAD-Token/v1.0" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "scope": "https://graph.microsoft.com/.default",
    "expires_in_minutes": 60
  }'
```

#### Step 2: Use the Token to Get a User

```bash
curl -X GET "https://localhost:7110/Graph/getUserByIdentifier/v1.0?identifier=user@domain.com" \
  -H "Authorization: Bearer <your-access-token>"
```

### Using Swagger UI

1. **Access Swagger UI**: Navigate to `https://localhost:7110/swagger`
2. **Generate Token**: Use the token endpoint to get an access token
3. **Authorize**: Click "Authorize" and enter `Bearer <your-token>`
4. **Test Endpoints**: Try the Graph endpoints with your token

## 📚 Usage Examples

### cURL Examples

#### Generate Token

```bash
# Generate Azure AD token
curl -X POST "https://localhost:7110/Token/getAAD-Token/v1.0" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "scope": "https://graph.microsoft.com/.default",
    "expires_in_minutes": 60
  }'
```

#### Get User

```bash
# Get user by email
curl -X GET "https://localhost:7110/Graph/getUserByIdentifier/v1.0?identifier=user@domain.com" \
  -H "Authorization: Bearer <your-token>"

# Get user by Object ID
curl -X GET "https://localhost:7110/Graph/getUserByIdentifier/v1.0?identifier=12345678-1234-1234-1234-123456789012" \
  -H "Authorization: Bearer <your-token>"
```

#### Update User

```bash
# Update user attributes
curl -X PATCH "https://localhost:7110/Graph/updateUserByIdentifier/v1.0?identifier=user@domain.com" \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Jane Doe",
    "jobTitle": "Senior Developer",
    "department": "Engineering"
  }'
```

#### Delete User

```bash
# Delete user
curl -X DELETE "https://localhost:7110/Graph/deleteUserByIdentifier/v1.0?identifier=user@domain.com" \
  -H "Authorization: Bearer <your-token>"
```

### JavaScript Example

```javascript
class OIDCAPI {
    constructor(baseUrl, clientId, clientSecret) {
        this.baseUrl = baseUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.token = null;
    }

    async generateToken() {
        const response = await fetch(`${this.baseUrl}/Token/getAAD-Token/v1.0`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: this.clientId,
                client_secret: this.clientSecret,
                scope: 'https://graph.microsoft.com/.default',
                expires_in_minutes: 60
            })
        });

        const tokenData = await response.json();
        this.token = tokenData.access_token;
        return tokenData;
    }

    async getUser(identifier) {
        if (!this.token) await this.generateToken();

        const response = await fetch(`${this.baseUrl}/Graph/getUserByIdentifier/v1.0?identifier=${encodeURIComponent(identifier)}`, {
            headers: { 'Authorization': `Bearer ${this.token}` }
        });

        return await response.json();
    }

    async updateUser(identifier, updates) {
        if (!this.token) await this.generateToken();

        const response = await fetch(`${this.baseUrl}/Graph/updateUserByIdentifier/v1.0?identifier=${encodeURIComponent(identifier)}`, {
            method: 'PATCH',
            headers: { 
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updates)
        });

        return await response.json();
    }
}

// Usage
const api = new OIDCAPI('https://localhost:7110', 'your-client-id', 'your-client-secret');
await api.generateToken();
const user = await api.getUser('user@domain.com');
console.log(user);
```

## 🎨 Swagger UI

The API includes enhanced Swagger UI features:

### Features
- **Interactive Documentation**: Test endpoints directly in the browser
- **Authentication Support**: Easy token authorization
- **Request/Response Examples**: Clear examples for all endpoints
- **Real-time Testing**: Execute requests and see responses immediately

### Accessing Swagger UI
1. Start the API: `dotnet run`
2. Open browser: `https://localhost:7110/swagger`
3. Explore endpoints and test functionality

### Using Swagger UI for Authentication
1. **Generate Token**: Use the Token endpoint to get an access token
2. **Authorize**: Click the "Authorize" button
3. **Enter Token**: Paste `Bearer <your-token>` in the authorization field
4. **Test Endpoints**: All Graph endpoints will now include your token

## 🔧 Troubleshooting

### Common Issues

#### 401 Unauthorized
**Cause**: Missing or invalid Azure AD token
**Solution**: 
1. Generate a new token using the Token endpoint
2. Verify the token format: `Bearer <access_token>`
3. Check token expiration

#### 404 Not Found
**Cause**: User not found in Azure AD
**Solution**: 
1. Verify the identifier is correct
2. Check if user exists in Azure AD
3. Try different identifier types (Object ID, UPN, Email)

#### 403 Forbidden
**Cause**: Insufficient permissions
**Solution**: 
1. Verify Azure AD app has required permissions
2. Ensure admin consent is granted
3. Check permission types (Application vs Delegated)

#### Configuration Errors
**Cause**: Missing or incorrect Azure AD configuration
**Solution**: 
1. Verify `appsettings.json` has correct values
2. Check Azure AD app registration
3. Ensure client secret is valid

### Error Response Format

```json
{
  "error": "error_code",
  "error_description": "Detailed error message",
  "error_codes": [error_code_numbers],
  "timestamp": "2025-09-11T14:30:00.0000000Z",
  "trace_id": "12345678-1234-1234-1234-123456789012",
  "correlation_id": "12345678-1234-1234-1234-123456789012"
}
```

### Logging and Diagnostics

Enable detailed logging in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.Graph": "Debug"
    }
  }
}
```

### Getting Help

1. **Check Logs**: Review application logs for detailed error information
2. **Verify Configuration**: Double-check Azure AD settings
3. **Test with Postman**: Use Postman to isolate issues
4. **Azure AD Portal**: Check app registration and permissions

## 🔒 Security

### Best Practices

1. **Secure Client Secrets**: Never commit client secrets to version control
2. **Use HTTPS**: Always use HTTPS in production
3. **Token Expiration**: Implement token refresh cycles
4. **Least Privilege**: Grant minimal required permissions
5. **Input Validation**: Validate all user inputs
6. **Error Handling**: Don't expose sensitive information in error messages

### Token Security

- **Short Expiration**: Use shorter token expiration times for high-security scenarios
- **Secure Storage**: Store tokens securely, never in plain text
- **Transmission**: Always use HTTPS for token transmission
- **Logging**: Never log tokens or sensitive credentials

### Azure AD Security

- **App Registration**: Use dedicated app registrations for different environments
- **Permissions**: Grant only necessary Microsoft Graph permissions
- **Admin Consent**: Control who can grant admin consent
- **Monitoring**: Monitor Azure AD logs for suspicious activity

## 🤝 Contributing

### Development Setup

1. **Fork the Repository**: Create your own fork
2. **Clone Locally**: `git clone <your-fork>`
3. **Install Dependencies**: `dotnet restore`
4. **Build Project**: `dotnet build`
5. **Run Tests**: `dotnet test` (if available)

### Code Guidelines

- Follow .NET naming conventions
- Include XML documentation for public APIs
- Write unit tests for new functionality
- Maintain backward compatibility
- Use meaningful commit messages

### Pull Request Process

1. Create feature branch: `git checkout -b feature/your-feature`
2. Commit changes: `git commit -m "Add your feature"`
3. Push to branch: `git push origin feature/your-feature`
4. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support and questions:

1. **Documentation**: Check this README for comprehensive information
2. **Swagger UI**: Use the interactive API documentation
3. **Azure AD Documentation**: Refer to Microsoft's Azure AD documentation
4. **Microsoft Graph Documentation**: Check Microsoft Graph API documentation

---

**Note**: This API is designed for managing Azure AD External Identities and requires appropriate Azure AD permissions and configuration.
```

<tool_call>
