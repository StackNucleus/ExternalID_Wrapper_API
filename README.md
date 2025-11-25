# OIDC External ID API

A streamlined ASP.NET Core Web API for managing Azure AD users through Microsoft Graph API. This API provides secure user management operations with Azure AD token-based authentication.

## Overview

This API enables secure user management operations in Azure AD External Identities through Microsoft Graph API integration. It supports user retrieval, updates, and deletion operations using flexible identifier types (Object ID, UPN, or Email).

### Key Features

- Azure AD token generation for Microsoft Graph API access
- User management operations (Get, Update, Delete)
- Flexible user identification (Object ID, UPN, Email)
- JWT Bearer token authentication
- Comprehensive Swagger/OpenAPI documentation
- Built with .NET 8.0 and C#

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/Token/Get AAD Token` | Generate Azure AD access token |
| GET | `/Graph/getUserByIdentifier` | Retrieve user details by identifier |
| PATCH | `/Graph/updateUserByIdentifier` | Update user attributes by identifier |
| PATCH | `/Graph/updateUserAttributesByIdentifier` | Update specific user attributes by identifier |
| DELETE | `/Graph/deleteUserByIdentifier` | Delete user by identifier |

### Technology Stack

- **Framework**: ASP.NET Core 8.0
- **Language**: C# 12
- **Authentication**: JWT Bearer tokens (Azure AD)
- **Graph Integration**: Microsoft Graph SDK v5.82.0
- **Documentation**: Swagger/OpenAPI (Swashbuckle v7.0.0)
- **Dependencies**:
  - Azure.Identity v1.14.0
  - Microsoft.AspNetCore.Authentication.JwtBearer v8.0.18
  - Microsoft.Graph v5.82.0
  - Newtonsoft.Json v13.0.3


## Architecture

### API Flow Diagram

```mermaid
graph TB
    Client[Client Application]
    
    subgraph "API Layer"
        TokenCtrl[TokenController]
        GraphCtrl[GraphController]
    end
    
    subgraph "Authentication"
        JWTAuth[JWT Bearer Auth]
        AzureAD[Azure AD]
    end
    
    subgraph "External Services"
        GraphAPI[Microsoft Graph API]
    end
    
    Client -->|1. Get Token| TokenCtrl
    TokenCtrl -->|2. Request Token| AzureAD
    AzureAD -->|3. Return Token| TokenCtrl
    TokenCtrl -->|4. Return Token| Client
    
    Client -->|5. API Request + Token| GraphCtrl
    GraphCtrl -->|6. Validate Token| JWTAuth
    JWTAuth -->|7. Validated| GraphCtrl
    GraphCtrl -->|8. Graph API Call| GraphAPI
    GraphAPI -->|9. User Data| GraphCtrl
    GraphCtrl -->|10. Response| Client
```

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant TokenEndpoint
    participant AzureAD
    participant GraphAPI

    Client->>TokenEndpoint: POST /Token/Get AAD Token
    TokenEndpoint->>AzureAD: Request token (client credentials)
    AzureAD-->>TokenEndpoint: Return access token
    TokenEndpoint-->>Client: Return token response
    
    Client->>API: Request with Bearer token
    API->>API: Validate Azure AD token
    API->>GraphAPI: Call Microsoft Graph
    GraphAPI-->>API: Return user data
    API-->>Client: Return response
```

### Endpoint Structure

```mermaid
graph LR
    API[API Root]
    
    API --> Token["Token"]
    API --> Graph["Graph"]
    
    Token --> GetAAD[POST: Get AAD Token]
    
    Graph --> GetUser[GET: getUserByIdentifier]
    Graph --> UpdateUser[PATCH: updateUserByIdentifier]
    Graph --> UpdateAttr[PATCH: updateUserAttributesByIdentifier]
    Graph --> DeleteUser[DELETE: deleteUserByIdentifier]
```


## Authentication

All Graph API endpoints require Azure AD Bearer token authentication. You must first generate a token using the Token endpoint, then include it in the Authorization header for all subsequent requests.

### Generating an Azure AD Token

To access the Graph endpoints, you need to generate an Azure AD access token using your Azure AD application credentials.

**Endpoint**: `POST /Token/Get AAD Token`

**Request Body**:
```json
{
  "client_id": "your-azure-ad-client-id",
  "client_secret": "your-azure-ad-client-secret",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in_minutes": 60
}
```

**Example Request**:
```bash
curl -X POST "https://your-api-url/Token/Get%20AAD%20Token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "12345678-1234-1234-1234-123456789abc",
    "client_secret": "your-secret-value",
    "expires_in_minutes": 60
  }'
```

**Example Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "https://graph.microsoft.com/.default",
  "expires_at": "2025-11-25T15:30:00Z",
  "issued_at": "2025-11-25T14:30:00Z",
  "expires_in_human": "59 minutes 59 seconds",
  "custom_expires_in_minutes": 60,
  "custom_expires_at": "2025-11-25T15:30:00Z",
  "token_refresh_guidance": "Token will expire in 60 minutes. Request a new token before expiration."
}
```

### Using the Token in Requests

Once you have the access token, include it in the Authorization header for all Graph API requests:

**Header Format**:
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Example Request with Token**:
```bash
curl -X GET "https://your-api-url/Graph/getUserByIdentifier?identifier=user@domain.com" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

### Token Expiration

- Azure AD tokens typically expire after 1 hour (3600 seconds)
- The `expires_in_minutes` parameter allows you to specify a custom expiration time (1-1440 minutes)
- Monitor the `expires_at` field in the token response
- Request a new token before the current one expires
- The API will return `401 Unauthorized` if the token is expired or invalid

### Authentication in Swagger UI

1. Navigate to the Swagger UI at `https://your-api-url/swagger`
2. Click the **Authorize** button (lock icon) at the top right
3. Generate a token using the `/Token/Get AAD Token` endpoint
4. Copy the `access_token` value from the response
5. In the authorization dialog, enter: `Bearer <your-access-token>`
6. Click **Authorize**
7. All subsequent requests will include the token automatically


## API Endpoints

### 1. Generate Azure AD Token

Generate an Azure AD access token for authenticating with the Graph API endpoints.

**Endpoint**: `POST /Token/Get AAD Token`

**Authentication**: None (this endpoint generates the token)

**Request Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| client_id | string | Yes | Azure AD application client ID |
| client_secret | string | Yes | Azure AD application client secret |
| scope | string | No | Token scope (default: `https://graph.microsoft.com/.default`) |
| expires_in_minutes | integer | No | Custom expiration time in minutes (1-1440, default: 60) |

**Request Body Example**:
```json
{
  "client_id": "12345678-1234-1234-1234-123456789abc",
  "client_secret": "your-secret-value",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in_minutes": 60
}
```

**Success Response (200 OK)**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "https://graph.microsoft.com/.default",
  "expires_at": "2025-11-25T15:30:00Z",
  "issued_at": "2025-11-25T14:30:00Z",
  "expires_in_human": "59 minutes 59 seconds",
  "custom_expires_in_minutes": 60,
  "custom_expires_at": "2025-11-25T15:30:00Z",
  "token_refresh_guidance": "Token will expire in 60 minutes. Request a new token before expiration."
}
```

**Error Responses**:

| Status Code | Description |
|-------------|-------------|
| 400 Bad Request | Invalid client credentials or parameters |
| 500 Internal Server Error | Azure AD configuration error or service unavailable |

**Error Response Example**:
```json
{
  "error": "invalid_client",
  "error_description": "AADSTS7000215: Invalid client secret provided."
}
```

---

### 2. Get User by Identifier

Retrieve user details from Azure AD using Object ID, User Principal Name (UPN), or Email address.

**Endpoint**: `GET /Graph/getUserByIdentifier`

**Authentication**: Required (Bearer token)

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| identifier | string | Yes | User Object ID, UPN, or Email address |

**Request Example**:
```bash
GET /Graph/getUserByIdentifier?identifier=user@domain.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Success Response (200 OK)**:
```json
{
  "id": "12345678-1234-1234-1234-123456789abc",
  "userPrincipalName": "user@domain.com",
  "displayName": "John Doe",
  "givenName": "John",
  "surname": "Doe",
  "mail": "user@domain.com",
  "jobTitle": "Software Engineer",
  "officeLocation": "Building 1",
  "mobilePhone": "+1234567890",
  "businessPhones": ["+1234567890"],
  "accountEnabled": true
}
```

**Error Responses**:

| Status Code | Description |
|-------------|-------------|
| 400 Bad Request | Invalid identifier format |
| 401 Unauthorized | Missing or invalid authentication token |
| 404 Not Found | User not found |
| 500 Internal Server Error | Graph API error |

**Error Response Example**:
```json
{
  "error": "user_not_found",
  "error_description": "User with identifier 'user@domain.com' was not found."
}
```

---

### 3. Update User by Identifier

Update user attributes in Azure AD using Object ID, User Principal Name (UPN), or Email address.

**Endpoint**: `PATCH /Graph/updateUserByIdentifier`

**Authentication**: Required (Bearer token)

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| identifier | string | Yes | User Object ID, UPN, or Email address |

**Request Body Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| displayName | string | No | User's display name |
| givenName | string | No | User's first name |
| surname | string | No | User's last name |
| jobTitle | string | No | User's job title |
| department | string | No | User's department |
| officeLocation | string | No | User's office location |
| mobilePhone | string | No | User's mobile phone number |
| businessPhones | array | No | User's business phone numbers |

**Request Example**:
```bash
PATCH /Graph/updateUserByIdentifier?identifier=user@domain.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
Content-Type: application/json

{
  "displayName": "Jane Smith",
  "jobTitle": "Senior Software Engineer",
  "department": "Engineering"
}
```

**Success Response (200 OK)**:
```json
{
  "message": "User updated successfully",
  "userId": "12345678-1234-1234-1234-123456789abc"
}
```

**Error Responses**:

| Status Code | Description |
|-------------|-------------|
| 400 Bad Request | Invalid identifier or empty update data |
| 401 Unauthorized | Missing or invalid authentication token |
| 404 Not Found | User not found |
| 500 Internal Server Error | Graph API error |

---

### 4. Update User Attributes by Identifier

Update specific user attributes (firstName, lastName, displayName) in Azure AD using Object ID, User Principal Name (UPN), or Email address.

**Endpoint**: `PATCH /Graph/updateUserAttributesByIdentifier`

**Authentication**: Required (Bearer token)

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| identifier | string | Yes | User Object ID, UPN, or Email address |

**Request Body Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| firstName | string | No | User's first name (maps to givenName) |
| lastName | string | No | User's last name (maps to surname) |
| DisplayName | string | No | User's display name |

**Request Example**:
```bash
PATCH /Graph/updateUserAttributesByIdentifier?identifier=user@domain.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
Content-Type: application/json

{
  "firstName": "Jane",
  "lastName": "Smith",
  "DisplayName": "Jane Smith"
}
```

**Success Response (200 OK)**:
```json
{
  "message": "User attributes updated successfully",
  "userId": "12345678-1234-1234-1234-123456789abc"
}
```

**Error Responses**:

| Status Code | Description |
|-------------|-------------|
| 400 Bad Request | Invalid identifier or empty update model |
| 401 Unauthorized | Missing or invalid authentication token |
| 404 Not Found | User not found |
| 500 Internal Server Error | Graph API error |

---

### 5. Delete User by Identifier

Delete a user from Azure AD using Object ID, User Principal Name (UPN), or Email address.

**Endpoint**: `DELETE /Graph/deleteUserByIdentifier`

**Authentication**: Required (Bearer token)

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| identifier | string | Yes | User Object ID, UPN, or Email address |

**Request Example**:
```bash
DELETE /Graph/deleteUserByIdentifier?identifier=user@domain.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Success Response (200 OK)**:
```json
{
  "message": "User deleted successfully",
  "userId": "12345678-1234-1234-1234-123456789abc"
}
```

**Error Responses**:

| Status Code | Description |
|-------------|-------------|
| 400 Bad Request | Invalid identifier format |
| 401 Unauthorized | Missing or invalid authentication token |
| 404 Not Found | User not found |
| 500 Internal Server Error | Graph API error |


## Configuration

### Required Configuration

The API requires Azure AD configuration to authenticate and access Microsoft Graph API. Configuration can be provided through `appsettings.json` or environment variables.

### appsettings.json Structure

Create or update your `appsettings.json` file with the following structure:

```json
{
  "AzureAd": {
    "TenantId": "your-tenant-id",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret",
    "Instance": "https://login.microsoftonline.com/",
    "Domain": "yourdomain.onmicrosoft.com"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.Graph": "Information"
    }
  },
  "AllowedHosts": "*"
}
```

### Configuration Values Explained

| Configuration Key | Description | Example | Required |
|-------------------|-------------|---------|----------|
| `AzureAd:TenantId` | Your Azure AD tenant ID (GUID) | `12345678-1234-1234-1234-123456789abc` | Yes |
| `AzureAd:ClientId` | Azure AD application (client) ID | `87654321-4321-4321-4321-cba987654321` | Yes |
| `AzureAd:ClientSecret` | Azure AD application client secret | `your-secret-value` | Yes |
| `AzureAd:Instance` | Azure AD instance URL | `https://login.microsoftonline.com/` | No (has default) |
| `AzureAd:Domain` | Your Azure AD domain | `yourdomain.onmicrosoft.com` | No |

### Environment Variables (Alternative)

You can also configure the API using environment variables, which is recommended for production deployments:

```bash
# Azure AD Configuration
export AzureAd__TenantId="your-tenant-id"
export AzureAd__ClientId="your-client-id"
export AzureAd__ClientSecret="your-client-secret"
export AzureAd__Instance="https://login.microsoftonline.com/"
export AzureAd__Domain="yourdomain.onmicrosoft.com"

# Logging Configuration
export Logging__LogLevel__Default="Information"
export Logging__LogLevel__Microsoft__AspNetCore="Warning"
```

**Note**: Environment variables use double underscores (`__`) to represent nested configuration levels.

### Azure AD App Registration Setup

To obtain the required configuration values, you need to register an application in Azure AD:

1. **Navigate to Azure Portal**:
   - Go to [Azure Portal](https://portal.azure.com)
   - Navigate to **Azure Active Directory** > **App registrations**

2. **Create New Registration**:
   - Click **New registration**
   - Enter a name for your application (e.g., "OIDC External ID API")
   - Select supported account types (typically "Single tenant")
   - Click **Register**

3. **Copy Application IDs**:
   - From the **Overview** page, copy:
     - **Application (client) ID** → Use as `AzureAd:ClientId`
     - **Directory (tenant) ID** → Use as `AzureAd:TenantId`

4. **Create Client Secret**:
   - Go to **Certificates & secrets** > **Client secrets**
   - Click **New client secret**
   - Add a description and select expiration period
   - Click **Add**
   - **Copy the secret value immediately** → Use as `AzureAd:ClientSecret`
   - ⚠️ You won't be able to see the secret value again

5. **Configure API Permissions**:
   - Go to **API permissions**
   - Click **Add a permission** > **Microsoft Graph** > **Application permissions**
   - Add the following permissions:
     - `User.Read.All` - Read all users' full profiles
     - `User.ReadWrite.All` - Read and write all users' full profiles
     - `Directory.ReadWrite.All` - Read and write directory data (for delete operations)
   - Click **Add permissions**
   - Click **Grant admin consent for [Your Tenant]**

### Required Microsoft Graph Permissions

| Permission | Type | Description | Used By |
|------------|------|-------------|---------|
| `User.Read.All` | Application | Read all users' full profiles | getUserByIdentifier |
| `User.ReadWrite.All` | Application | Read and write all users' full profiles | updateUserByIdentifier, updateUserAttributesByIdentifier |
| `Directory.ReadWrite.All` | Application | Read and write directory data | deleteUserByIdentifier |

### Security Best Practices

1. **Never commit secrets to source control**
   - Add `appsettings.json` to `.gitignore` if it contains secrets
   - Use `appsettings.Development.json` for local development
   - Use environment variables or Azure Key Vault for production

2. **Rotate client secrets regularly**
   - Set expiration dates on client secrets
   - Update secrets before they expire
   - Use Azure Key Vault for automated rotation

3. **Use least privilege principle**
   - Only grant the minimum required permissions
   - Use application permissions (not delegated) for service-to-service calls

4. **Enable HTTPS only**
   - Always use HTTPS in production
   - Configure HSTS (HTTP Strict Transport Security)


## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed and configured:

- **.NET 8.0 SDK** or later
  - Download from [dotnet.microsoft.com](https://dotnet.microsoft.com/download)
  - Verify installation: `dotnet --version`

- **Azure AD Tenant** with administrative access
  - Required to create app registrations
  - Required to grant API permissions

- **Development Tools** (choose one):
  - Visual Studio 2022 or later
  - Visual Studio Code with C# extension
  - JetBrains Rider

- **API Testing Tool** (optional but recommended):
  - Postman, Insomnia, or curl
  - Or use the built-in Swagger UI

### Installation Steps

#### 1. Clone or Download the Repository

```bash
git clone <repository-url>
cd OIDC_ExternalID_API
```

#### 2. Restore NuGet Packages

```bash
dotnet restore
```

#### 3. Configure Azure AD Settings

Create or update `appsettings.Development.json` in the project root:

```json
{
  "AzureAd": {
    "TenantId": "your-tenant-id",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret"
  }
}
```

Replace the placeholder values with your Azure AD app registration details (see [Configuration](#configuration) section for setup instructions).

#### 4. Build the Project

```bash
dotnet build
```

Verify that the build completes without errors.

#### 5. Run the API

```bash
dotnet run
```

The API will start and display the URLs it's listening on:

```
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://localhost:7001
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://localhost:5000
```

### Making Your First API Call

#### Step 1: Generate an Azure AD Token

Use curl, Postman, or Swagger UI to generate a token:

**Using curl**:
```bash
curl -X POST "https://localhost:7001/Token/Get%20AAD%20Token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "expires_in_minutes": 60
  }'
```

**Using PowerShell**:
```powershell
$body = @{
    client_id = "your-client-id"
    client_secret = "your-client-secret"
    expires_in_minutes = 60
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:7001/Token/Get%20AAD%20Token" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "expires_in_human": "59 minutes 59 seconds"
}
```

Copy the `access_token` value for the next step.

#### Step 2: Call a Graph Endpoint

Use the token to retrieve a user:

**Using curl**:
```bash
curl -X GET "https://localhost:7001/Graph/getUserByIdentifier?identifier=user@domain.com" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

**Using PowerShell**:
```powershell
$token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
$headers = @{
    Authorization = "Bearer $token"
}

Invoke-RestMethod -Uri "https://localhost:7001/Graph/getUserByIdentifier?identifier=user@domain.com" `
  -Method Get `
  -Headers $headers
```

**Response**:
```json
{
  "id": "12345678-1234-1234-1234-123456789abc",
  "userPrincipalName": "user@domain.com",
  "displayName": "John Doe",
  "givenName": "John",
  "surname": "Doe",
  "mail": "user@domain.com"
}
```

### Using Swagger UI

The easiest way to test the API is through the built-in Swagger UI:

1. **Open Swagger UI**:
   - Navigate to `https://localhost:7001/swagger` in your browser
   - You'll see all available endpoints

2. **Generate a Token**:
   - Expand the `POST /Token/Get AAD Token` endpoint
   - Click **Try it out**
   - Fill in your `client_id` and `client_secret`
   - Click **Execute**
   - Copy the `access_token` from the response

3. **Authorize Swagger**:
   - Click the **Authorize** button (lock icon) at the top right
   - Enter: `Bearer <your-access-token>`
   - Click **Authorize**, then **Close**

4. **Test Endpoints**:
   - All Graph endpoints are now authorized
   - Expand any endpoint (e.g., `GET /Graph/getUserByIdentifier`)
   - Click **Try it out**
   - Enter the required parameters
   - Click **Execute**
   - View the response

### Quick Start Checklist

- [ ] .NET 8.0 SDK installed
- [ ] Azure AD app registration created
- [ ] API permissions granted and admin consent provided
- [ ] `appsettings.Development.json` configured with Azure AD credentials
- [ ] Project builds successfully (`dotnet build`)
- [ ] API runs successfully (`dotnet run`)
- [ ] Token generated successfully via `/Token/Get AAD Token`
- [ ] Graph endpoint called successfully with token
- [ ] Swagger UI accessible and functional

### Next Steps

- Review the [API Endpoints](#api-endpoints) section for detailed endpoint documentation
- Check the [Troubleshooting](#troubleshooting) section if you encounter issues
- Configure production settings using environment variables
- Set up logging and monitoring for production deployments


## Troubleshooting

This section covers common issues and their solutions. For detailed information about the API cleanup process, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### Common Authentication Errors

#### Error: "401 Unauthorized"

**Symptoms**:
- Graph endpoints return 401 status code
- Error message: "Unauthorized" or "No authenticationScheme was specified"

**Possible Causes & Solutions**:

1. **Missing Authorization Header**
   - Ensure you include the `Authorization` header in your request
   - Format: `Authorization: Bearer <your-access-token>`

2. **Expired Token**
   - Azure AD tokens typically expire after 1 hour
   - Generate a new token using `/Token/Get AAD Token`
   - Check the `expires_at` field in the token response

3. **Invalid Token Format**
   - Ensure the token is prefixed with "Bearer "
   - Example: `Bearer eyJ0eXAiOiJKV1Qi...`
   - Don't include quotes around the token

4. **Token from Wrong Tenant**
   - Verify the token was generated for the correct Azure AD tenant
   - Check the `tid` claim in the token (decode at [jwt.ms](https://jwt.ms))

#### Error: "AADSTS7000215: Invalid client secret provided"

**Symptoms**:
- Token generation fails with this error
- `/Token/Get AAD Token` returns 400 status code

**Solutions**:
1. Verify the `client_secret` in your request matches the Azure AD app registration
2. Check if the client secret has expired in Azure Portal
3. Generate a new client secret if needed
4. Ensure there are no extra spaces or characters in the secret

#### Error: "AADSTS700016: Application not found"

**Symptoms**:
- Token generation fails
- Error mentions application with identifier not found

**Solutions**:
1. Verify the `client_id` is correct
2. Ensure the app registration exists in the correct Azure AD tenant
3. Check that you're using the Application (client) ID, not the Object ID

### Common Graph API Errors

#### Error: "404 Not Found - User not found"

**Symptoms**:
- Graph endpoints return 404 status code
- Error message indicates user doesn't exist

**Solutions**:
1. Verify the user identifier (Object ID, UPN, or Email) is correct
2. Check if the user exists in Azure AD Portal
3. Ensure the user is in the same tenant as your app registration
4. Try using the Object ID instead of email or UPN

#### Error: "403 Forbidden - Insufficient privileges"

**Symptoms**:
- Graph endpoints return 403 status code
- Error message about insufficient privileges

**Solutions**:
1. Verify API permissions in Azure AD app registration:
   - `User.Read.All` for read operations
   - `User.ReadWrite.All` for update operations
   - `Directory.ReadWrite.All` for delete operations
2. Ensure admin consent has been granted for the permissions
3. Wait a few minutes after granting permissions for changes to propagate

#### Error: "400 Bad Request - Invalid identifier"

**Symptoms**:
- Graph endpoints return 400 status code
- Error about invalid identifier format

**Solutions**:
1. Ensure the identifier is not empty or null
2. Verify the identifier format:
   - Object ID: GUID format (e.g., `12345678-1234-1234-1234-123456789abc`)
   - UPN: email format (e.g., `user@domain.com`)
   - Email: valid email address
3. URL-encode special characters in the identifier

#### Error: "Request_ResourceNotFound"

**Symptoms**:
- Microsoft Graph returns this error code
- User operations fail

**Solutions**:
1. The user may have been deleted
2. The identifier may be incorrect
3. Try searching for the user in Azure AD Portal to verify existence

### Configuration Issues

#### Error: "Configuration section 'AzureAd' not found"

**Symptoms**:
- API fails to start
- Error about missing configuration

**Solutions**:
1. Ensure `appsettings.json` or `appsettings.Development.json` exists
2. Verify the `AzureAd` section is present in the configuration file
3. Check that all required fields are present:
   - `TenantId`
   - `ClientId`
   - `ClientSecret`

#### Error: "Unable to resolve service for type 'Microsoft.Graph.GraphServiceClient'"

**Symptoms**:
- API fails to start
- Dependency injection error

**Solutions**:
1. Ensure all NuGet packages are restored: `dotnet restore`
2. Verify `Microsoft.Graph` package is installed
3. Check that `Program.cs` registers the GraphServiceClient

### SSL/Certificate Issues

#### Error: "The SSL connection could not be established"

**Symptoms**:
- Cannot connect to the API via HTTPS
- Certificate validation errors

**Solutions**:
1. **For Development**:
   - Trust the development certificate: `dotnet dev-certs https --trust`
   - Restart your browser/API client

2. **For Production**:
   - Ensure a valid SSL certificate is installed
   - Configure the certificate in your hosting environment

### Swagger UI Issues

#### Issue: "Authorize button doesn't work"

**Solutions**:
1. Generate a token first using `/Token/Get AAD Token`
2. Copy the entire `access_token` value (not the whole response)
3. In the Authorize dialog, enter: `Bearer <token>`
4. Ensure there's a space between "Bearer" and the token

#### Issue: "Endpoints return 401 even after authorizing"

**Solutions**:
1. Check if the token has expired
2. Generate a new token and re-authorize
3. Clear browser cache and cookies
4. Try in an incognito/private browser window

### Performance Issues

#### Issue: "Slow response times from Graph endpoints"

**Solutions**:
1. Check your internet connection to Azure services
2. Verify Azure AD service health in Azure Portal
3. Consider implementing caching for frequently accessed users
4. Check if you're hitting Microsoft Graph throttling limits

### Logging and Diagnostics

#### Enable Detailed Logging

To troubleshoot issues, enable detailed logging in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Debug",
      "Microsoft.Graph": "Debug"
    }
  }
}
```

#### View Application Logs

**Console Output**:
- Logs are written to the console when running with `dotnet run`
- Look for error messages and stack traces

**Log Files** (if configured):
- Check your logging provider configuration
- Review log files for detailed error information

### Getting Additional Help

If you continue to experience issues:

1. **Check the detailed troubleshooting guide**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. **Review Azure AD app registration**:
   - Verify all settings in Azure Portal
   - Check API permissions and admin consent
3. **Test with Microsoft Graph Explorer**:
   - Visit [Graph Explorer](https://developer.microsoft.com/graph/graph-explorer)
   - Test the same operations to isolate API vs. Graph issues
4. **Check Microsoft Graph API status**:
   - Visit [Azure Status](https://status.azure.com)
   - Check for any service outages
5. **Review application logs**:
   - Enable detailed logging
   - Look for specific error messages and stack traces

### Common Error Codes Reference

| Error Code | Description | Common Solution |
|------------|-------------|-----------------|
| 400 | Bad Request | Check request parameters and body format |
| 401 | Unauthorized | Verify token is valid and not expired |
| 403 | Forbidden | Check API permissions and admin consent |
| 404 | Not Found | Verify user exists and identifier is correct |
| 429 | Too Many Requests | Implement retry logic with exponential backoff |
| 500 | Internal Server Error | Check application logs for details |
| 503 | Service Unavailable | Azure AD or Graph API may be experiencing issues |

