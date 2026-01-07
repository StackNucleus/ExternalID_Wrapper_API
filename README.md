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

### Key Features
- **Azure AD Integration**: Seamless integration with Azure Active Directory for user management
- **Microsoft Graph API**: Direct integration with Microsoft Graph API for user operations
- **Token-Based Authentication**: Secure authentication using Azure AD tokens
- **Delegated User Enforcement**: Ensures that API endpoints only work for the delegated user
- **Application Permissions**: Uses application permissions (client credentials) for Microsoft Graph interactions

### Available Endpoints
- **GraphController**: Uses application permissions to interact with Microsoft Graph
- **DGraphController**: Uses delegated permissions to interact with Microsoft Graph (hidden from Swagger)
- **TokenController**: Generates Azure AD tokens for authentication (hidden from Swagger)

## 🏗️ Architecture

### API Flow Diagram
```
┌───────────────────────────────────────────────────────────────────────────────┐
│                                                                               │
│  ┌─────────────┐    ┌─────────────┐    ┌───────────────────────────────────┐  │
│  │             │    │             │    │                               │       │  │
│  │   Client    │    │   Azure AD  │    │   OIDC External ID API        │       │  │
│  │             │    │             │    │                               │       │  │
│  └─────────────┘    └─────────────┘    └───────────────────────────────────┘  │
│          │                 │                         │                         │
│          │ 1. Get Token    │                         │                         │
│          └────────────────>│                         │                         │
│                          │                         │                         │
│                          │ 2. Validate Token       │                         │
│                          └────────────────────────>│                         │
│                                          │                         │
│                                          │ 3. Process Request       │
│                                          └────────────────────────>│
│                                                  │                         │
│                                                  │ 4. Return Response      │
│                                                  <────────────────────────│
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Authentication Flow
1. **Client Requests Token**: The client requests an Azure AD token from the TokenController
2. **Azure AD Validates**: Azure AD validates the client credentials and returns a token
3. **Client Uses Token**: The client uses the token to authenticate with the OIDC External ID API
4. **API Validates Token**: The API validates the token and extracts the delegated user's identity
5. **API Processes Request**: The API processes the request and returns the response

### Technology Stack
- **ASP.NET Core**: Web framework for building the API
- **Microsoft Graph SDK**: SDK for interacting with Microsoft Graph
- **Azure Identity**: Library for authenticating with Azure AD
- **Swashbuckle**: Library for generating Swagger documentation
- **Serilog**: Library for logging

## 🔐 Authentication

### Azure AD Token Generation
To use the API, you need to generate an Azure AD token. The token is used to authenticate with the API and authorize access to the API endpoints.

#### Required Parameters
- `client_id`: The Azure AD application's client ID
- `client_secret`: The Azure AD application's client secret
- `scope`: The scope of the token (e.g., `https://graph.microsoft.com/.default`)
- `expires_in_minutes`: The expiration time of the token in minutes

#### Example Request
```http
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
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "https://graph.microsoft.com/.default",
  "expires_at": "2023-01-01T00:00:00.000Z",
  "issued_at": "2023-01-01T00:00:00.000Z",
  "expires_in_human": "1 hour",
  "custom_expires_in_minutes": 60,
  "custom_expires_at": "2023-01-01T00:00:00.000Z",
  "token_refresh_guidance": "Token will expire in 1 hour. Please refresh the token before it expires."
}
```

### Using the Token in Requests
To use the token in requests, include it in the `Authorization` header:

```http
GET /Graph/getUserByIdentifier/v1.0?identifier=user@example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token Expiration
The token will expire after the specified expiration time. To continue using the API, you need to generate a new token.

## 📡 API Endpoints

### 1. Generate Azure AD Token
Generate an Azure AD token for authenticating with the API.

**Endpoint**: `POST /Token/getAAD-Token/v1.0`

**Request**:
```json
{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in_minutes": 60
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "https://graph.microsoft.com/.default",
  "expires_at": "2023-01-01T00:00:00.000Z",
  "issued_at": "2023-01-01T00:00:00.000Z",
  "expires_in_human": "1 hour",
  "custom_expires_in_minutes": 60,
  "custom_expires_at": "2023-01-01T00:00:00.000Z",
  "token_refresh_guidance": "Token will expire in 1 hour. Please refresh the token before it expires."
}
```

### 2. Get User by Identifier
Get a user by their identifier (Object ID, UPN, or Email).

**Endpoint**: `GET /Graph/getUserByIdentifier/v1.0?identifier={identifier}`

**Response**:
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "displayName": "John Doe",
  "mail": "john.doe@example.com",
  "userPrincipalName": "john.doe@example.com",
  "givenName": "John",
  "surname": "Doe",
  "jobTitle": "Software Engineer",
  "officeLocation": "Seattle",
  "mobilePhone": "+1 206-555-0123",
  "businessPhones": ["+1 206-555-0123"],
  "accountEnabled": true
}
```

### 3. Update User by Identifier
Update a user by their identifier (Object ID, UPN, or Email).

**Endpoint**: `PATCH /Graph/updateUserByIdentifier/v1.0?identifier={identifier}`

**Request**:
```json
{
  "givenName": "John",
  "surname": "Doe",
  "displayName": "John Doe"
}
```

**Response**:
```json
{
  "message": "User updated successfully.",
  "userId": "123e4567-e89b-12d3-a456-426614174000"
}
```

### 4. Update User Attributes by Identifier
Update specific user attributes by their identifier (Object ID, UPN, or Email).

**Endpoint**: `PATCH /Graph/updateUserAttributesByIdentifier/v1.0?identifier={identifier}`

**Request**:
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "DisplayName": "John Doe"
}
```

**Response**:
```json
{
  "message": "User attributes updated successfully.",
  "userId": "123e4567-e89b-12d3-a456-426614174000"
}
```

### 5. Delete User by Identifier
Delete a user by their identifier (Object ID, UPN, or Email).

**Endpoint**: `DELETE /Graph/deleteUserByIdentifier/v1.0?identifier={identifier}`

**Response**:
```json
{
  "message": "User deleted successfully.",
  "userId": "123e4567-e89b-12d3-a456-426614174000"
}
```

## ⚙️ Configuration

### Required Configuration
The API requires the following configuration in the `appsettings.json` file:

#### AzureAd
```json
{
  "AzureAd": {
    "TenantId": "your-tenant-id",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret"
  }
}
```

#### Logging
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

#### AllowedHosts
```json
{
  "AllowedHosts": "*"
}
```

### Configuration Values Explained
- **TenantId**: The Azure AD tenant ID
- **ClientId**: The Azure AD application's client ID
- **ClientSecret**: The Azure AD application's client secret
- **LogLevel**: The logging level for the application
- **AllowedHosts**: The allowed hosts for the application

### Azure AD App Registration Setup
To use the API, you need to register an application in Azure AD and configure the following settings:

1. **Register an Application**:
   - Go to the Azure AD portal and register a new application
   - Note the application's client ID and tenant ID

2. **Create a Client Secret**:
   - Go to the application's certificates and secrets page
   - Create a new client secret and note the secret value

3. **Configure API Permissions**:
   - Go to the application's API permissions page
   - Add the following permissions:
     - `User.Read.All` (Application)
     - `User.ReadWrite.All` (Application)
   - Grant admin consent for the permissions

### Required Microsoft Graph Permissions
The API requires the following Microsoft Graph permissions:

- **User.Read.All**: Read all users' full profiles
- **User.ReadWrite.All**: Read and write all users' full profiles

## 🚀 Getting Started

### Prerequisites
- .NET 8.0 SDK
- Azure AD tenant
- Azure AD application registration

### Installation Steps

#### 1. Clone the Repository
```bash
git clone https://github.com/your-repository/OIDC-ExternalID-API.git
cd OIDC-ExternalID-API
```

#### 2. Restore NuGet Packages
```bash
dotnet restore
```

#### 3. Configure Azure AD Settings
Update the `appsettings.json` file with your Azure AD settings:

```json
{
  "AzureAd": {
    "TenantId": "your-tenant-id",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret"
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
curl -X GET "https://localhost:7110/Graph/getUserByIdentifier/v1.0?identifier=user@example.com" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 📚 Usage Examples

### cURL Examples

#### Generate Token
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

#### Get User
```bash
curl -X GET "https://localhost:7110/Graph/getUserByIdentifier/v1.0?identifier=user@example.com" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Update User
```bash
curl -X PATCH "https://localhost:7110/Graph/updateUserByIdentifier/v1.0?identifier=user@example.com" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "givenName": "John",
    "surname": "Doe",
    "displayName": "John Doe"
  }'
```

#### Delete User
```bash
curl -X DELETE "https://localhost:7110/Graph/deleteUserByIdentifier/v1.0?identifier=user@example.com" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JavaScript Example

```javascript
class OIDCAPI {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  async generateToken(clientId, clientSecret, scope, expiresInMinutes) {
    const response = await fetch(`${this.baseUrl}/Token/getAAD-Token/v1.0`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        scope: scope,
        expires_in_minutes: expiresInMinutes
      })
    });

    const tokenData = await response.json();
    return tokenData;
  }

  async getUser(identifier, token) {
    const response = await fetch(`${this.baseUrl}/Graph/getUserByIdentifier/v1.0?identifier=${identifier}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const user = await response.json();
    return user;
  }

  async updateUser(identifier, updates, token) {
    const response = await fetch(`${this.baseUrl}/Graph/updateUserByIdentifier/v1.0?identifier=${identifier}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(updates)
    });

    const result = await response.json();
    return result;
  }
}

// Usage
const api = new OIDCAPI('https://localhost:7110');
const token = await api.generateToken('your-client-id', 'your-client-secret', 'https://graph.microsoft.com/.default', 60);
const user = await api.getUser('user@example.com', token.access_token);
```

## 🎨 Swagger UI

### Features
- Interactive API documentation
- Try out API endpoints directly from the browser
- View request and response examples
- Generate client code in various languages

### Accessing Swagger UI
The Swagger UI is available at `https://localhost:7110/swagger` when the API is running.

### Using Swagger UI for Authentication
1. Generate an Azure AD token using the `/Token/getAAD-Token/v1.0` endpoint
2. Click the "Authorize" button in the Swagger UI
3. Enter the token in the format `Bearer <token>`
4. Try out the API endpoints

## 🔧 Troubleshooting

### Common Issues

#### 401 Unauthorized
- **Cause**: Invalid or missing token
- **Solution**: Generate a new token and ensure it is included in the `Authorization` header

#### 404 Not Found
- **Cause**: The requested resource does not exist
- **Solution**: Verify the identifier and ensure the resource exists

#### 403 Forbidden
- **Cause**: Insufficient permissions to access the resource
- **Solution**: Ensure the token has the necessary permissions and the delegated user has access to the resource

#### Configuration Errors
- **Cause**: Missing or invalid configuration values
- **Solution**: Verify the `appsettings.json` file and ensure all required values are present and correct

### Error Response Format
```json
{
  "error": {
    "code": "ErrorCode",
    "message": "Error message",
    "details": "Error details",
    "timestamp": "2023-01-01T00:00:00.000Z",
    "trace_id": "trace-id",
    "correlation_id": "correlation-id"
  }
}
```

### Logging and Diagnostics
The API uses Serilog for logging. You can configure the logging level in the `appsettings.json` file:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.Graph": "Information"
    }
  }
}
```

### Getting Help
If you encounter any issues, please check the following:
- Ensure the `appsettings.json` file is correctly configured
- Verify the Azure AD application has the necessary permissions
- Check the logs for detailed error information

## 🔒 Security

### Best Practices
- **Token Security**: Always use HTTPS to transmit tokens
- **Token Expiration**: Use short-lived tokens and refresh them as needed
- **Token Storage**: Store tokens securely and avoid logging them
- **Token Validation**: Validate tokens on every request

### Azure AD Security
- **App Registration**: Register your application in Azure AD and configure the necessary permissions
- **Client Secrets**: Use client secrets to authenticate with Azure AD
- **Admin Consent**: Grant admin consent for the necessary permissions

### Data Protection
- **HTTPS**: Always use HTTPS to transmit data
- **Encryption**: Encrypt sensitive data at rest and in transit
- **Access Control**: Restrict access to sensitive data

### Compliance
- **GDPR**: Ensure compliance with GDPR and other data protection regulations
- **Audit Logs**: Maintain audit logs for all API operations

## 🤝 Contributing

### Development Setup
1. Clone the repository
2. Restore NuGet packages
3. Configure Azure AD settings
4. Build the project
5. Run the API

### Code Guidelines
- Follow the existing code style and conventions
- Write clear and concise code
- Include comments and documentation
- Write unit tests for new features

### Pull Request Process
1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Commit your changes
4. Push your changes to your fork
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 📞 Support

For support, please contact the project maintainers or open an issue on the project's GitHub repository.