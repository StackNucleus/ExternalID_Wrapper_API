# Troubleshooting Guide

## API Cleanup Summary

This document provides a comprehensive overview of the cleanup performed on the OIDC External ID API project. The cleanup focused on retaining only essential endpoints while removing unused code, controllers, and dependencies to streamline the codebase.

### Cleanup Objectives
- Retain only 5 essential API endpoints (4 Graph + 1 Token)
- Remove all unused controllers and endpoints
- Clean up unused models and helper methods
- Simplify authentication configuration
- Update documentation to reflect current state

---

## Removed Controllers

### 1. CustomGraphController
**File:** `Controllers/CustomGraphController.cs`

**Description:** Alternative Graph API controller that duplicated functionality already available in GraphController. All custom graph operations were redundant with the main GraphController implementation.

**Reason for Removal:** Functionality fully covered by GraphController with better Microsoft Graph SDK integration.

### 2. WeatherForecastController
**File:** `Controllers/WeatherForecastController.cs`

**Description:** Demo/template controller included with ASP.NET Core project template. Provided sample weather forecast data for testing purposes.

**Reason for Removal:** Not needed for production API; was only a demonstration endpoint.

---

## Removed Endpoints

### GraphController Endpoints Removed

| HTTP Method | Route | Description |
|-------------|-------|-------------|
| GET | `/Graph/readme` | Returns API documentation/readme |
| GET | `/Graph/getCurrentUser` | Gets current authenticated user details |
| POST | `/Graph/inviteUser` | Invites a new user to the tenant |
| GET | `/Graph/getUser` | Gets user by ID (old version) |
| GET | `/Graph/getUserByUpn` | Gets user by User Principal Name |
| GET | `/Graph/getUserByEmail` | Gets user by email address |
| GET | `/Graph/getUserDetails` | Gets detailed user information |
| PATCH | `/Graph/updateUserAttributesByEmail` | Updates user attributes by email |
| DELETE | `/Graph/deleteUserByEmail` | Deletes user by email address |
| POST | `/Graph/changePassword` | Changes user password |
| POST | `/Graph/resetPasswordById` | Resets password by user ID |
| POST | `/Graph/resetPasswordByEmail` | Resets password by email |
| POST | `/Graph/requestPasswordReset` | Initiates password reset flow |
| POST | `/Graph/completePasswordReset` | Completes password reset with code |
| POST | `/Graph/authenticate` | Custom authentication endpoint |
| POST | `/Graph/authenticateWithMfa` | Authentication with MFA |
| POST | `/Graph/verifyMfaCode` | Verifies MFA code |

### TokenController Endpoints Removed

| HTTP Method | Route | Description |
|-------------|-------|-------------|
| POST | `/Token/GetToken` | Generates custom JWT tokens |
| POST | `/Token/GetAzureAdClientCredentialsToken` | Alternative Azure AD token endpoint |
| POST | `/Token/ValidateToken` | Validates JWT tokens |

### CustomGraphController Endpoints Removed

All endpoints from this controller were removed as the entire controller was deleted.

### WeatherForecastController Endpoints Removed

| HTTP Method | Route | Description |
|-------------|-------|-------------|
| GET | `/WeatherForecast` | Returns sample weather data |

---

## Retained Endpoints

### GraphController Endpoints (4 endpoints)

| HTTP Method | Route | Description |
|-------------|-------|-------------|
| GET | `/Graph/getUserByIdentifier` | Retrieves user by ID, UPN, or Email |
| PATCH | `/Graph/updateUserByIdentifier` | Updates user by ID, UPN, or Email |
| PATCH | `/Graph/updateUserAttributesByIdentifier` | Updates specific user attributes |
| DELETE | `/Graph/deleteUserByIdentifier` | Deletes user by ID, UPN, or Email |

### TokenController Endpoints (1 endpoint)

| HTTP Method | Route | Description |
|-------------|-------|-------------|
| POST | `/Token/Get AAD Token` | Generates Azure AD access token |

---

## Removed Model Files

### Password-Related Models
- `Models/ChangePasswordModel.cs` - Model for password change requests
- `Models/RequestPasswordResetModel.cs` - Model for password reset initiation
- `Models/ResetPasswordModel.cs` - Model for password reset completion
- `Models/SelfServicePasswordResetModel.cs` - Model for SSPR functionality

### Demo Models
- `WeatherForecast.cs` - Model for weather forecast demo data

### Token Models (Removed from TokenController.cs)
- `OAuth2TokenRequest` - Custom OAuth2 token request model
- `OAuth2TokenResponse` - Custom OAuth2 token response model
- `TokenValidationRequest` - Token validation request model
- `TokenValidationResponse` - Token validation response model
- `AzureAdTokenRequest` - Alternative Azure AD token request model

---

## Retained Model Files

### User Management Models
- `Models/UserUpdateModel.cs` - Used for updating user attributes
- `Models/UserDetailResponse.cs` - Used for returning user details

### Token Models (Retained in TokenController.cs)
- `AzureAdClientCredentialsRequest` - Azure AD token request model
- `AzureAdTokenResponse` - Azure AD token response model

---

## Removed Helper Methods

### GraphController Helper Methods Removed
- `GenerateVerificationCode()` - Generated random verification codes
- `StoreVerificationCode()` - Stored verification codes in memory
- `ValidateVerificationCode()` - Validated verification codes
- `ClearVerificationCode()` - Cleared verification codes from memory
- `SendVerificationEmail()` - Sent verification emails
- `_verificationCodes` static field - In-memory verification code storage

### TokenController Helper Methods Removed
- `HandleClientCredentialsFlow()` - Handled OAuth2 client credentials flow
- `HandlePasswordFlow()` - Handled OAuth2 password flow
- `HandleRefreshTokenFlow()` - Handled OAuth2 refresh token flow
- `GenerateAccessToken()` - Generated custom JWT tokens
- `ValidateClientCredentials()` - Validated client credentials
- `ValidateUserCredentials()` - Validated user credentials
- `ValidateRefreshToken()` - Validated refresh tokens
- `GetJwtSecret()` - Retrieved JWT secret from configuration

---

## Removed Dependencies

**No NuGet packages were removed.** All current dependencies are required by the retained endpoints:

- **Azure.Identity** (v1.14.0) - Required for Azure AD authentication
- **Microsoft.AspNetCore.Authentication.JwtBearer** (v8.0.18) - Required for JWT token validation
- **Microsoft.Graph** (v5.82.0) - Required for Microsoft Graph API integration
- **Newtonsoft.Json** (v13.0.3) - Used for JSON serialization
- **Swashbuckle.AspNetCore** (v7.0.0) - Required for Swagger/OpenAPI documentation
- **Swashbuckle.AspNetCore.Annotations** (v7.0.0) - Used for endpoint documentation

---

## Configuration Changes

### Program.cs Changes

#### Authentication Configuration
- **Simplified:** OnAuthenticationFailed event handler to focus on Azure AD tokens only
- **Removed:** Custom JWT secret generation logic (if it was not needed)
- **Retained:** JWT Bearer authentication for Azure AD token validation
- **Retained:** Azure AD tenant configuration

#### Middleware Configuration
- **Reviewed:** Session middleware (removed if not needed by retained endpoints)
- **Retained:** CORS configuration
- **Retained:** Static files middleware for Swagger UI
- **Retained:** Authorization middleware

#### Swagger Configuration
- **Updated:** API description to reflect only retained endpoints
- **Removed:** References to removed controllers in documentation
- **Updated:** Authentication description to focus on Azure AD tokens
- **Cleaned:** Commented-out OAuth2 configuration code

#### Using Statements
- **Cleaned:** Removed unused using directives across all files
- **Organized:** Remaining using statements alphabetically

---

## Common Issues and Solutions

### Issue: Endpoint Returns 404 Not Found

**Cause:** The endpoint you're trying to access was removed during cleanup.

**Solution:** Verify you're using one of the 5 retained endpoints listed above. Check the updated README.md for current endpoint documentation.

### Issue: Authentication Fails with 401 Unauthorized

**Cause:** Missing or invalid Azure AD token.

**Solution:** 
1. Generate a new token using `POST /Token/Get AAD Token`
2. Include the token in the Authorization header: `Bearer <your-token>`
3. Verify the token hasn't expired

### Issue: Custom JWT Tokens No Longer Work

**Cause:** Custom JWT token generation endpoints were removed.

**Solution:** Use the Azure AD token endpoint (`POST /Token/Get AAD Token`) to generate tokens. The API now only accepts Azure AD tokens.

### Issue: Password Reset Endpoints Missing

**Cause:** All password-related endpoints were removed during cleanup.

**Solution:** Password management functionality is no longer available in this API. Use Azure AD portal or Microsoft Graph API directly for password operations.

### Issue: Cannot Find User by Email

**Cause:** Specific email-based endpoints were removed.

**Solution:** Use the unified `getUserByIdentifier` endpoint which accepts email, UPN, or Object ID as the identifier parameter.

### Issue: Build Errors After Cleanup

**Cause:** Missing references to removed files or methods.

**Solution:** 
1. Clean and rebuild the solution: `dotnet clean && dotnet build`
2. Verify all using statements are correct
3. Check that no code references removed controllers or methods

### Issue: Swagger UI Shows Removed Endpoints

**Cause:** Browser cache or outdated Swagger configuration.

**Solution:**
1. Clear browser cache
2. Restart the application
3. Verify Program.cs Swagger configuration is updated

---

## Migration Guide

### If You Were Using Removed Endpoints

#### Email-Based User Operations
**Old:** `GET /Graph/getUserByEmail?email=user@domain.com`  
**New:** `GET /Graph/getUserByIdentifier?identifier=user@domain.com`

**Old:** `DELETE /Graph/deleteUserByEmail?email=user@domain.com`  
**New:** `DELETE /Graph/deleteUserByIdentifier?identifier=user@domain.com`

#### Custom JWT Tokens
**Old:** `POST /Token/GetToken` with custom credentials  
**New:** `POST /Token/Get AAD Token` with Azure AD client credentials

#### Password Operations
**Old:** Various password reset endpoints  
**New:** Not available - use Azure AD portal or Microsoft Graph API directly

---

## Testing the Retained Endpoints

### 1. Generate Azure AD Token
```http
POST /Token/Get AAD Token
Content-Type: application/json

{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "expires_in_minutes": 60
}
```

### 2. Test Graph Endpoints
```http
GET /Graph/getUserByIdentifier?identifier=user@domain.com
Authorization: Bearer <your-token>
```

### 3. Verify Removed Endpoints Return 404
```http
GET /Graph/getUserByEmail?email=user@domain.com
Expected: 404 Not Found
```

---

## Additional Resources

- **README.md** - Comprehensive API documentation with examples
- **Swagger UI** - Interactive API documentation at `/swagger`
- **Design Document** - `.kiro/specs/api-endpoint-cleanup/design.md`
- **Requirements Document** - `.kiro/specs/api-endpoint-cleanup/requirements.md`

---

## Support

For issues not covered in this guide:
1. Check the updated README.md for detailed endpoint documentation
2. Review the Swagger UI for interactive API testing
3. Verify your Azure AD configuration in appsettings.json
4. Check application logs for detailed error messages

---

**Last Updated:** November 25, 2025  
**Cleanup Version:** 1.0
