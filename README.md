# OIDC_ExternalID_API

This API enables secure user management in Azure AD via Microsoft Graph, using JWT Bearer token authentication. It is built with C# and .NET.

## 🔐 Authentication System

The API now uses **JWT Bearer token authentication** for secure access to all Graph endpoints:

### Token Generation
- **Endpoint**: `POST /Token`
- **Grant Types**: `client_credentials`, `password`, `refresh_token`
- **Token Type**: JWT Bearer token
- **Expiration**: 1 hour (configurable)

### Token Validation
- **Endpoint**: `POST /Token/validate`
- **Purpose**: Validate existing tokens and get user information

### Swagger UI Integration
- All Graph endpoints require Bearer token authentication
- Use the "Authorize" button in Swagger UI to set your Bearer token
- Format: `Bearer <your-jwt-token>`

### Two Graph Controller Options
1. **GraphController** - Uses GraphServiceClient with Azure AD credentials
2. **CustomGraphController** - Uses your JWT token directly with Microsoft Graph API

---

## Supported Account Types for Token Generation and Password Change

| Account Type                                 | Token Generation | Password Change |
|----------------------------------------------|:----------------:|:--------------:|
| Azure AD user                               |       ✅         |      ✅        |
| Azure AD B2B guest                          |       ✅         |      ✅        |
| Social login (federated via Azure AD B2C/B2B)|       ✅         |      ✅*       |
| Local-only account (not in Azure AD)         |       ❌         |      ❌        |
| Social login (not federated)                 |       ❌         |      ❌        |

*Password change for social logins is only possible if the social account is federated through Azure AD B2C/B2B and the user is managed by your Azure AD tenant. Otherwise, password changes must be performed with the external provider (e.g., Google, Facebook).

---

## Quick Start

1. **Generate a Token**:
   ```
   POST https://localhost:demo/Token
   Content-Type: application/x-www-form-urlencoded
   
   client_id=your-client-id&client_secret=your-secret&scope=api://default&grant_type=client_credentials
   ```

2. **Copy the Access Token** from the response

3. **Open Swagger UI** at `https://localhost:demo/swagger`

4. **Authorize in Swagger UI**:
   - Click the **"Authorize"** button (🔒)
   - Enter: `Bearer <your-access-token>`
   - Click "Authorize"

5. **Test Graph Endpoints**:
   - All `/Graph/*` endpoints now require Bearer token authentication
   - Try `GET /Graph/getUserById?idOrEmail=user@example.com`
   - Try `GET /Graph/me` to see your token information
   - Try `GET /CustomGraph/getUserById?idOrEmail=user@example.com` (uses your JWT token directly)
   - Try `PATCH /CustomGraph/updateUserByEmail?email=user@example.com` (update user by email)
   - Try `POST /CustomGraph/changePassword` (change password)
   - Try `PATCH /CustomGraph/resetPasswordByEmail?email=user@example.com` (reset password by email)
   - Try `POST /Graph/requestPasswordReset(SSPR-likeInAzure` (request password reset)
   - Try `POST /Graph/completePasswordReset(SSPR-likeInAzure)` (complete password reset)

---

## Troubleshooting

- **Domain not valid:** Make sure the user's domain is allowed in Azure AD External Identities settings.
- **User not found:** Ensure the user is registered and has accepted any invitations.
- **Permission errors:** Confirm the app registration has the right Microsoft Graph permissions and consent is granted.
- **Redirect URI issues:** The redirect URI in Azure AD must match exactly what is used in Swagger UI.

---

## Troubleshooting: External Identities User Sign-In Issues

If you create a user (e.g., with a Gmail or other external domain) via an Azure AD External Identities user flow (B2C/B2B), and then try to authenticate or use API endpoints via Swagger UI, you may encounter errors like:
- "The domain is not valid"
- "User is not present in the tenant"
- "User not found"

### Why does this happen?
- **User type and sign-in method mismatch:**
  - If the user was created as a federated user (e.g., Google), they must sign in using the same provider (Google) via the correct user flow.
  - If you try to sign in with a password for a federated user, or vice versa, authentication will fail.
- **Wrong user flow or policy:**
  - Azure AD B2C/B2B uses different user flows (policies) for different identity providers. Using the wrong flow will cause errors.
- **Swagger UI or App Registration not configured for external identities:**
  - Ensure your OAuth2 config and Azure AD App Registration support external identities and the correct user flows.
- **Domain restrictions:**
  - Your Azure AD tenant may restrict which domains can sign in.

### How to resolve
1. **Check how the user was created** (local or federated) in Azure AD (see the PKCE and External Identities Users section above).
2. **Use the correct sign-in method** for that user type (e.g., Google users must use "Sign in with Google").
3. **Ensure your OAuth2 endpoints and policies match the user type:**
   - For B2C, use the B2C-specific endpoints and policies in your OAuth2 config:
     ```
     https://<your-tenant>.b2clogin.com/<your-tenant>.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_SIGNIN
     ```
   - For B2B or multi-tenant, use the appropriate Azure AD endpoint.
4. **Check allowed domains** in Azure AD > External Identities > Cross-tenant access settings.

### Summary Table
| User Type      | How to Sign In                | Common Error if Wrong Flow      |
|----------------|------------------------------|---------------------------------|
| Local Account  | Username/password (local)    | "Domain not valid", "User not found" |
| Google/Federated| "Sign in with Google" button | "Domain not valid", "User not found" |
| B2B Guest      | Home tenant credentials      | "User not found", "Domain not valid" |

**Tip:**
- Always use the correct user flow and OAuth2 endpoint for the user type.
- If you get a domain or user error, double-check the user's identity provider and the sign-in method you are using.

---

## PKCE and External Identities Users

### What is PKCE?
PKCE (Proof Key for Code Exchange) is a security feature used in the OAuth2 Authorization Code flow. It protects the login process for all users—regardless of how they were created (native, B2B, B2C, social, etc.). PKCE prevents attackers from intercepting the authorization code and exchanging it for a token. It is required for browser-based and public clients, and is recommended by Microsoft for all modern authentication scenarios.

- **PKCE is not tied to user type.** It is a security mechanism for the login flow.
- **All users** (B2B, B2C, social) can authenticate using PKCE if your app is configured for it.

---

## API Endpoint Support for External Identities Users

The table below shows which API endpoints are available to different user types created via Azure AD External Identities:

| Endpoint                        | B2B Guest | B2C Local | Social/Federated |
|----------------------------------|:---------:|:---------:|:----------------:|
| `/Graph/getUserById`             |    ✅     |    ✅     |        ✅        |
| `/Graph/getUserByEmail`          |    ✅     |    ✅     |        ✅        |
| `/Graph/updateUserById`          |    ✅     |    ✅     |        ✅        |
| `/Graph/updateUserByEmail`       |    ✅     |    ✅     |        ✅        |
| `/Graph/updateUserAttributesById`|    ✅     |    ✅     |        ✅        |
| `/Graph/updateUserAttributesByEmail`|    ✅     |    ✅     |        ✅        |
| `/Graph/deleteUserById`          |    ✅     |    ✅     |        ✅        |
| `/Graph/deleteUserByEmail`       |    ✅     |    ✅     |        ✅        |
| `/Graph/changePassword`          |    ✅     |    ✅     |        ❌*       |
| `/Graph/resetPasswordById`       |    ✅     |    ✅     |        ❌*       |
| `/Graph/resetPasswordByEmail`    |    ✅     |    ✅     |        ❌*       |
| `/Graph/requestPasswordReset(SSPR-likeInAzure`    |    ✅     |    ✅     |        ❌*       |
| `/Graph/completePasswordReset(SSPR-likeInAzure)`   |    ✅     |    ✅     |        ❌*       |

- **✅ = Supported**
- **❌ = Not supported for social/federated users** (must reset password with their original provider)
- *Social/federated users (e.g., Google, Facebook) must use their provider's password reset flow, not the API's password endpoints.

---

### Summary
- **PKCE** is a security feature for the login flow, not tied to user type.
- **All users** (B2B, B2C, social) can authenticate and get tokens using PKCE.
- **API endpoints that do not involve password change** will work for all users.
- **Password change/reset endpoints** only work for users whose credentials are managed by your Azure AD/B2C tenant (not for social/federated users).

If you want to support password reset for social users, you must redirect them to their provider's password reset flow.

---

## Using PKCE from Swagger UI: Which API Endpoints Can Be Authorized?

When you use PKCE from Swagger UI (OAuth2 Authorization Code flow with PKCE), you can authorize and authenticate for all API endpoints that require a delegated user token, as long as:
- The user is allowed to access the endpoint (based on their type and role)
- The access token has the required Microsoft Graph scopes
- The user signs in using the correct method for their identity type (local, B2B, federated/social)

### Endpoint Support Table

| Endpoint                        | Works for Local/B2B/B2C Local | Works for Social/Federated | Notes                        |
|----------------------------------|:-----------------------------:|:--------------------------:|------------------------------|
| `/Graph/getUserById`             |              ✅               |            ✅              |                              |
| `/Graph/getUserByEmail`          |              ✅               |            ✅              |                              |
| `/Graph/updateUserById`          |              ✅               |            ✅              | Own profile or admin         |
| `/Graph/updateUserByEmail`       |              ✅               |            ✅              | Own profile or admin         |
| `/Graph/updateUserAttributesById`|              ✅               |            ✅              | Own profile or admin         |
| `/Graph/updateUserAttributesByEmail`|              ✅               |            ✅              | Own profile or admin         |
| `/Graph/deleteUserById`          |              ✅               |            ✅              | Own profile or admin         |
| `/Graph/deleteUserByEmail`       |              ✅               |            ✅              | Own profile or admin         |
| `/Graph/changePassword`          |              ✅               |            ❌              |                              |
| `/Graph/resetPasswordById`       |              ✅               |            ❌              | Admin only                   |
| `/Graph/resetPasswordByEmail`    |              ✅               |            ❌              | Admin only                   |
| `/Graph/requestPasswordReset(SSPR-likeInAzure`    |              ✅               |            ❌              | Self-service                 |
| `/Graph/completePasswordReset(SSPR-likeInAzure)`   |              ✅               |            ❌              | Self-service                 |
| `/WeatherForecast`               |              ✅               |            ✅              | Public                       |

- **✅ = Supported**
- **❌ = Not supported for social/federated users** (must reset password with their original provider)

### Best Practices for Using PKCE in Swagger UI
- Always use PKCE for secure login in Swagger UI.
- Select all required Microsoft Graph scopes when authorizing (see Authentication & Authorization section).
- For password endpoints, ensure the user is managed by your tenant (not a social/federated user).
- Handle errors gracefully and guide federated users to their provider's password reset if needed.

### Notes
- PKCE is a security feature for the login flow and does not limit which endpoints you can use; endpoint access depends on user type and permissions.
- All users can use profile and general endpoints; only tenant-managed users can use password endpoints.
- If you get an error, check the user's type and the scopes granted to the access token.



---

## Testing the API with Swagger UI and Azure AD Roles

### Prerequisites
- API is deployed and accessible (e.g., `https://your-api.azurewebsites.net/swagger`).
- Azure AD App Registration is configured with:
  - Redirect URI: `https://your-api.azurewebsites.net/swagger/oauth2-redirect.html`
  - Required Microsoft Graph API permissions: `User.Read.All`, `User.ReadWrite.All`, `Directory.AccessAsUser.All`, `offline_access`, `openid`.
- Users are assigned to appropriate roles in Azure AD (Global Admin, User Admin, Helpdesk Admin, Regular User, etc.).

---

### How to Test as Different Users/Roles

1. **Open Swagger UI**
   - Go to your API’s Swagger UI: `https://your-api.azurewebsites.net/swagger`

2. **Authenticate via OAuth2 (PKCE)**
   - Click the **Authorize** button (top right).
   - Select the scopes you want to test with (choose all for admin, or just `User.Read` for regular user).
   - Click **Authorize**.
   - Sign in as the user you want to test (admin, helpdesk, regular user, B2B guest, etc.).
   - Consent to permissions if prompted.
   - After login, you’ll be redirected back to Swagger UI, and the access token will be used for API calls.

3. **Test API Endpoints**
   - Click on an endpoint (e.g., `/Graph/resetPasswordById`, `/Graph/changePassword`, `/Graph/deleteUserById`).
   - Click **Try it out**, fill in parameters, and click **Execute**.
   - Admin endpoints will only succeed for users with the required admin role. Self-service endpoints work for regular users.

4. **Switch Users/Roles**
   - Click **Authorize** again, then **Logout**.
   - Repeat the authentication process as a different user/role.
   - Test endpoints again.

5. **Check Responses**
   - 200 = Success
   - 401 = Not authenticated
   - 403 = Not authorized (insufficient role/permission)

6. **(Optional) Inspect Token Claims**
   - After authenticating, copy the access token and paste it at [jwt.ms](https://jwt.ms) to inspect user roles and claims.

---

### Role-Based Access Summary Table

| Role           | Can Reset Others' Passwords | Can Delete Other Users | Can Change Own Password | Can Update/Delete Own Profile |
|----------------|:--------------------------:|:---------------------:|:-----------------------:|:-----------------------------:|
| Global Admin   | Yes                        | Yes                   | Yes                     | Yes                           |
| User Admin     | Yes                        | Yes                   | Yes                     | Yes                           |
| Helpdesk Admin | Yes                        | Yes                   | Yes                     | Yes                           |
| Regular User   | No                         | No                    | Yes                     | Yes                           |
| B2B/B2C Guest  | No (unless assigned)       | No                    | Yes                     | Yes                           |

---

### Troubleshooting
- **401 Unauthorized:** Not authenticated. Make sure you are signed in and the token is present.
- **403 Forbidden:** Authenticated but do not have the required role/permission for the endpoint.
- **Consent/Permission Errors:** Check Azure AD App Registration and API permissions.

---

### Notes on Token Endpoints
- The `/Token/callback` and `/Token/refresh` endpoints in the API are **not required** when using Swagger UI. Swagger UI handles the full OAuth2 Authorization Code flow with PKCE and token refresh directly with Azure AD.
- Your API acts as a resource server, validating Bearer tokens sent by Swagger UI.

---

For more details on endpoint permissions and roles, see the API Usage Guide and endpoint documentation above.

## Azure AD Integration: Service Principal (SPN) and App Registration Support

This application can be configured to work with both:

### 1. Service Principal (SPN) / App Registration (Application Permissions)
- Register an application in Azure AD (App Registration).
- Assign application permissions (e.g., `User.Read.All`, `User.ReadWrite.All`, `User-PasswordProfile.ReadWrite.All`).
- Generate a client secret or certificate for the app.
- Use the app’s client ID and secret with the `client_credentials` grant in the `/Token` endpoint.
- The API will authenticate as the app (Service Principal) and can call Microsoft Graph as the app.

### 2. Delegated Permissions (User Context)
- Register the app and assign delegated permissions.
- Use user credentials (for testing) or implement OAuth2 Authorization Code flow.
- The API will act on behalf of the signed-in user.

### Summary Table

| Scenario         | Supported by This API? | How to Configure/Use                |
|------------------|-----------------------|-------------------------------------|
| Service Principal (SPN) / App Registration (App-only) | ✅ Yes | Register app in Azure AD, assign application permissions, use client credentials in `/Token` |
| Delegated (User) | ✅ Yes | Register app, assign delegated permissions, use user credentials or OAuth2 flow |

### How to Configure
1. Register your app in Azure AD (App Registration).
2. Assign the required Microsoft Graph permissions (delegated and/or application).
3. For SPN/app-only:
   - Generate a client secret or certificate.
   - Use `client_id` and `client_secret` with the `client_credentials` grant in `/Token`.
4. For delegated:
   - Use user credentials (for testing) or implement OAuth2 Authorization Code flow.

**References:**
- [App-only authentication with Microsoft Graph](https://learn.microsoft.com/en-us/graph/auth-v2-service)
- [Delegated vs. Application permissions](https://learn.microsoft.com/en-us/graph/permissions-reference)

## Step-by-Step Setup Instructions

### 1. Service Principal (SPN) / App Registration (Application Permissions)

**a. Register an Application in Azure AD**
1. Go to [Azure Portal > Azure Active Directory > App registrations](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
2. Click **New registration**.
3. Enter a name, select supported account types, and click **Register**.

**b. Configure Application Permissions**
1. In your app registration, go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**.
2. Add required permissions (e.g., `User.Read.All`, `User.ReadWrite.All`, `User-PasswordProfile.ReadWrite.All`).
3. Click **Add permissions**.
4. Click **Grant admin consent** for your tenant.

**c. Create a Client Secret**
1. Go to **Certificates & secrets** > **New client secret**.
2. Add a description and expiration, then click **Add**.
3. Copy the value (you will not see it again).

**d. Configure Your API**
- Use the `client_id` and `client_secret` from your app registration in your `/Token` endpoint with the `client_credentials` grant.

**Example Token Request:**
```bash
curl -X POST "https://localhost:demo/Token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=api://default&grant_type=client_credentials"
```

---

### 2. Delegated (User) Permissions

**a. Register an Application in Azure AD**
- (Same as above)

**b. Configure Delegated Permissions**
1. In your app registration, go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated permissions**.
2. Add required permissions (e.g., `User.Read`, `User.ReadWrite`, `User-PasswordProfile.ReadWrite.All`).
3. Click **Add permissions**.
4. Click **Grant admin consent** if needed.

**c. (For testing) Use Resource Owner Password Credentials (ROPC) Flow**
- Only for test tenants and non-MFA users.
- Use the `/Token` endpoint with `grant_type=password`:

```bash
curl -X POST "https://localhost:demo/Token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=api://default&grant_type=password&username=USER@DOMAIN.COM&password=USER_PASSWORD"
```

**d. (For production) Use OAuth2 Authorization Code Flow**
- Implement the standard OAuth2 Authorization Code flow in your client app.
- Redirect users to the Azure AD login page, obtain an authorization code, and exchange it for a token.
- Use the token in the `Authorization` header for API requests.

**References:**
- [Microsoft Identity Platform: App registration](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Microsoft Identity Platform: OAuth2.0 Authorization Code Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)


# Visual Flow

flowchart LR
    UserApp((App Team))
    APIApp((API App / SPN))
    Authorization(Authorizaion Via Token)
    WraperAPI((Wraper Graph API))
    GraphAPI((Microsoft Graph API))

    UserApp --calls--> Authorization
    Authorization --calls--> WraperAPI
    WraperAPI --calls--> APIApp
    APIApp --calls--> GraphAPI
    GraphAPI --Sends Response--> WraperAPI
    WraperAPI --Sends Response--> UserApp

# Architecture & Permission Flow

flowchart TD
    subgraph AzureAD
        APIApp["API App (SPN)<br/>(Has Graph Permissions)"]
        ClientApp["Client App<br/>(No Graph Permissions)"]
    end

    subgraph YourAPI
        GraphController
        CustomGraphController
    end

    ClientApp -- "Calls (with JWT or Azure AD token)" --> YourAPI
    YourAPI -- "Uses app credentials<br/>(ClientSecretCredential)" --> APIApp
    GraphController -- "Calls Graph API<br/>(always as API App)" --> MicrosoftGraph[(Microsoft Graph API)]
    CustomGraphController -- "Calls Graph API<br/>(as API App or as Client App, depending on token)" --> MicrosoftGraph

    APIApp -- "Has Graph API permissions" --- MicrosoftGraph