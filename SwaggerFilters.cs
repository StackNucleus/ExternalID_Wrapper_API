using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.OpenApi.Any;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Reflection;

namespace OIDC_ExternalID_API
{
    /// <summary>
    /// Custom operation filter to add default values and examples to Swagger documentation
    /// </summary>
    public class SwaggerDefaultValues : IOperationFilter
    {
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            var controllerActionDescriptor = context.ApiDescription.ActionDescriptor as ControllerActionDescriptor;
            if (controllerActionDescriptor == null) return;

            var controllerName = controllerActionDescriptor.ControllerName;
            var actionName = controllerActionDescriptor.ActionName;

            // Add controller-specific documentation
            switch (controllerName)
            {
                case "Token":
                    AddTokenControllerDocs(operation, actionName);
                    break;
                case "DGraph":
                    AddDGraphControllerDocs(operation, actionName);
                    break;
                case "Graph":
                    AddGraphControllerDocs(operation, actionName);
                    break;
                case "DGraph":
                    AddDGraphControllerDocs(operation, actionName);
                    break;
            }

            // Add common examples for all operations
            AddCommonExamples(operation, context);
        }

        private void AddTokenControllerDocs(OpenApiOperation operation, string actionName)
        {
            switch (actionName)
            {
                case "GetToken":
                    operation.Summary = "Generate Custom JWT Token";
                    operation.Description = @"
                        Generate a custom JWT token using OAuth 2.0 flows.

                        **Supported Grant Types:**
                        - `client_credentials` - Service-to-service authentication
                        - `password` - Username/password authentication
                        - `refresh_token` - Refresh expired tokens

                        **Usage:**
                        1. Use form data to send credentials
                        2. Copy the `access_token` from response
                        3. Use with `Bearer <token>` in Authorization header";
                    break;

                case "GetAzureAdToken":
                    operation.Summary = "Generate Azure AD Token (Client Credentials)";
                    operation.Description = @"
                        Generate an Azure AD token using client credentials flow with optional custom expiration control.

                        **Features:**
                        - Uses Azure AD OAuth 2.0 client credentials flow
                        - Supports Microsoft Graph API scopes
                        - Works with both GraphController and DGraphController
                        - Manual expiration time control for enhanced security

                        **Required Fields:**
                        - `client_id`: Your Azure AD application client ID
                        - `client_secret`: Your Azure AD application client secret
                        
                        **Optional Fields:**
                        - `scope`: Microsoft Graph API scope (defaults to `https://graph.microsoft.com/.default`)
                        - `expires_in_minutes`: Custom expiration time (1-1440 minutes, default: 60)
                        
                        **Security Benefits:**
                        - Forced token refresh cycles
                        - Reduced attack window
                        - Flexible security levels";
                    break;

                case "GetAzureAdClientCredentialsToken":
                    operation.Summary = "Generate Azure AD Token (Alternative Client Credentials)";
                    operation.Description = @"
                        Alternative endpoint for generating Azure AD tokens using client credentials flow.

                        **Same functionality as `/Token/azure-ad` but with different endpoint path.**
                        Useful for service-to-service authentication scenarios.";
                    break;

                case "ValidateToken":
                    operation.Summary = "Validate Access Token";
                    operation.Description = @"
                        Validate an existing access token and get token information.

                        **Returns:**
                        - Token validity status
                        - Token claims (subject, scope, expiration)
                        - Error details if token is invalid";
                    break;
            }
        }

        private void AddCustomGraphControllerDocs(OpenApiOperation operation, string actionName)
        {
            switch (actionName)
            {
                case "GetUserByEmail":
                    operation.Summary = "Get User by Email Address";
                    operation.Description = @"
                        Retrieve user details from Microsoft Graph API using email address.

                        **Features:**
                        - Direct Microsoft Graph API integration
                        - Supports all token types (Custom JWT, Azure AD)
                        - Searches by primary email or other email addresses

                        **Authentication:**
                        Requires Bearer token from any of these sources:
                        - `/Token` (Custom JWT)
                        - `/Token/azure-ad` (Azure AD)
                        - `/Token/azure-ad/client-credentials` (Azure AD)";
                    break;

                case "UpdateUserByEmail":
                    operation.Summary = "Update User by Email Address";
                    operation.Description = @"
                        Update user attributes in Microsoft Graph API using email address.

                        **Features:**
                        - Direct Microsoft Graph API integration
                        - Supports partial updates
                        - Automatically finds user by email first

                        **Common Update Fields:**
                        - `displayName`: User's display name
                        - `jobTitle`: Job title
                        - `department`: Department
                        - `mobilePhone`: Mobile phone number
                        - `businessPhones`: Business phone numbers";
                    break;

                case "UpdateUserAttributesByEmail":
                    operation.Summary = "Update Specific User Attributes by Email";
                    operation.Description = @"
                        Update specific user attributes using a structured model.

                        **Supported Attributes:**
                        - `DisplayName`: User's display name
                        - `JobTitle`: Job title
                        - `Department`: Department

                        **Benefits:**
                        - Type-safe updates
                        - Clear parameter documentation
                        - Validation built-in";
                    break;

                case "DeleteUserByEmail":
                    operation.Summary = "Delete User by Email Address";
                    operation.Description = @"
                        Delete a user from Microsoft Graph API using email address.

                        **⚠️ Warning:**
                        This operation permanently deletes the user account.
                        Make sure you have the correct email address before proceeding.

                        **Process:**
                        1. Finds user by email address
                        2. Deletes the user account
                        3. Returns success confirmation";
                    break;

                case "ResetPasswordByEmail":
                    operation.Summary = "Reset User Password by Email";
                    operation.Description = @"
                        Reset a user's password in Microsoft Graph API using email address.

                        **Features:**
                        - Admin-level operation
                        - Generates temporary password
                        - User must change password on next sign-in

                        **Required Fields:**
                        - `forceChangePasswordNextSignIn`: Set to true for security
                        - `password`: New temporary password";
                    break;
            }
        }

        private void AddGraphControllerDocs(OpenApiOperation operation, string actionName)
        {
            switch (actionName)
            {
                case "GetUserByEmail":
                    operation.Summary = "Get User by Email (GraphServiceClient)";
                    operation.Description = @"
                        Retrieve user details using GraphServiceClient.

                        **Features:**
                        - Uses GraphServiceClient with Azure AD credentials
                        - Automatic token management
                        - Built-in error handling

                        **Authentication:**
                        Uses configured Azure AD application credentials.";
                    break;

                case "UpdateUserByEmail":
                    operation.Summary = "Update User by Email (GraphServiceClient)";
                    operation.Description = @"
                        Update user attributes using GraphServiceClient.

                        **Features:**
                        - Uses GraphServiceClient with Azure AD credentials
                        - Automatic token management
                        - Built-in error handling

                        **Authentication:**
                        Uses configured Azure AD application credentials.";
                    break;
            }
        }

        private void AddCustomTestControllerDocs(OpenApiOperation operation, string actionName)
        {
            switch (actionName)
            {
                case "GetUserByIdentifier":
                    operation.Summary = "Get User by ID, UPN, or Email (Delegated Permissions)";
                    operation.Description = @"
                        Retrieve user details using delegated permissions with the authenticated user's token.

                        **Features:**
                        - Uses the authenticated user's access token directly with Microsoft Graph API
                        - Supports delegated permissions model
                        - Automatic user identification (ID, UPN, or email)

                        **Authentication:**
                        Requires a valid Azure AD access token with delegated permissions (User.Read.All).";
                    break;

                case "UpdateUserByIdentifier":
                    operation.Summary = "Update User by ID, UPN, or Email (Delegated Permissions)";
                    operation.Description = @"
                        Update user attributes using delegated permissions with the authenticated user's token.

                        **Features:**
                        - Uses the authenticated user's access token directly with Microsoft Graph API
                        - Supports delegated permissions model
                        - Automatic user identification (ID, UPN, or email)

                        **Authentication:**
                        Requires a valid Azure AD access token with delegated permissions (User.ReadWrite.All).";
                    break;

                case "DeleteUserByIdentifier":
                    operation.Summary = "Delete User by ID, UPN, or Email (Delegated Permissions)";
                    operation.Description = @"
                        Delete a user using delegated permissions with the authenticated user's token.

                        **Features:**
                        - Uses the authenticated user's access token directly with Microsoft Graph API
                        - Supports delegated permissions model
                        - Automatic user identification (ID, UPN, or email)
                        - ⚠️ Permanent operation

                        **Authentication:**
                        Requires a valid Azure AD access token with delegated permissions (User.ReadWrite.All).";
                    break;
            }
        }

        private void AddCommonExamples(OpenApiOperation operation, OperationFilterContext context)
        {
            // Add examples for common parameters
            foreach (var parameter in operation.Parameters)
            {
                switch (parameter.Name?.ToLower())
                {
                    case "email":
                        parameter.Description = "User's email address (e.g., user@company.com)";
                        parameter.Example = new OpenApiString("user@yourdomain.onmicrosoft.com");
                        break;
                    case "idoremail":
                        parameter.Description = "User's object ID or email address";
                        parameter.Example = new OpenApiString("user@yourdomain.onmicrosoft.com");
                        break;
                    case "top":
                        parameter.Description = "Number of users to return (max 999)";
                        parameter.Example = new OpenApiInteger(10);
                        break;
                }
            }

            // Add examples for request bodies
            if (operation.RequestBody?.Content != null)
            {
                foreach (var content in operation.RequestBody.Content)
                {
                    if (content.Key.Contains("json"))
                    {
                        var controllerActionDescriptor = context.ApiDescription.ActionDescriptor as ControllerActionDescriptor;
                        if (controllerActionDescriptor != null)
                        {
                            var controllerName = controllerActionDescriptor.ControllerName;
                            var actionName = controllerActionDescriptor.ActionName;

                            switch ($"{controllerName}.{actionName}")
                            {
                                case "Token.GetAzureAdToken":
                                    content.Value.Example = new OpenApiObject
                                    {
                                        ["client_id"] = new OpenApiString("your-client-id"),
                                        ["client_secret"] = new OpenApiString("your-client-secret"),
                                        ["scope"] = new OpenApiString("https://graph.microsoft.com/.default"),
                                        ["expires_in_minutes"] = new OpenApiInteger(60)
                                    };
                                    break;

                                case "Token.GetAzureAdClientCredentialsToken":
                                    content.Value.Example = new OpenApiObject
                                    {
                                        ["client_id"] = new OpenApiString("your-client-id"),
                                        ["client_secret"] = new OpenApiString("your-client-secret"),
                                        ["scope"] = new OpenApiString("https://graph.microsoft.com/.default"),
                                        ["expires_in_minutes"] = new OpenApiInteger(60)
                                    };
                                    break;


                                case "DGraph.UpdateUserAttributesByEmail":

                                    content.Value.Example = new OpenApiObject
                                    {
                                        ["DisplayName"] = new OpenApiString("John Doe"),
                                        ["JobTitle"] = new OpenApiString("Software Engineer"),
                                        ["Department"] = new OpenApiString("Engineering")
                                    };
                                    break;


                                case "DGraph.ResetPasswordByEmail":

                                    content.Value.Example = new OpenApiObject
                                    {
                                        ["passwordProfile"] = new OpenApiObject
                                        {
                                            ["password"] = new OpenApiString("TempPassword123!"),
                                            ["forceChangePasswordNextSignIn"] = new OpenApiBoolean(true)
                                        }
                                    };
                                    break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Custom schema filter to add better model documentation
    /// </summary>
    public class SwaggerSchemaFilter : ISchemaFilter
    {
        public void Apply(OpenApiSchema schema, SchemaFilterContext context)
        {
            var type = context.Type;

            // Add descriptions for common models
            switch (type.Name)
            {
                case "AzureAdTokenRequest":
                    schema.Description = "Request model for generating Azure AD tokens using client credentials flow.";
                    break;

                case "AzureAdClientCredentialsRequest":
                    schema.Description = "Request model for generating Azure AD tokens using client credentials flow.";
                    break;

                case "AzureAdTokenResponse":
                    schema.Description = "Response model containing Azure AD access token and metadata.";
                    break;

                case "UserUpdateModel":
                    schema.Description = "Model for updating specific user attributes in Microsoft Graph.";
                    break;

                case "OAuth2TokenRequest":
                    schema.Description = "Request model for generating custom JWT tokens using OAuth 2.0 flows.";
                    break;

                case "OAuth2TokenResponse":
                    schema.Description = "Response model containing custom JWT access token and metadata.";
                    break;
            }

            // Add property descriptions
            if (schema.Properties != null)
            {
                foreach (var property in schema.Properties)
                {
                    switch (property.Key)
                    {
                        case "client_id":
                            property.Value.Description = "Azure AD application client ID";
                            property.Value.Example = new OpenApiString("61ecb3ed-b4e2-4dd3-8a9f-1ee03cc47f4e");
                            break;

                        case "client_secret":
                            property.Value.Description = "Azure AD application client secret";
                            property.Value.Example = new OpenApiString("your-client-secret");
                            break;

                        case "scope":
                            property.Value.Description = "Microsoft Graph API scope";
                            property.Value.Example = new OpenApiString("https://graph.microsoft.com/.default");
                            break;

                        case "access_token":
                            property.Value.Description = "JWT access token for API authentication";
                            property.Value.Example = new OpenApiString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
                            break;

                        case "token_type":
                            property.Value.Description = "Type of token (always 'Bearer')";
                            property.Value.Example = new OpenApiString("Bearer");
                            break;

                        case "expires_in":
                            property.Value.Description = "Token expiration time in seconds";
                            property.Value.Example = new OpenApiInteger(3600);
                            break;

                        case "expires_in_minutes":
                            property.Value.Description = "Custom token expiration time in minutes for manual refresh cycles (1-1440 minutes, default: 60)";
                            property.Value.Example = new OpenApiInteger(60);
                            break;

                        case "DisplayName":
                            property.Value.Description = "User's display name";
                            property.Value.Example = new OpenApiString("John Doe");
                            break;

                        case "JobTitle":
                            property.Value.Description = "User's job title";
                            property.Value.Example = new OpenApiString("Software Engineer");
                            break;

                        case "Department":
                            property.Value.Description = "User's department";
                            property.Value.Example = new OpenApiString("Engineering");
                            break;
                    }
                }
            }
        }
    }
} 