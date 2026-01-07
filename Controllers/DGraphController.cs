using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;
using OIDC_ExternalID_API.Utilities;
using Swashbuckle.AspNetCore.Annotations;
using System.Net.Http.Headers;
using System.Text.Json;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiExplorerSettings(IgnoreApi = true)]
    [ApiController]
    //[Route("[controller]")]
    //[Authorize]
    //[NonAction]
    [Authorize(Policy = "BlockAccess")]
    public class DGraphController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _config;
        private readonly ILogger<DGraphController> _logger;

        public DGraphController(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor, IConfiguration config, ILogger<DGraphController> logger)
        {
            _httpClientFactory = httpClientFactory;
            _httpContextAccessor = httpContextAccessor;
            _config = config;
            _logger = logger;
        }

        [HttpGet("getUserByIdentifier/v1.0")]
        [Authorize]
        [ProducesResponseType(typeof(object), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Get User by ID, UPN, or Email (Delegated Permissions)",
            Description = "Retrieve user details from Microsoft Graph API using delegated permissions. The authenticated user's token is used directly with Microsoft Graph API.",
            OperationId = "GetUserDelegated",
            Tags = new[] { "CustomTest" }
        )]
        [SwaggerResponse(200, "User details retrieved successfully", typeof(object))]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> GetUserByIdentifier(
            [FromQuery]
            [SwaggerParameter("User Object ID, User Principal Name (UPN), or Email address", Required = true)]
            string identifier)
        {
            try
            {
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                // Get the access token from the authenticated user
                var accessToken = TokenUtility.GetAccessTokenFromRequest(Request);
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Access token not found in Authorization header");
                }

                // First, try to get user info from the token itself
                var userFromToken = TokenUtility.GetUserFromToken(accessToken);
                User fullUser = null;

                if (userFromToken != null)
                {
                    // If identifier matches token info, get full details from Azure AD
                    if (identifier == userFromToken.UserPrincipalName ||
                        identifier == userFromToken.Email ||
                        identifier == userFromToken.ObjectId)
                    {
                        // Get full user details from Azure AD using the object ID from token
                        fullUser = await GetFullUserFromAzureAD(userFromToken.ObjectId, accessToken);
                        if (fullUser != null)
                        {
                            return Ok(fullUser);
                        }
                    }
                    // Special case: if identifier is an email that matches token's email but user not found in AD
                    else if (identifier == userFromToken.Email && identifier.Contains("@"))
                    {
                        _logger.LogInformation("Email {Email} from token not found in AD, trying with token's object ID {ObjectId}",
                            identifier, userFromToken.ObjectId);
                        // Try to get user by object ID from token
                        fullUser = await GetFullUserFromAzureAD(userFromToken.ObjectId, accessToken);
                        if (fullUser != null)
                        {
                            return Ok(fullUser);
                        }
                    }
                }

                // If not found in token or identifier doesn't match, search Azure AD
                // Create HTTP client with user's token
                using var httpClient = _httpClientFactory.CreateClient();
                // Use the helper method to find user by any identifier type
                fullUser = await FindUserByIdentifierAsync(identifier, accessToken);

                if (fullUser == null)
                    return NotFound("User not found.");

                return Ok(fullUser);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user with identifier: {Identifier}", identifier);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPatch("updateUserByIdentifier/v1.0")]
        [Authorize]
        [ProducesResponseType(200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Update User by ID, UPN, or Email (Delegated Permissions)",
            Description = "Update user attributes in Microsoft Graph API using delegated permissions. The authenticated user's token is used directly with Microsoft Graph API.",
            OperationId = "UpdateUserDelegated",
            Tags = new[] { "CustomTest" }
        )]
        [SwaggerResponse(200, "User updated successfully")]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> UpdateUserByIdentifier(
            [FromQuery]
            [SwaggerParameter("User Object ID, User Principal Name (UPN), or Email address", Required = true)]
            string identifier,
            [FromBody] Dictionary<string, object> updates)
        {
            try
            {
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (updates == null || updates.Count == 0)
                {
                    return BadRequest("Update data is required");
                }

                // Validate update data
                if (updates.Any(kvp => string.IsNullOrEmpty(kvp.Key)))
                {
                    return BadRequest("Property names cannot be empty");
                }

                // Check for valid user properties
                var validProperties = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "givenName", "surname", "displayName", "jobTitle", "department",
                    "companyName", "officeLocation", "streetAddress", "city", "state",
                    "postalCode", "country", "mobilePhone", "businessPhones", "mail"
                };

                foreach (var kvp in updates)
                {
                    if (!validProperties.Contains(kvp.Key))
                    {
                        _logger.LogWarning("Attempt to update invalid user property: {PropertyName}", kvp.Key);
                        // Allow it anyway since Microsoft Graph might accept it
                    }
                }

                // Get the access token from the authenticated user
                var accessToken = TokenUtility.GetAccessTokenFromRequest(Request);
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Access token not found in Authorization header");
                }

                // First, try to get user info from the token itself (same logic as getUserByIdentifier)
                var userFromToken = TokenUtility.GetUserFromToken(accessToken);
                User user = null;

                if (userFromToken != null)
                {
                    // If identifier matches token info, get full details from Azure AD
                    if (identifier == userFromToken.UserPrincipalName ||
                        identifier == userFromToken.Email ||
                        identifier == userFromToken.ObjectId)
                    {
                        // Get full user details from Azure AD using the object ID from token
                        user = await GetFullUserFromAzureAD(userFromToken.ObjectId, accessToken);
                        if (user != null)
                        {
                            // Found user via token, proceed with update
                        }
                    }
                    // Special case: if identifier is an email that matches token's email but user not found in AD
                    else if (identifier == userFromToken.Email && identifier.Contains("@"))
                    {
                        _logger.LogInformation("Email {Email} from token not found in AD, trying with token's object ID {ObjectId}",
                            identifier, userFromToken.ObjectId);
                        // Try to get user by object ID from token
                        user = await GetFullUserFromAzureAD(userFromToken.ObjectId, accessToken);
                        if (user != null)
                        {
                            // Found user via token fallback, proceed with update
                        }
                    }
                }

                // If not found in token or identifier doesn't match, search Azure AD
                if (user == null)
                {
                    user = await FindUserByIdentifierAsync(identifier, accessToken);
                    if (user == null)
                    {
                        return NotFound("User not found.");
                    }
                }

                string userId = user.Id;

                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("Found user object but ID is null for identifier: {Identifier}", identifier);
                    return NotFound("User not found.");
                }

                _logger.LogInformation("Found user with ID: {UserId} for identifier: {Identifier}", userId, identifier);

                // Update user using delegated permissions
                using var updateClient = _httpClientFactory.CreateClient();
                updateClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                // Create proper update request for Microsoft Graph
                // Build the update request with proper validation
                var updateRequest = new Dictionary<string, object>();
                foreach (var kvp in updates)
                {
                    // Skip null or empty values
                    if (kvp.Value != null && !string.IsNullOrEmpty(kvp.Value.ToString()))
                    {
                        updateRequest[kvp.Key] = kvp.Value;
                    }
                }

                if (updateRequest.Count == 0)
                {
                    return BadRequest("No valid properties to update");
                }

                var updateContent = new StringContent(JsonSerializer.Serialize(updateRequest), System.Text.Encoding.UTF8, "application/json");
                _logger.LogDebug("Update request for user {UserId}: {UpdateContent}", userId, await updateContent.ReadAsStringAsync());
                var updateResponse = await updateClient.PatchAsync($"https://graph.microsoft.com/v1.0/users/{userId}", updateContent);

                if (updateResponse.IsSuccessStatusCode)
                {
                    return Ok("User updated successfully.");
                }
                else
                {
                    var errorContent = await updateResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Update failed for user {UserId}: {StatusCode} - {ErrorContent}", userId, updateResponse.StatusCode, errorContent);

                    try
                    {
                        var errorData = JsonSerializer.Deserialize<ODataError>(errorContent);
                        if (errorData?.Error != null)
                        {
                            // Provide specific guidance for common errors
                            if (errorData.Error.Code == "Request_BadRequest" || errorData.Error.Code == "InvalidRequest")
                            {
                                return BadRequest($"Cannot update user: {errorData.Error.Message}. This property may be read-only or require special permissions.");
                            }
                            else if (errorData.Error.Code == "ErrorInvalidProperty")
                            {
                                return BadRequest($"Invalid property: {errorData.Error.Message}. Please check the property name and try again.");
                            }
                            else if (errorData.Error.Code == "Authorization_RequestDenied")
                            {
                                return BadRequest($"Insufficient privileges: {errorData.Error.Message}. Your token has delegated permissions which only allow updating your own profile. For updating other users or restricted properties, application permissions (User.ReadWrite.All) with admin consent are required.");
                            }
                            else
                            {
                                return BadRequest($"{errorData.Error.Code}: {errorData.Error.Message}");
                            }
                        }
                        return BadRequest("Unknown error updating user. The property may not be writable.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to parse error response for user {UserId}", userId);
                        return BadRequest(new { Message = $"Error updating user: {errorContent}. This may indicate the property cannot be updated." });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user with identifier: {Identifier}", identifier);
                return StatusCode(500, ApiResponse<object>.CreateError($"Internal server error: {ex.Message}"));
            }
        }

        [HttpPatch("updateUserAttributesByIdentifier/v1.0")]
        [Authorize]
        [ProducesResponseType(200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Update Specific User Attributes by ID, UPN, or Email (Delegated Permissions)",
            Description = "Update specific user attributes (firstName, lastName, displayName, etc.) using a structured model with delegated permissions. Type-safe updates with validation.",
            OperationId = "UpdateUserAttributesByIdentifierDelegated",
            Tags = new[] { "CustomTest" }
        )]
        [SwaggerResponse(200, "User updated successfully")]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> UpdateUserAttributesByIdentifier(
            [FromQuery]
            [SwaggerParameter("User Object ID, User Principal Name (UPN), or Email address", Required = true)]
            string identifier,
            [FromBody] UserUpdateModel updates)
        {
            try
            {
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (updates == null)
                {
                    return BadRequest("Update data is required");
                }

                // Get the access token from the authenticated user
                var accessToken = TokenUtility.GetAccessTokenFromRequest(Request);
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Access token not found in Authorization header");
                }

                // First, try to get user info from the token itself (same logic as getUserByIdentifier)
                var userFromToken = TokenUtility.GetUserFromToken(accessToken);
                User user = null;

                if (userFromToken != null)
                {
                    // If identifier matches token info, get full details from Azure AD
                    if (identifier == userFromToken.UserPrincipalName ||
                        identifier == userFromToken.Email ||
                        identifier == userFromToken.ObjectId)
                    {
                        // Get full user details from Azure AD using the object ID from token
                        user = await GetFullUserFromAzureAD(userFromToken.ObjectId, accessToken);
                        if (user != null)
                        {
                            // Found user via token, proceed with update
                        }
                    }
                    // Special case: if identifier is an email that matches token's email but user not found in AD
                    else if (identifier == userFromToken.Email && identifier.Contains("@"))
                    {
                        _logger.LogInformation("Email {Email} from token not found in AD, trying with token's object ID {ObjectId}",
                            identifier, userFromToken.ObjectId);
                        // Try to get user by object ID from token
                        user = await GetFullUserFromAzureAD(userFromToken.ObjectId, accessToken);
                        if (user != null)
                        {
                            // Found user via token fallback, proceed with update
                        }
                    }
                }

                // If not found in token or identifier doesn't match, search Azure AD
                if (user == null)
                {
                    user = await FindUserByIdentifierAsync(identifier, accessToken);
                    if (user == null)
                    {
                        return NotFound("User not found.");
                    }
                }

                string userId = user.Id;
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("Found user object but ID is null for identifier: {Identifier}", identifier);
                    return NotFound("User not found.");
                }

                // Build the update request using the structured model
                var updateRequest = new Dictionary<string, object>();

                if (!string.IsNullOrEmpty(updates.firstName))
                    updateRequest["givenName"] = updates.firstName;
                if (!string.IsNullOrEmpty(updates.lastName))
                    updateRequest["surname"] = updates.lastName;
                if (!string.IsNullOrEmpty(updates.DisplayName))
                    updateRequest["displayName"] = updates.DisplayName;

                if (updateRequest.Count == 0)
                {
                    return BadRequest("No valid properties to update");
                }

                // Update user using delegated permissions
                using var updateClient = _httpClientFactory.CreateClient();
                updateClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var updateContent = new StringContent(JsonSerializer.Serialize(updateRequest), System.Text.Encoding.UTF8, "application/json");
                _logger.LogDebug("Update attributes request for user {UserId}: {UpdateContent}", userId, await updateContent.ReadAsStringAsync());
                var updateResponse = await updateClient.PatchAsync($"https://graph.microsoft.com/v1.0/users/{userId}", updateContent);

                if (updateResponse.IsSuccessStatusCode)
                {
                    return Ok("User attributes updated successfully.");
                }
                else
                {
                    var errorContent = await updateResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Update attributes failed for user {UserId}: {StatusCode} - {ErrorContent}", userId, updateResponse.StatusCode, errorContent);

                    try
                    {
                        var errorData = JsonSerializer.Deserialize<ODataError>(errorContent);
                        if (errorData?.Error != null)
                        {
                            // Provide specific guidance for common errors
                            if (errorData.Error.Code == "Request_BadRequest" || errorData.Error.Code == "InvalidRequest")
                            {
                                return BadRequest($"Cannot update user: {errorData.Error.Message}. This property may be read-only or require special permissions.");
                            }
                            else if (errorData.Error.Code == "ErrorInvalidProperty")
                            {
                                return BadRequest($"Invalid property: {errorData.Error.Message}. Please check the property name and try again.");
                            }
                            else if (errorData.Error.Code == "Authorization_RequestDenied")
                            {
                                return BadRequest($"Insufficient privileges: {errorData.Error.Message}. Your token has delegated permissions which only allow updating your own profile. For updating other users or restricted properties, application permissions (User.ReadWrite.All) with admin consent are required.");
                            }
                            else
                            {
                                return BadRequest($"{errorData.Error.Code}: {errorData.Error.Message}");
                            }
                        }
                        return BadRequest("Unknown error updating user attributes. The property may not be writable.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to parse error response for user {UserId}", userId);
                        return BadRequest(new { Message = $"Error updating user attributes: {errorContent}. This may indicate the property cannot be updated." });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user attributes with identifier: {Identifier}", identifier);
                return StatusCode(500, ApiResponse<object>.CreateError($"Internal server error: {ex.Message}"));
            }
        }

        /// <summary>
        /// Helper method to find user by Object ID, UPN, or email
        /// </summary>
        /// <param name="identifier">User Object ID, User Principal Name (UPN), or email address</param>
        /// <param name="accessToken">Access token for Microsoft Graph API</param>
        /// <returns>User object if found, null otherwise</returns>
        private async Task<User> FindUserByIdentifierAsync(string identifier, string accessToken)
        {
            _logger.LogInformation("Starting user lookup for identifier: {Identifier}", identifier);
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            // Try direct lookup first (works for Object ID and UPN)
            try
            {
                _logger.LogDebug("Attempting direct lookup for identifier: {Identifier}", identifier);
                var directResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{identifier}");
                _logger.LogDebug("Direct lookup response status: {StatusCode}", directResponse.StatusCode);

                if (directResponse.IsSuccessStatusCode)
                {
                    var userJson = await directResponse.Content.ReadAsStringAsync();
                    _logger.LogDebug("Direct lookup response: {UserJson}", userJson);
                    var user = JsonSerializer.Deserialize<User>(userJson);
                    // Ensure user ID is set (should be the same as the identifier for direct lookup)
                    if (string.IsNullOrEmpty(user?.Id))
                    {
                        user.Id = identifier;
                    }
                    _logger.LogInformation("Found user via direct lookup: {UserId}", user.Id);
                    return user;
                }
                else if (directResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    _logger.LogWarning("403 Forbidden: Insufficient permissions to access user data. Check that User.Read.All permission has admin consent.");
                    return null;
                }
                else if (directResponse.StatusCode != System.Net.HttpStatusCode.NotFound)
                {
                    var errorContent = await directResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Unexpected error in direct lookup: {StatusCode} - {ErrorContent}", directResponse.StatusCode, errorContent);
                    directResponse.EnsureSuccessStatusCode();
                }
                else
                {
                    _logger.LogDebug("User not found via direct lookup");
                }
            }
            catch (Exception ex) when (ex is not System.Net.Http.HttpRequestException)
            {
                _logger.LogWarning(ex, "Direct user lookup failed for identifier: {Identifier}", identifier);
            }

            // If direct lookup failed and identifier contains @, try email search
            if (identifier.Contains("@"))
            {
                try
                {
                    _logger.LogDebug("Attempting email search for identifier: {Identifier}", identifier);

                    // First try simple UPN lookup (email might be the UPN)
                    try
                    {
                        _logger.LogDebug("Attempting UPN lookup for email identifier: {Identifier}", identifier);
                        var upnResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{Uri.EscapeDataString(identifier)}");

                        if (upnResponse.IsSuccessStatusCode)
                        {
                            var userJson = await upnResponse.Content.ReadAsStringAsync();
                            var user = JsonSerializer.Deserialize<User>(userJson);
                            if (string.IsNullOrEmpty(user?.Id))
                            {
                                user.Id = identifier;
                            }
                            _logger.LogInformation("Found user via UPN lookup: {UserId}", user.Id);
                            return user;
                        }
                        else if (upnResponse.StatusCode != System.Net.HttpStatusCode.NotFound)
                        {
                            var errorContent = await upnResponse.Content.ReadAsStringAsync();
                            _logger.LogWarning("UPN lookup failed: {StatusCode} - {ErrorContent}", upnResponse.StatusCode, errorContent);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "UPN lookup failed for identifier: {Identifier}", identifier);
                    }

                    // Try email search with simpler, more reliable approach
                    try
                    {
                        _logger.LogDebug("Attempting email search with mail filter for identifier: {Identifier}", identifier);
                        // Use URL-encoded email in filter
                        var encodedEmail = Uri.EscapeDataString(identifier);
                        var mailFilterResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{encodedEmail}'&$top=1");

                        if (mailFilterResponse.IsSuccessStatusCode)
                        {
                            var jsonResponse = await mailFilterResponse.Content.ReadAsStringAsync();
                            var usersResponse = JsonSerializer.Deserialize<JsonElement>(jsonResponse);

                            if (usersResponse.TryGetProperty("value", out var usersArray) && usersArray.GetArrayLength() > 0)
                            {
                                var userJson = usersArray[0].GetRawText();
                                var user = JsonSerializer.Deserialize<User>(userJson);
                                if (string.IsNullOrEmpty(user?.Id) && usersArray[0].TryGetProperty("id", out var idProperty))
                                {
                                    user.Id = idProperty.GetString();
                                }
                                _logger.LogInformation("Found user via mail filter: {UserId}", user.Id);
                                return user;
                            }
                        }
                        else if (mailFilterResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                        {
                            _logger.LogWarning("403 Forbidden: Insufficient permissions for mail filter search. Delegated permissions may not support this query.");
                        }
                        else
                        {
                            var errorContent = await mailFilterResponse.Content.ReadAsStringAsync();
                            _logger.LogDebug("Mail filter search failed: {StatusCode} - {ErrorContent}", mailFilterResponse.StatusCode, errorContent);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Mail filter search failed for identifier: {Identifier}", identifier);
                    }

                    // Try alternative approach: get all users and filter locally (for small directories)
                    try
                    {
                        _logger.LogDebug("Attempting fallback: get all users and filter locally");
                        var allUsersResponse = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/users?$top=100");

                        if (allUsersResponse.IsSuccessStatusCode)
                        {
                            var jsonResponse = await allUsersResponse.Content.ReadAsStringAsync();
                            var usersResponse = JsonSerializer.Deserialize<JsonElement>(jsonResponse);

                            if (usersResponse.TryGetProperty("value", out var usersArray))
                            {
                                foreach (var userElement in usersArray.EnumerateArray())
                                {
                                    // Check mail property
                                    if (userElement.TryGetProperty("mail", out var mailProperty) &&
                                        mailProperty.GetString()?.Equals(identifier, StringComparison.OrdinalIgnoreCase) == true)
                                    {
                                        var userJson = userElement.GetRawText();
                                        var user = JsonSerializer.Deserialize<User>(userJson);
                                        if (string.IsNullOrEmpty(user?.Id) && userElement.TryGetProperty("id", out var idProperty))
                                        {
                                            user.Id = idProperty.GetString();
                                        }
                                        _logger.LogInformation("Found user via local mail filter: {UserId}", user.Id);
                                        return user;
                                    }

                                    // Check otherMails array
                                    if (userElement.TryGetProperty("otherMails", out var otherMailsProperty))
                                    {
                                        foreach (var otherMail in otherMailsProperty.EnumerateArray())
                                        {
                                            if (otherMail.GetString()?.Equals(identifier, StringComparison.OrdinalIgnoreCase) == true)
                                            {
                                                var userJson = userElement.GetRawText();
                                                var user = JsonSerializer.Deserialize<User>(userJson);
                                                if (string.IsNullOrEmpty(user?.Id) && userElement.TryGetProperty("id", out var idProperty))
                                                {
                                                    user.Id = idProperty.GetString();
                                                }
                                                _logger.LogInformation("Found user via local otherMails filter: {UserId}", user.Id);
                                                return user;
                                            }
                                        }
                                    }
                                }
                                _logger.LogDebug("No users found with matching email in local search");
                            }
                        }
                        else if (allUsersResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                        {
                            _logger.LogWarning("403 Forbidden: Insufficient permissions to list all users. Delegated permissions may not support this operation.");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Fallback user search failed for identifier: {Identifier}", identifier);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Email-based user search failed for identifier: {Identifier}", identifier);
                }
            }

            // If still not found and it looks like a GUID, try as object ID
            if (Guid.TryParse(identifier, out _))
            {
                try
                {
                    _logger.LogDebug("Attempting object ID lookup for identifier: {Identifier}", identifier);
                    var objectIdResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{identifier}");
                    _logger.LogDebug("Object ID lookup response status: {StatusCode}", objectIdResponse.StatusCode);

                    if (objectIdResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                    {
                        _logger.LogWarning("403 Forbidden: Insufficient permissions to access user by object ID. Check that User.Read.All permission has admin consent.");
                        return null;
                    }
                    else if (objectIdResponse.IsSuccessStatusCode)
                    {
                        var userJson = await objectIdResponse.Content.ReadAsStringAsync();
                        _logger.LogDebug("Object ID lookup response: {UserJson}", userJson);
                        var user = JsonSerializer.Deserialize<User>(userJson);
                        // Ensure user ID is set (should be the same as the identifier for object ID lookup)
                        if (string.IsNullOrEmpty(user?.Id))
                        {
                            user.Id = identifier;
                        }
                        _logger.LogInformation("Found user via object ID lookup: {UserId}", user.Id);
                        return user;
                    }
                    else
                    {
                        var errorContent = await objectIdResponse.Content.ReadAsStringAsync();
                        _logger.LogError("Object ID lookup failed: {StatusCode} - {ErrorContent}", objectIdResponse.StatusCode, errorContent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Object ID lookup failed for identifier: {Identifier}", identifier);
                }
            }

            _logger.LogWarning("User not found after all lookup attempts for identifier: {Identifier}", identifier);
            return null;
        }

        /// <summary>
        /// Get full user details from Azure AD using object ID
        /// </summary>
        /// <param name="objectId">User's object ID</param>
        /// <param name="accessToken">Access token for Microsoft Graph API</param>
        /// <returns>Full User object from Azure AD or null if not found</returns>
        private async Task<User> GetFullUserFromAzureAD(string objectId, string accessToken)
        {
            if (string.IsNullOrEmpty(objectId))
            {
                return null;
            }

            try
            {
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var response = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{objectId}");

                if (response.IsSuccessStatusCode)
                {
                    var userJson = await response.Content.ReadAsStringAsync();
                    // Log the raw response for debugging
                    _logger.LogDebug("Microsoft Graph response: {UserJson}", userJson);

                    // Use more flexible deserialization
                    var options = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true,
                        WriteIndented = true
                    };

                    try
                    {
                        var user = JsonSerializer.Deserialize<User>(userJson, options);
                        if (user != null && !string.IsNullOrEmpty(user.Id))
                        {
                            return user;
                        }
                        else
                        {
                            _logger.LogWarning("Deserialized user has null ID. Raw response: {UserJson}", userJson);
                            return null;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to deserialize user from Graph API. Response: {UserJson}", userJson);
                        return null;
                    }
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    _logger.LogWarning("403 Forbidden: Insufficient permissions to get full user details. Check that User.Read.All permission has admin consent.");
                    return null;
                }
                else if (response.StatusCode != System.Net.HttpStatusCode.NotFound)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Microsoft Graph error: {StatusCode} - {ErrorContent}", response.StatusCode, errorContent);
                    return null;
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting full user details from Azure AD for object ID: {ObjectId}", objectId);
                return null;
            }
        }
    }
}
