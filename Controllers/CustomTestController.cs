using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;
using Swashbuckle.AspNetCore.Annotations;
using System.Net.Http.Headers;
using System.Text.Json;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class CustomTestController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _config;
        private readonly ILogger<CustomTestController> _logger;

        public CustomTestController(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor, IConfiguration config, ILogger<CustomTestController> logger)
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
                var accessToken = GetAccessTokenFromRequest();
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Access token not found in Authorization header");
                }

                // Create HTTP client with user's token
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                User user = null;

                if (identifier.Contains("@"))
                {
                    // Search by email
                    var response = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')");
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var jsonResponse = await response.Content.ReadAsStringAsync();
                        var usersResponse = JsonSerializer.Deserialize<JsonElement>(jsonResponse);
                        
                        if (usersResponse.TryGetProperty("value", out var usersArray) && usersArray.GetArrayLength() > 0)
                        {
                            var userJson = usersArray[0].GetRawText();
                            user = JsonSerializer.Deserialize<User>(userJson);
                        }
                    }

                    // If not found by email filter, try direct access
                    if (user == null)
                    {
                        try
                        {
                            var directResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{identifier}");
                            if (directResponse.IsSuccessStatusCode)
                            {
                                var userJson = await directResponse.Content.ReadAsStringAsync();
                                user = JsonSerializer.Deserialize<User>(userJson);
                            }
                        }
                        catch
                        {
                            // Continue with user not found
                        }
                    }
                }
                else
                {
                    // Search by ID
                    var response = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{identifier}");
                    if (response.IsSuccessStatusCode)
                    {
                        var userJson = await response.Content.ReadAsStringAsync();
                        user = JsonSerializer.Deserialize<User>(userJson);
                    }
                }

                if (user == null)
                    return NotFound("User not found.");

                return Ok(user);
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

                // Get the access token from the authenticated user
                var accessToken = GetAccessTokenFromRequest();
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Access token not found in Authorization header");
                }

                // Find user ID first
                string userId = null;
                
                if (identifier.Contains("@"))
                {
                    // Get user ID by email
                    using var httpClient = _httpClientFactory.CreateClient();
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    
                    var response = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')");
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var jsonResponse = await response.Content.ReadAsStringAsync();
                        var usersResponse = JsonSerializer.Deserialize<JsonElement>(jsonResponse);
                        
                        if (usersResponse.TryGetProperty("value", out var usersArray) && usersArray.GetArrayLength() > 0)
                        {
                            if (usersArray[0].TryGetProperty("id", out var idProperty))
                            {
                                userId = idProperty.GetString();
                            }
                        }
                    }

                    // If not found by email filter, try direct access
                    if (string.IsNullOrEmpty(userId))
                    {
                        try
                        {
                            var directResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{identifier}");
                            if (directResponse.IsSuccessStatusCode)
                            {
                                var userJson = await directResponse.Content.ReadAsStringAsync();
                                var user = JsonSerializer.Deserialize<JsonElement>(userJson);
                                if (user.TryGetProperty("id", out var idProperty))
                                {
                                    userId = idProperty.GetString();
                                }
                            }
                        }
                        catch
                        {
                            // Continue with user not found
                        }
                    }
                }
                else
                {
                    userId = identifier;
                }

                if (string.IsNullOrEmpty(userId))
                    return NotFound("User not found.");

                // Update user using delegated permissions
                using var updateClient = _httpClientFactory.CreateClient();
                updateClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                
                var updateContent = new StringContent(JsonSerializer.Serialize(updates), System.Text.Encoding.UTF8, "application/json");
                var updateResponse = await updateClient.PatchAsync($"https://graph.microsoft.com/v1.0/users/{userId}", updateContent);

                if (updateResponse.IsSuccessStatusCode)
                {
                    return Ok($"User updated successfully.");
                }
                else
                {
                    var errorContent = await updateResponse.Content.ReadAsStringAsync();
                    try
                    {
                        var errorData = JsonSerializer.Deserialize<ODataError>(errorContent);
                        return BadRequest(errorData);
                    }
                    catch
                    {
                        return BadRequest($"Error updating user: {errorContent}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user with identifier: {Identifier}", identifier);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpDelete("deleteUserByIdentifier/v1.0")]
        [Authorize]
        [ProducesResponseType(200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Delete User by ID, UPN, or Email (Delegated Permissions)",
            Description = "Delete a user from Microsoft Graph API using delegated permissions. The authenticated user's token is used directly with Microsoft Graph API. ⚠️ This operation is permanent.",
            OperationId = "DeleteUserDelegated",
            Tags = new[] { "CustomTest" }
        )]
        [SwaggerResponse(200, "User deleted successfully")]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> DeleteUserByIdentifier(
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
                var accessToken = GetAccessTokenFromRequest();
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Access token not found in Authorization header");
                }

                // Find user ID first
                string userId = null;
                
                if (identifier.Contains("@"))
                {
                    // Get user ID by email
                    using var httpClient = _httpClientFactory.CreateClient();
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    
                    var response = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')");
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var jsonResponse = await response.Content.ReadAsStringAsync();
                        var usersResponse = JsonSerializer.Deserialize<JsonElement>(jsonResponse);
                        
                        if (usersResponse.TryGetProperty("value", out var usersArray) && usersArray.GetArrayLength() > 0)
                        {
                            if (usersArray[0].TryGetProperty("id", out var idProperty))
                            {
                                userId = idProperty.GetString();
                            }
                        }
                    }

                    // If not found by email filter, try direct access
                    if (string.IsNullOrEmpty(userId))
                    {
                        try
                        {
                            var directResponse = await httpClient.GetAsync($"https://graph.microsoft.com/v1.0/users/{identifier}");
                            if (directResponse.IsSuccessStatusCode)
                            {
                                var userJson = await directResponse.Content.ReadAsStringAsync();
                                var user = JsonSerializer.Deserialize<JsonElement>(userJson);
                                if (user.TryGetProperty("id", out var idProperty))
                                {
                                    userId = idProperty.GetString();
                                }
                            }
                        }
                        catch
                        {
                            // Continue with user not found
                        }
                    }
                }
                else
                {
                    userId = identifier;
                }

                if (string.IsNullOrEmpty(userId))
                    return NotFound("User not found.");

                // Delete user using delegated permissions
                using var deleteClient = _httpClientFactory.CreateClient();
                deleteClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                
                var deleteResponse = await deleteClient.DeleteAsync($"https://graph.microsoft.com/v1.0/users/{userId}");

                if (deleteResponse.IsSuccessStatusCode)
                {
                    return Ok($"User deleted successfully.");
                }
                else
                {
                    var errorContent = await deleteResponse.Content.ReadAsStringAsync();
                    try
                    {
                        var errorData = JsonSerializer.Deserialize<ODataError>(errorContent);
                        return BadRequest(errorData);
                    }
                    catch
                    {
                        return BadRequest($"Error deleting user: {errorContent}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user with identifier: {Identifier}", identifier);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        private string GetAccessTokenFromRequest()
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return null;
                }

                return authHeader.Substring("Bearer ".Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting access token from request");
                return null;
            }
        }
    }
}