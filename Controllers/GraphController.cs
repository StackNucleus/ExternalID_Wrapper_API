using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;
using Swashbuckle.AspNetCore.Annotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class GraphController : ControllerBase
    {
        private readonly GraphServiceClient _graphServiceClient;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _config;
        private readonly ILogger<GraphController> _logger;

        public GraphController(GraphServiceClient graphServiceClient, IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor, IConfiguration config, ILogger<GraphController> logger)
        {
            _graphServiceClient = graphServiceClient;
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
            Summary = "Get User by ID, UPN, or Email",
            Description = "Retrieve user details from Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address. The system automatically detects the type of identifier provided.",
            OperationId = "GetUser",
            Tags = new[] { "Graph" }
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

                User user = null;

                if (identifier.Contains("@"))
                {
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    user = users?.Value?.FirstOrDefault();

                    if (user == null && identifier.Contains("@"))
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                        }
                    }
                }
                else
                {
                    user = await _graphServiceClient.Users[identifier].GetAsync();
                }

                if (user == null)
                    return NotFound("User not found.");

                return Ok(user);
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
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
            Summary = "Update User by ID, UPN, or Email",
            Description = "Update user attributes in Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address. The system automatically detects the type of identifier provided.",
            OperationId = "UpdateUser",
            Tags = new[] { "Graph" }
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

                string userId = null;

                if (identifier.Contains("@"))
                {
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    var user = users?.Value?.FirstOrDefault();

                    if (user == null)
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                        }
                    }

                    if (user == null)
                        return NotFound("User not found.");

                    userId = user.Id;
                }
                else
                {
                    userId = identifier;
                }

                var userUpdate = new User();
                foreach (var kvp in updates)
                {
                    userUpdate.AdditionalData[kvp.Key] = kvp.Value;
                }

                await _graphServiceClient.Users[userId].PatchAsync(userUpdate);

                return Ok($"User updated successfully.");
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPatch("updateUserAttributesByIdentifier/v1.0")]
        [Authorize]
        [ProducesResponseType(200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Update Specific User Attributes by ID, UPN, or Email",
            Description = "Update specific user attributes (firstName, lastName, displayName, etc.) using a structured model. Type-safe updates with validation. The system automatically detects the type of identifier provided.",
            OperationId = "UpdateUserAttributesByIdentifier",
            Tags = new[] { "Graph" }
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

                string userId = null;

                if (identifier.Contains("@"))
                {
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    var user = users?.Value?.FirstOrDefault();

                    if (user == null)
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                        }
                    }

                    if (user == null)
                        return NotFound("User not found.");

                    userId = user.Id;
                }
                else
                {
                    userId = identifier;
                }

                var userUpdate = new User();
                if (updates.firstName != null)
                    userUpdate.GivenName = updates.firstName;
                if (updates.lastName != null)
                    userUpdate.Surname = updates.lastName;
                if (updates.DisplayName != null)
                    userUpdate.DisplayName = updates.DisplayName;

                await _graphServiceClient.Users[userId].PatchAsync(userUpdate);

                return Ok($"User updated successfully.");
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
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
            Summary = "Delete User by ID, UPN, or Email",
            Description = "Delete a user from Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address. The system automatically detects the type of identifier provided. ⚠️ This operation is permanent.",
            OperationId = "DeleteUserByIdentifier",
            Tags = new[] { "Graph" }
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

                string userId = null;

                if (identifier.Contains("@"))
                {
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    var user = users?.Value?.FirstOrDefault();

                    if (user == null)
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                        }
                    }

                    if (user == null)
                        return NotFound("User not found.");

                    userId = user.Id;
                }
                else
                {
                    userId = identifier;
                }

                await _graphServiceClient.Users[userId].DeleteAsync();

                return Ok($"User deleted successfully.");
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        private async Task<string> GetAccessTokenAsync()
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    _logger.LogWarning("No Bearer token found in Authorization header");
                    return null;
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                return await GetMicrosoftGraphToken(jwtToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting access token");
                return null;
            }
        }

        private async Task<string> GetMicrosoftGraphToken(string jwtToken)
        {
            try
            {
                if (IsAzureAdToken(jwtToken))
                {
                    _logger.LogInformation("Using Azure AD token directly for Microsoft Graph");
                    return jwtToken;
                }

                _logger.LogInformation("Using client credentials flow to get Microsoft Graph token for custom JWT");
                
                var tenantId = _config["AzureAd:TenantId"];
                var clientId = _config["AzureAd:ClientId"];
                var clientSecret = _config["AzureAd:ClientSecret"];

                if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                {
                    _logger.LogError("Azure AD configuration is missing for client credentials flow");
                    return null;
                }

                using var client = _httpClientFactory.CreateClient();
                
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default")
                });

                var tokenResponse = await client.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", tokenRequest);
                
                if (tokenResponse.IsSuccessStatusCode)
                {
                    var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
                    var tokenData = JsonDocument.Parse(tokenContent);
                    return tokenData.RootElement.GetProperty("access_token").GetString();
                }
                else
                {
                    var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Failed to get Microsoft Graph token: {StatusCode} - {Error}", tokenResponse.StatusCode, errorContent);
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting Microsoft Graph token");
                return null;
            }
        }

        private bool IsAzureAdToken(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token) || token.Length < 100)
                    return false;

                var tokenHandler = new JwtSecurityTokenHandler();
                if (tokenHandler.CanReadToken(token))
                {
                    var jwtToken = tokenHandler.ReadJwtToken(token);
                    
                    var issuer = jwtToken.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
                    var audience = jwtToken.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;
                    
                    if (!string.IsNullOrEmpty(issuer) && 
                        (issuer.Contains("login.microsoftonline.com") || issuer.Contains("sts.windows.net")))
                    {
                        return true;
                    }
                    
                    if (!string.IsNullOrEmpty(audience) && 
                        audience.Contains("graph.microsoft.com"))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
