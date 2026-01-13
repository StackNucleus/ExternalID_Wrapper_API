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
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Linq;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    // [Route("[controller]")]
    [Authorize]
    public class GraphPhoneAuthenticationController : ControllerBase
    {
        private readonly GraphServiceClient _graphServiceClient;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _config;
        private readonly ILogger<GraphPhoneAuthenticationController> _logger;

        public GraphPhoneAuthenticationController(GraphServiceClient graphServiceClient, IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor, IConfiguration config, ILogger<GraphPhoneAuthenticationController> logger)
        {
            _graphServiceClient = graphServiceClient;
            _httpClientFactory = httpClientFactory;
            _httpContextAccessor = httpContextAccessor;
            _config = config;
            _logger = logger;
        }

        [HttpGet("v1.0/getPhoneAuthenticationMethod")]
        [Authorize]
        [ProducesResponseType(typeof(List<PhoneAuthenticationMethodModel>), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Get Phone Authentication Methods",
            Description = "Retrieve phone authentication methods for a user from Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address. The system automatically detects the type of identifier provided.",
            OperationId = "GetPhoneAuthenticationMethod",
            Tags = new[] { "PhoneAuthentication" }
        )]
        [SwaggerResponse(200, "Phone authentication methods retrieved successfully", typeof(List<PhoneAuthenticationMethodModel>))]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> GetPhoneAuthenticationMethod(
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

                // Extract the delegated user from the token
                var userFromToken = TokenUtility.GetUserFromToken(TokenUtility.GetAccessTokenFromRequest(Request));
                if (userFromToken == null)
                {
                    return Unauthorized("Invalid or missing delegated token");
                }

                // Ensure the identifier matches the delegated user
                if (identifier != userFromToken.ObjectId &&
                    identifier != userFromToken.UserPrincipalName &&
                    identifier != userFromToken.Email)
                {
                    return Forbid("Access denied: Identifier does not match the delegated user");
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

                // Get phone authentication methods for the user
                var phoneMethods = await _graphServiceClient.Users[userId].Authentication.PhoneMethods
                    .GetAsync();

                if (phoneMethods?.Value == null || !phoneMethods.Value.Any())
                    return NotFound("No phone authentication methods found for this user.");

                // Convert Microsoft Graph models to custom models
                var customPhoneMethods = phoneMethods.Value.Select(pm => new PhoneAuthenticationMethodModel
                {
                    Id = pm.Id,
                    PhoneNumber = pm.PhoneNumber,
                    PhoneType = pm.PhoneType?.ToString(),
                    SmsSignInState = pm.SmsSignInState?.ToString()
                }).ToList();

                return Ok(customPhoneMethods);
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User or phone authentication methods not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost("v1.0/addPhoneAuthenticationMethod")]
        [Authorize]
        [ProducesResponseType(typeof(PhoneAuthenticationMethodModel), 201)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Add Phone Authentication Method",
            Description = "Add a new phone authentication method for a user in Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address. The system automatically detects the type of identifier provided.",
            OperationId = "AddPhoneAuthenticationMethod",
            Tags = new[] { "PhoneAuthentication" }
        )]
        [SwaggerResponse(201, "Phone authentication method added successfully", typeof(PhoneAuthenticationMethodModel))]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> AddPhoneAuthenticationMethod(
            [FromQuery]
            [SwaggerParameter("User Object ID, User Principal Name (UPN), or Email address", Required = true)]
            string identifier,
            [FromBody]
            [SwaggerParameter("Phone authentication method details", Required = true)]
            PhoneAuthenticationMethodCreationModel phoneAuthenticationMethod)
        {
            try
            {
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (phoneAuthenticationMethod == null || string.IsNullOrEmpty(phoneAuthenticationMethod.PhoneNumber))
                {
                    return BadRequest("Phone authentication method and phone number are required");
                }

                // Extract the delegated user from the token
                var userFromToken = TokenUtility.GetUserFromToken(TokenUtility.GetAccessTokenFromRequest(Request));
                if (userFromToken == null)
                {
                    return Unauthorized("Invalid or missing delegated token");
                }

                // Ensure the identifier matches the delegated user
                if (identifier != userFromToken.ObjectId &&
                    identifier != userFromToken.UserPrincipalName &&
                    identifier != userFromToken.Email)
                {
                    return Forbid("Access denied: Identifier does not match the delegated user");
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

                // Create the Microsoft Graph PhoneAuthenticationMethod object from our custom model
                var graphPhoneMethod = new PhoneAuthenticationMethod
                {
                    PhoneNumber = phoneAuthenticationMethod.PhoneNumber
                };

                // Only set PhoneType if provided
                if (!string.IsNullOrEmpty(phoneAuthenticationMethod.PhoneType))
                {
                    graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Mobile; // Default, will be updated based on input
                    
                    // Map the string value to the appropriate enum value
                    switch (phoneAuthenticationMethod.PhoneType.ToLowerInvariant())
                    {
                        case "mobile":
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Mobile;
                            break;
                        case "alternatemobile":
                        case "alternate_mobile":
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.AlternateMobile;
                            break;
                        case "office":
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Office;
                            break;
                        default:
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Mobile; // Default
                            break;
                    }
                }

                // Add phone authentication method for the user
                var newPhoneMethod = await _graphServiceClient.Users[userId].Authentication.PhoneMethods
                    .PostAsync(graphPhoneMethod);

                if (newPhoneMethod == null)
                    return StatusCode(500, "Failed to add phone authentication method.");

                // Convert the response to our custom model
                var customPhoneMethod = new PhoneAuthenticationMethodModel
                {
                    Id = newPhoneMethod.Id,
                    PhoneNumber = newPhoneMethod.PhoneNumber,
                    PhoneType = newPhoneMethod.PhoneType?.ToString(),
                    SmsSignInState = newPhoneMethod.SmsSignInState?.ToString()
                };

                return CreatedAtAction(nameof(GetPhoneAuthenticationMethod), new { identifier = identifier }, customPhoneMethod);
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

        [HttpPatch("v1.0/updatePhoneAuthenticationMethod")]
        [Authorize]
        [ProducesResponseType(typeof(PhoneAuthenticationMethodModel), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Update Phone Authentication Method",
            Description = "Update an existing phone authentication method for a user in Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address and the phone method ID. The system automatically detects the type of identifier provided.",
            OperationId = "UpdatePhoneAuthenticationMethod",
            Tags = new[] { "PhoneAuthentication" }
        )]
        [SwaggerResponse(200, "Phone authentication method updated successfully", typeof(PhoneAuthenticationMethodModel))]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User or phone authentication method not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> UpdatePhoneAuthenticationMethod(
            [FromQuery]
            [SwaggerParameter("User Object ID, User Principal Name (UPN), or Email address", Required = true)]
            string identifier,
            [FromQuery]
            [SwaggerParameter("Phone authentication method ID", Required = true)]
            string phoneMethodId,
            [FromBody]
            [SwaggerParameter("Updated phone authentication method details", Required = true)]
            PhoneAuthenticationMethodUpdateModel phoneAuthenticationMethod)
        {
            try
            {
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (string.IsNullOrEmpty(phoneMethodId))
                {
                    return BadRequest("Phone method ID parameter is required");
                }

                if (phoneAuthenticationMethod == null)
                {
                    return BadRequest("Phone authentication method data is required");
                }

                // Extract the delegated user from the token
                var userFromToken = TokenUtility.GetUserFromToken(TokenUtility.GetAccessTokenFromRequest(Request));
                if (userFromToken == null)
                {
                    return Unauthorized("Invalid or missing delegated token");
                }

                // Ensure the identifier matches the delegated user
                if (identifier != userFromToken.ObjectId &&
                    identifier != userFromToken.UserPrincipalName &&
                    identifier != userFromToken.Email)
                {
                    return Forbid("Access denied: Identifier does not match the delegated user");
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

                // Create the Microsoft Graph PhoneAuthenticationMethod object from our custom model
                var graphPhoneMethod = new PhoneAuthenticationMethod();

                if (!string.IsNullOrEmpty(phoneAuthenticationMethod.PhoneNumber))
                {
                    graphPhoneMethod.PhoneNumber = phoneAuthenticationMethod.PhoneNumber;
                }

                if (!string.IsNullOrEmpty(phoneAuthenticationMethod.PhoneType))
                {
                    // Map the string value to the appropriate enum value
                    switch (phoneAuthenticationMethod.PhoneType.ToLowerInvariant())
                    {
                        case "mobile":
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Mobile;
                            break;
                        case "alternatemobile":
                        case "alternate_mobile":
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.AlternateMobile;
                            break;
                        case "office":
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Office;
                            break;
                        default:
                            graphPhoneMethod.PhoneType = Microsoft.Graph.Models.AuthenticationPhoneType.Mobile; // Default
                            break;
                    }
                }

                // Update phone authentication method for the user
                await _graphServiceClient.Users[userId].Authentication.PhoneMethods[phoneMethodId]
                    .PatchAsync(graphPhoneMethod);

                // Retrieve the updated phone method to return
                var updatedPhoneMethod = await _graphServiceClient.Users[userId].Authentication.PhoneMethods[phoneMethodId]
                    .GetAsync();

                if (updatedPhoneMethod == null)
                    return NotFound("Phone authentication method not found after update.");

                // Convert the response to our custom model
                var customUpdatedPhoneMethod = new PhoneAuthenticationMethodModel
                {
                    Id = updatedPhoneMethod.Id,
                    PhoneNumber = updatedPhoneMethod.PhoneNumber,
                    PhoneType = updatedPhoneMethod.PhoneType?.ToString(),
                    SmsSignInState = updatedPhoneMethod.SmsSignInState?.ToString()
                };

                return Ok(customUpdatedPhoneMethod);
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User or phone authentication method not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpDelete("v1.0/deletePhoneAuthenticationMethod")]
        [Authorize]
        [ProducesResponseType(204)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Delete Phone Authentication Method",
            Description = "Delete an existing phone authentication method for a user in Microsoft Graph API using User Object ID, User Principal Name (UPN), or Email address and the phone method ID. The system automatically detects the type of identifier provided.",
            OperationId = "DeletePhoneAuthenticationMethod",
            Tags = new[] { "PhoneAuthentication" }
        )]
        [SwaggerResponse(204, "Phone authentication method deleted successfully")]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User or phone authentication method not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> DeletePhoneAuthenticationMethod(
            [FromQuery]
            [SwaggerParameter("User Object ID, User Principal Name (UPN), or Email address", Required = true)]
            string identifier,
            [FromQuery]
            [SwaggerParameter("Phone authentication method ID", Required = true)]
            string phoneMethodId)
        {
            try
            {
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (string.IsNullOrEmpty(phoneMethodId))
                {
                    return BadRequest("Phone method ID parameter is required");
                }

                // Extract the delegated user from the token
                var userFromToken = TokenUtility.GetUserFromToken(TokenUtility.GetAccessTokenFromRequest(Request));
                if (userFromToken == null)
                {
                    return Unauthorized("Invalid or missing delegated token");
                }

                // Ensure the identifier matches the delegated user
                if (identifier != userFromToken.ObjectId &&
                    identifier != userFromToken.UserPrincipalName &&
                    identifier != userFromToken.Email)
                {
                    return Forbid("Access denied: Identifier does not match the delegated user");
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

                // Delete phone authentication method for the user
                await _graphServiceClient.Users[userId].Authentication.PhoneMethods[phoneMethodId]
                    .DeleteAsync();

                return NoContent();
            }
            catch (ODataError odataError)
            {
                if (odataError.Error?.Code == "Request_ResourceNotFound" ||
                    odataError.Error?.Message?.Contains("does not exist") == true)
                {
                    return NotFound("User or phone authentication method not found.");
                }
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}