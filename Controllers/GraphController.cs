using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;
using Swashbuckle.AspNetCore.Annotations;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    //[ApiExplorerSettings(IgnoreApi = true)]
    public class GraphController : ControllerBase
    {


        private readonly GraphServiceClient _graphServiceClient;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _config;
        private readonly ILogger<GraphController> _logger;


        // This injects the GraphServiceClient into your controller
        public GraphController(GraphServiceClient graphServiceClient, IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor, IConfiguration config, ILogger<GraphController> logger)
        {
            _graphServiceClient = graphServiceClient;
            _httpClientFactory = httpClientFactory;
            _httpContextAccessor = httpContextAccessor;
            _config = config;
            _logger = logger;
        }



        [HttpGet("Readme-Instructuons-API-Endpoints")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult GetReadme()
        {
            var readme = System.IO.File.ReadAllText("README.md");
            return Content(readme, "text/markdown");
        }

        [HttpGet("me")]
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult GetCurrentUser()
        {
            try
            {
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                var username = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
                var scope = User.FindFirst("scope")?.Value;

                return Ok(new
                {
                    UserId = userId,
                    Username = username,
                    Scope = scope,
                    IsAuthenticated = User.Identity.IsAuthenticated,
                    Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"Error getting current user: {ex.Message}");
            }
        }

        [HttpPost("invite")]
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]

        public async Task<IActionResult> InviteUser(string email)
        {
            var invitation = new Invitation
            {
                InvitedUserEmailAddress = email,
                InviteRedirectUrl = "https://localhost:7110/", // This URL needs to be one of the redirect URIs registered in your app registration
                SendInvitationMessage = true,
                InvitedUserMessageInfo = new InvitedUserMessageInfo
                {
                    CustomizedMessageBody = "Hello! You've been invited to collaborate with us. Please accept the invitation to get started."
                }
            };

            try
            {
                // This line calls the Graph API behind the scenes
                var result = await _graphServiceClient.Invitations.PostAsync(invitation);
                return Ok(result);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }



        // [HttpGet("Get_User-by-userobjID")]
        [HttpGet("getUserById")]
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> GetUser([FromQuery] string idOrEmail)
        {
            try
            {
                // This line calls the Graph API to get user details
                var user = await _graphServiceClient.Users[idOrEmail].GetAsync();
                return Ok(user);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        [HttpGet("getUserByIdentifier")] // (Identifier => Eg :- User Object ID (UID) / User Principal Name (UPN) / Email )
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
                // Validate input
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                User user = null;

                // Determine the type of identifier and call appropriate method
                if (identifier.Contains("@"))
                {
                    // This looks like an email or UPN, try to find user by email first
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    user = users?.Value?.FirstOrDefault();

                    // If not found by email and it looks like a UPN, try direct UPN lookup
                    if (user == null && identifier.Contains("@"))
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                            // User not found by UPN either, will return 404 below
                        }
                    }
                }
                else
                {
                    // This looks like a user object ID
                    user = await _graphServiceClient.Users[identifier].GetAsync();
                }

                if (user == null)
                    return NotFound("User not found.");

                return Ok(user);
            }
            catch (ODataError odataError)
            {
                // Check if the error is because user was not found
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

        [HttpGet("getUserByUpn")]
        [Authorize]
        [ProducesResponseType(typeof(object), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Get User by User Principal Name (UPN)",
            Description = "Retrieve user details from Microsoft Graph API using User Principal Name (UPN). Supports all token types (Custom JWT, Azure AD).",
            OperationId = "GetUserByUpn",
            Tags = new[] { "Graph" }
        )]
        [SwaggerResponse(200, "User details retrieved successfully", typeof(object))]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> GetUserByUpn(
            [FromQuery]
            [SwaggerParameter("User Principal Name (UPN) of the user to retrieve", Required = true)]
            string upn)
        {
            try
            {
                // Use GraphServiceClient to get user by UPN
                // Microsoft Graph supports querying users directly by UPN using the user ID parameter
                var user = await _graphServiceClient.Users[upn].GetAsync();
                return Ok(user);
            }
            catch (ODataError odataError)
            {
                // Check if the error is because user was not found
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

        // [HttpGet("Get_User/by-email")]
        [HttpGet("getUserByEmail")]
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> GetUserByEmail([FromQuery] string email)
        {
            try
            {
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                return Ok(user);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        [HttpGet("getUserDetails(Default: displayName,givenName,identities)")]
        [Authorize]
        [ProducesResponseType(typeof(UserDetailResponse), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Get User Details with Specific Fields",
            Description = "Retrieve specific user details from Microsoft Graph API beta endpoint. Returns displayName, givenName, and identities by default. Supports custom field selection using OData $select parameter.",
            OperationId = "GetUserDetails",
            Tags = new[] { "Graph" }
        )]
        [SwaggerResponse(200, "User details retrieved successfully", typeof(UserDetailResponse))]
        [SwaggerResponse(401, "Unauthorized - Bearer token required")]
        [SwaggerResponse(404, "User not found")]
        [SwaggerResponse(500, "Internal server error")]
        public async Task<IActionResult> GetUserDetails(
            [FromQuery] 
            [SwaggerParameter("User ID or email address", Required = true)] 
            string idOrEmail, 
            [FromQuery] 
            [SwaggerParameter("OData select fields (default: displayName,givenName,identities)", Required = false)] 
            string? select = null)
        {
            try
            {
                // Use HttpClient to make direct calls to Microsoft Graph beta API for accessing identities
                var accessToken = await GetAccessTokenAsync();
                if (string.IsNullOrEmpty(accessToken))
                {
                    return Unauthorized("Failed to obtain access token for Microsoft Graph.");
                }

                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                // Default select parameters if not provided
                var selectFields = select ?? "displayName,givenName,identities";
                
                string userId;
                
                // Check if the input looks like an email address
                if (idOrEmail.Contains("@"))
                {
                    // First, find the user by email using filter
                    var filterUrl = $"https://graph.microsoft.com/beta/users?$filter=mail eq '{idOrEmail}' or otherMails/any(x:x eq '{idOrEmail}')&$select=id";
                    
                    var filterResponse = await client.GetAsync(filterUrl);
                    
                    if (!filterResponse.IsSuccessStatusCode)
                    {
                        var errorContent = await filterResponse.Content.ReadAsStringAsync();
                        return StatusCode((int)filterResponse.StatusCode, $"Microsoft Graph API error during user lookup: {errorContent}");
                    }
                    
                    var filterContent = await filterResponse.Content.ReadAsStringAsync();
                    var filterData = JsonDocument.Parse(filterContent);
                    var users = filterData.RootElement.GetProperty("value");
                    
                    if (users.GetArrayLength() == 0)
                    {
                        return NotFound("User not found.");
                    }
                    
                    // Get the user ID from the first result
                    userId = users[0].GetProperty("id").GetString();
                }
                else
                {
                    // Assume it's already a user ID
                    userId = idOrEmail;
                }
                
                // Now get the user details with the specified fields
                var url = $"https://graph.microsoft.com/beta/users/{userId}?$select={selectFields}";

                var response = await client.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var userData = JsonConvert.DeserializeObject<UserDetailResponse>(content);
                    return Ok(userData);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Microsoft Graph API error: {errorContent}");
                }
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }




        // [HttpPatch("Update_User-by-userobjID")]
        //[HttpPatch("updateUserById")]
        //[Authorize]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> UpdateUser([FromQuery] string idOrEmail, [FromBody] Dictionary<string, object> updates)
        //{
        //    try
        //    {
        //        var user = new User();
        //        foreach (var kvp in updates)
        //        {
        //            user.AdditionalData[kvp.Key] = kvp.Value;
        //        }

        //        // This line calls the Graph API to update a user
        //        await _graphServiceClient.Users[idOrEmail].PatchAsync(user);

        //        return Ok("User Updated Successfully.");

        //        // Fetch the updated user object
        //        //var updatedUser = await _graphServiceClient.Users[idOrEmail].GetAsync();
        //        //return Ok(updatedUser);
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}

        [HttpPatch("updateUserByIdentifier")] // (Identifier => Eg :- User Object ID (UID) / User Principal Name (UPN) / Email )
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
                // Validate input
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (updates == null || updates.Count == 0)
                {
                    return BadRequest("Update data is required");
                }

                string userId = null;

                // Determine the type of identifier and get the user ID
                if (identifier.Contains("@"))
                {
                    // This looks like an email or UPN, try to find user by email first
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    var user = users?.Value?.FirstOrDefault();

                    // If not found by email and it looks like a UPN, try direct UPN lookup
                    if (user == null)
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                            // User not found by UPN either
                        }
                    }

                    if (user == null)
                        return NotFound("User not found.");

                    userId = user.Id;
                }
                else
                {
                    // This looks like a user object ID
                    userId = identifier;
                }

                // Create user object with updates
                var userUpdate = new User();
                foreach (var kvp in updates)
                {
                    userUpdate.AdditionalData[kvp.Key] = kvp.Value;
                }

                // Update the user
                await _graphServiceClient.Users[userId].PatchAsync(userUpdate);

                return Ok($"User updated successfully.");
            }
            catch (ODataError odataError)
            {
                // Check if the error is because user was not found
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




        //[HttpPatch("updateUserByEmail")]
        //[Authorize]
        //public async Task<IActionResult> UpdateUserByEmail([FromQuery] string email, [FromBody] Dictionary<string, object> updates)
        //{
        //    try
        //    {
        //        // Find the user by email
        //        var users = await _graphServiceClient.Users
        //            .GetAsync(requestConfig =>
        //            {
        //                requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
        //            });

        //        var user = users?.Value?.FirstOrDefault();
        //        if (user == null)
        //            return NotFound("User not found.");

        //        var userUpdate = new User();
        //        foreach (var kvp in updates)
        //        {
        //            userUpdate.AdditionalData[kvp.Key] = kvp.Value;
        //        }

        //        await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

        //        return Ok($"User with email '{email}' updated successfully.");
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}




        // [HttpPatch("UpdateUserLimitedAttributes-userobjID")]
        //[HttpPatch("updateUserAttributesById")]
        //[Authorize]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> UpdateUserLimitedAttributes([FromQuery] string idOrEmail, [FromBody] UserUpdateModel updates)
        //{
        //    try
        //    {
        //        var user = new User();
        //        if(updates.firstName != null)
        //            user.GivenName = updates.firstName;
        //        if (updates.lastName != null)
        //            user.Surname = updates.lastName;
        //        if (updates.DisplayName != null)
        //            user.DisplayName = updates.DisplayName; // updates.firstName + " " + updates.lastName; // updates.DisplayName;
        //        //if (updates.JobTitle != null)
        //        //    user.JobTitle = updates.JobTitle;
        //        //if (updates.Department != null)
        //        //    user.Department = updates.Department;
        //        // Add other fields as needed

        //        await _graphServiceClient.Users[idOrEmail].PatchAsync(user);

        //        return Ok("User Updated with Limited Attributes");
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}


        [HttpPatch("updateUserAttributesByIdentifier")] // (Identifier => Eg :- User Object ID (UID) / User Principal Name (UPN) / Email )
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
                // Validate input
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                if (updates == null)
                {
                    return BadRequest("Update data is required");
                }

                string userId = null;

                // Determine the type of identifier and get the user ID
                if (identifier.Contains("@"))
                {
                    // This looks like an email or UPN, try to find user by email first
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    var user = users?.Value?.FirstOrDefault();

                    // If not found by email and it looks like a UPN, try direct UPN lookup
                    if (user == null)
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                            // User not found by UPN either
                        }
                    }

                    if (user == null)
                        return NotFound("User not found.");

                    userId = user.Id;
                }
                else
                {
                    // This looks like a user object ID
                    userId = identifier;
                }

                // Create user object with updates
                var userUpdate = new User();
                if (updates.firstName != null)
                    userUpdate.GivenName = updates.firstName;
                if (updates.lastName != null)
                    userUpdate.Surname = updates.lastName;
                if (updates.DisplayName != null)
                    userUpdate.DisplayName = updates.DisplayName;

                // Update the user
                await _graphServiceClient.Users[userId].PatchAsync(userUpdate);

                return Ok($"User updated successfully.");
            }
            catch (ODataError odataError)
            {
                // Check if the error is because user was not found
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


        [HttpPatch("updateUserAttributesByEmail")]
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> UpdateUserAttributesByEmail([FromQuery] string email, [FromBody] UserUpdateModel updates)
        {
            try
            {
                // Find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                var userUpdate = new User();
                if (updates.firstName != null)
                    userUpdate.GivenName = updates.firstName;
                if (updates.lastName != null)
                    userUpdate.Surname = updates.lastName;
                if (updates.DisplayName != null)
                    userUpdate.DisplayName = updates.DisplayName; // updates.firstName + " " + updates.lastName; // updates.DisplayName;
                //if (updates.JobTitle != null)
                //    userUpdate.JobTitle = updates.JobTitle;
                //if (updates.Department != null)
                //    userUpdate.Department = updates.Department;
                // Add other fields as needed

                await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

                return Ok($"User with email '{email}' updated with limited attributes.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        // [HttpDelete("Delete_User-by-userobjID")]
        //[HttpDelete("deleteUserById")]
        //[Authorize]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> DeleteUser([FromQuery] string idOrEmail)
        //{
        //    try
        //    {
        //        // This line calls the Graph API to delete a user
        //        await _graphServiceClient.Users[idOrEmail].DeleteAsync();
        //        return Ok("User deleted successfully.");
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}

        [HttpDelete("deleteUserByIdentifier")] // (Identifier => Eg :- User Object ID (UID) / User Principal Name (UPN) / Email )
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
                // Validate input
                if (string.IsNullOrEmpty(identifier))
                {
                    return BadRequest("Identifier parameter is required");
                }

                string userId = null;

                // Determine the type of identifier and get the user ID
                if (identifier.Contains("@"))
                {
                    // This looks like an email or UPN, try to find user by email first
                    var users = await _graphServiceClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{identifier}' or otherMails/any(x:x eq '{identifier}')";
                        });

                    var user = users?.Value?.FirstOrDefault();

                    // If not found by email and it looks like a UPN, try direct UPN lookup
                    if (user == null)
                    {
                        try
                        {
                            user = await _graphServiceClient.Users[identifier].GetAsync();
                        }
                        catch (ODataError)
                        {
                            // User not found by UPN either
                        }
                    }

                    if (user == null)
                        return NotFound("User not found.");

                    userId = user.Id;
                }
                else
                {
                    // This looks like a user object ID
                    userId = identifier;
                }

                // Delete the user
                await _graphServiceClient.Users[userId].DeleteAsync();

                return Ok($"User deleted successfully.");
            }
            catch (ODataError odataError)
            {
                // Check if the error is because user was not found
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

        // [HttpDelete("Delete_User-by-email")]
        [HttpDelete("deleteUserByEmail")]
        [Authorize]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> DeleteUserByEmail([FromQuery] string email)
        {
            try
            {
                // First, find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                // Delete the user using their ID
                await _graphServiceClient.Users[user.Id].DeleteAsync();
                return Ok($"User with email '{email}' deleted successfully.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        //[HttpPost("changePassword")]
        //[Authorize]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        //{
        //    var accessToken = await GetAccessTokenAsync();
        //    if (string.IsNullOrEmpty(accessToken))
        //        return Unauthorized();

        //    var client = _httpClientFactory.CreateClient();
        //    var request = new HttpRequestMessage(HttpMethod.Post, "https://graph.microsoft.com/v1.0/me/changePassword");
        //    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        //    request.Content = new StringContent(JsonConvert.SerializeObject(new
        //    {
        //        currentPassword = model.CurrentPassword,
        //        newPassword = model.NewPassword
        //    }), Encoding.UTF8, "application/json");

        //    var response = await client.SendAsync(request);
        //    if (response.StatusCode == HttpStatusCode.NoContent)
        //        return NoContent();

        //    var error = await response.Content.ReadAsStringAsync();
        //    return StatusCode((int)response.StatusCode, error);
        //}

        //[HttpPatch("resetPasswordById")]
        //[Authorize]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> ResetPasswordById([FromQuery] string idOrEmail, [FromBody] ResetPasswordModel model)
        //{
        //    try
        //    {
        //        var user = new User
        //        {
        //            PasswordProfile = new PasswordProfile
        //            {
        //                Password = model.NewPassword,
        //                ForceChangePasswordNextSignIn = false, // model.ForceChangePasswordNextSignIn,
        //                ForceChangePasswordNextSignInWithMfa = false // model.ForceChangePasswordNextSignInWithMfa
        //            }
        //        };

        //        // This line calls the Graph API to update the user's password profile
        //        await _graphServiceClient.Users[idOrEmail].PatchAsync(user);

        //        return Ok($"Password reset successfully for user {idOrEmail}. User will not be required to change password on next sign-in"); // : {model.ForceChangePasswordNextSignIn}
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}

        //[HttpPatch("resetPasswordByEmail")]
        //[Authorize]
        //public async Task<IActionResult> ResetPasswordByEmail([FromQuery] string email, [FromBody] ResetPasswordModel model)
        //{
        //    try
        //    {
        //        // First, find the user by email and get their identities
        //        var users = await _graphServiceClient.Users
        //            .GetAsync(requestConfig =>
        //            {
        //                requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
        //                requestConfig.QueryParameters.Select = new[] { "id", "userPrincipalName", "identities" };
        //            });

        //        var user = users?.Value?.FirstOrDefault();
        //        if (user == null)
        //            return NotFound("User not found.");

        //        // Check if user is using social IDP based on identities issuer
        //        if (user.Identities != null && user.Identities.Any())
        //        {
        //            foreach (var identity in user.Identities)
        //            {
        //                // if (identity.Issuer != null)
        //                if (identity.Issuer != null && identity.Issuer != "volvogroupextiddev.onmicrosoft.com" && identity.SignInType != null)
        //                {
        //                    // Check if the issuer indicates a social IDP
        //                    var issuer = identity.Issuer.ToLowerInvariant();
                            
        //                    // Common social IDP issuers
        //                    if (issuer.Contains("google.com") ||
        //                        issuer.Contains("facebook.com") ||
        //                        issuer.Contains("microsoft.com") ||
        //                        issuer.Contains("live.com") ||
        //                        issuer.Contains("outlook.com") ||
        //                        issuer.Contains("twitter.com") ||
        //                        issuer.Contains("linkedin.com") ||
        //                        issuer.Contains("github.com") ||
        //                        issuer.Contains("apple.com") ||
        //                        issuer.Contains("amazon.com") ||
        //                        // Check for federated/external issuers (not your tenant domain)
        //                        (!issuer.Contains(".onmicrosoft.com") && identity.SignInType != "userPrincipalName"))
        //                    {
        //                        return BadRequest(new
        //                        {
        //                            error = "Password reset not supported for social identity provider accounts",
        //                            message = $"This account uses a social identity provider ('{identity.Issuer}'). Password changes must be performed through the original identity provider.",
        //                            signInType = identity.SignInType,
        //                            issuer = identity.Issuer,
        //                            suggestion = "Please contact your identity provider to change your password."
        //                        });
        //                    }
        //                }
        //            }
        //        }

        //        var userUpdate = new User
        //        {
        //            PasswordProfile = new PasswordProfile
        //            {
        //                Password = model.NewPassword,
        //                ForceChangePasswordNextSignIn = false, // model.ForceChangePasswordNextSignIn,
        //                ForceChangePasswordNextSignInWithMfa = false // model.ForceChangePasswordNextSignInWithMfa
        //            }
        //        };

        //        // Update the user's password profile using their ID
        //        await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

        //        return Ok($"Password reset successfully for user with email '{email}'. User will not be required to change password on next sign-in"); // : {model.ForceChangePasswordNextSignIn}
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}

        //[HttpGet("users/{id}/authentication/methods")]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> GetUserAuthenticationMethods(string id)
        //{
        //    try
        //    {
        //        // Get authentication methods from Microsoft Graph
        //        var methods = await _graphServiceClient.Users[id]
        //            .Authentication
        //            .Methods
        //            .GetAsync();

        //        return Ok(methods);
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.LogError(ex, "Error getting authentication methods for user {UserId}", id);
        //        return StatusCode(500, "Internal server error");
        //    }
        //}


       // [HttpGet("users/{idOrEmail}/authentication/methods")]
       // [ApiExplorerSettings(IgnoreApi = true)]
        // [HttpGet("users/{identifier}/auth-methods")]
        // [HttpGet("users/email/{email}/auth-methods")]
        //public async Task<IActionResult> GetUserAuthenticationMethodsByIdorEmail(string idOrEmail)
        //{
        //    try
        //    {
        //        // First try to get user by ID
        //        try
        //        {
        //            var methods = await _graphServiceClient.Users[idOrEmail]
        //                .Authentication
        //                .Methods
        //                .GetAsync();
        //            return Ok(methods);
        //        }
        //        catch (ODataError)
        //        {
        //            // If ID fails, try email lookup
        //            var users = await _graphServiceClient.Users
        //                .GetAsync(requestConfig =>
        //                {
        //                    requestConfig.QueryParameters.Filter =
        //                        $"mail eq '{idOrEmail}' or otherMails/any(x:x eq '{idOrEmail}')";
        //                });

        //            var user = users?.Value?.FirstOrDefault();
        //            if (user == null)
        //                return NotFound("User not found");

        //            var methods = await _graphServiceClient.Users[user.Id]
        //                .Authentication
        //                .Methods
        //                .GetAsync();

        //            return Ok(methods);
        //        }
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.LogError(ex, "Error getting authentication methods for user {UserIdentifier}", idOrEmail);
        //        return StatusCode(500, "Internal server error");
        //    }
        //}

        //[HttpPost("requestPasswordReset(SSPR-likeInAzure")]
        //[AllowAnonymous]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> RequestPasswordReset([FromBody] RequestPasswordResetModel model)
        //{
        //    try
        //    {
        //        // First, verify the user exists
        //        var users = await _graphServiceClient.Users
        //            .GetAsync(requestConfig =>
        //            {
        //                requestConfig.QueryParameters.Filter = $"mail eq '{model.Email}' or otherMails/any(x:x eq '{model.Email}')";
        //            });

        //        var user = users?.Value?.FirstOrDefault();
        //        if (user == null)
        //        {
        //            // Don't reveal if user exists or not for security
        //            return Ok("If the email address exists in our system, a verification code has been sent.");
        //        }

        //        // Generate a verification code (6 digits)
        //        var verificationCode = GenerateVerificationCode();
                
        //        // Store the verification code with expiration (you might want to use a database or cache)
        //        // For demo purposes, we'll use a simple in-memory storage
        //        StoreVerificationCode(model.Email, verificationCode);

        //        // Send email with verification code
        //        // Note: In a real implementation, you would integrate with an email service
        //        // For now, we'll just return the code in the response for testing
        //        await SendVerificationEmail(model.Email, verificationCode);

        //        return Ok(new
        //        {
        //            message = "If the email address exists in our system, a verification code has been sent.",
        //            verificationCode = verificationCode, // Remove this in production
        //            expiresIn = "15 minutes"
        //        });
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}

        //[HttpPost("completePasswordReset(SSPR-likeInAzure)")]
        //[AllowAnonymous]
        //[ApiExplorerSettings(IgnoreApi = true)]
        //public async Task<IActionResult> CompletePasswordReset([FromBody] SelfServicePasswordResetModel model)
        //{
        //    try
        //    {
        //        // Verify the verification code
        //        if (!ValidateVerificationCode(model.Email, model.VerificationCode))
        //        {
        //            return BadRequest("Invalid or expired verification code.");
        //        }

        //        // Find the user by email
        //        var users = await _graphServiceClient.Users
        //            .GetAsync(requestConfig =>
        //            {
        //                requestConfig.QueryParameters.Filter = $"mail eq '{model.Email}' or otherMails/any(x:x eq '{model.Email}')";
        //            });

        //        var user = users?.Value?.FirstOrDefault();
        //        if (user == null)
        //        {
        //            return NotFound("User not found.");
        //        }

        //        // Update the user's password profile
        //        var userUpdate = new User
        //        {
        //            PasswordProfile = new PasswordProfile
        //            {
        //                Password = model.NewPassword,
        //                ForceChangePasswordNextSignIn = model.ForceChangePasswordNextSignIn,
        //                ForceChangePasswordNextSignInWithMfa = model.ForceChangePasswordNextSignInWithMfa
        //            }
        //        };

        //        await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

        //        // Clear the verification code after successful reset
        //        ClearVerificationCode(model.Email);

        //        return Ok(new
        //        {
        //            message = "Password reset successfully. You can now log in with your new password.",
        //            forceChangePasswordNextSignIn = model.ForceChangePasswordNextSignIn
        //        });
        //    }
        //    catch (ODataError odataError)
        //    {
        //        return BadRequest(odataError.Error);
        //    }
        //}

        private string GenerateVerificationCode()
        {
            // Generate a 6-digit verification code
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        private void StoreVerificationCode(string email, string code)
        {
            // In a real implementation, store this in a database or cache with expiration
            // For demo purposes, we'll use a simple dictionary
            // Note: This is not thread-safe and will be lost on app restart
            if (_verificationCodes == null)
                _verificationCodes = new Dictionary<string, (string code, DateTime expires)>();

            _verificationCodes[email.ToLower()] = (code, DateTime.UtcNow.AddMinutes(15));
        }

        private bool ValidateVerificationCode(string email, string code)
        {
            if (_verificationCodes == null)
                return false;

            var emailKey = email.ToLower();
            if (!_verificationCodes.ContainsKey(emailKey))
                return false;

            var (storedCode, expires) = _verificationCodes[emailKey];
            
            // Check if code has expired
            if (DateTime.UtcNow > expires)
            {
                _verificationCodes.Remove(emailKey);
                return false;
            }

            // Check if code matches
            return storedCode == code;
        }

        private void ClearVerificationCode(string email)
        {
            if (_verificationCodes != null)
            {
                _verificationCodes.Remove(email.ToLower());
            }
        }

        private async Task SendVerificationEmail(string email, string code)
        {
            // In a real implementation, integrate with an email service like:
            // - SendGrid
            // - Mailgun
            // - Azure Communication Services
            // - SMTP server
            
            // For demo purposes, we'll just log the email
            // In production, replace this with actual email sending logic
            var emailContent = $@"
                Password Reset Verification Code
                
                Your verification code is: {code}
                
                This code will expire in 15 minutes.
                
                If you didn't request this password reset, please ignore this email.
            ";

            // Log the email content (remove this in production)
            Console.WriteLine($"Email to {email}: {emailContent}");
            
            await Task.CompletedTask; // Simulate async email sending
        }

        // In-memory storage for verification codes (replace with database/cache in production)
        private static Dictionary<string, (string code, DateTime expires)> _verificationCodes;

        private async Task<string> GetAccessTokenAsync()
        {
            try
            {
                // Get the JWT token from the Authorization header
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
                // First, try to validate if this is an Azure AD token by checking its format
                if (IsAzureAdToken(jwtToken))
                {
                    // If it's an Azure AD token, use it directly
                    _logger.LogInformation("Using Azure AD token directly for Microsoft Graph");
                    return jwtToken;
                }

                // If it's a custom JWT token, we need to exchange it for an Azure AD token
                // Since we don't have user credentials, we'll use client credentials flow
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
                
                // Use client credentials flow to get Microsoft Graph token
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
                // Azure AD tokens are typically longer than custom JWT tokens
                // and contain specific claims that indicate they're from Azure AD
                if (string.IsNullOrEmpty(token) || token.Length < 100)
                    return false;

                // Try to decode the JWT to check for Azure AD specific claims
                var tokenHandler = new JwtSecurityTokenHandler();
                if (tokenHandler.CanReadToken(token))
                {
                    var jwtToken = tokenHandler.ReadJwtToken(token);
                    
                    // Check for Azure AD specific claims
                    var issuer = jwtToken.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
                    var audience = jwtToken.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;
                    
                    // Azure AD tokens typically have these characteristics:
                    // - Issuer contains "login.microsoftonline.com" or "sts.windows.net"
                    // - Audience contains "https://graph.microsoft.com" or similar
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
                // If we can't parse the token, assume it's not an Azure AD token
                return false;
            }
        }

        

        

    }
} 
