using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<TokenController> _logger;
        private readonly HttpClient _httpClient;

        public TokenController(IConfiguration config, ILogger<TokenController> logger, HttpClient httpClient)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient;
        }

        /// <summary>
        /// Generate Azure AD token for Microsoft Graph API access using client credentials flow
        /// This token can be used for both GraphController and DGraphController
        /// Supports custom expiration time control for manual token refresh cycles
        /// </summary>
        /// <param name="request">Azure AD client credentials request with optional custom expiration</param>
        /// <returns>Azure AD access token response with enhanced expiration information</returns>
        [HttpPost("getAAD-Token/v1.0")]
        // [HttpPost("azure-ad-Token_Generation")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AzureAdTokenResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Generate Azure AD Token (Client Credentials)",
            Description = "Generate an Azure AD token using client credentials flow with optional custom expiration time control. " +
                         "This token works with GraphC endpoints. " +
                         "The custom expiration setting helps you manage when to manually refresh tokens.",
            OperationId = "GenerateAzureAdToken",
            Tags = new[] { "Token" }
        )]
        public async Task<IActionResult> GetAzureAdToken([FromBody] AzureAdClientCredentialsRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(request.client_id))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
                }

                if (string.IsNullOrEmpty(request.client_secret))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_secret is required" });
                }

                // Validate and set custom expiration time (default: 60 minutes, max: 1440 minutes = 24 hours)
                var customExpirationMinutes = request.expires_in_minutes ?? 60;
                if (customExpirationMinutes < 1 || customExpirationMinutes > 1440)
                {
                    return BadRequest(new {
                        error = "invalid_request",
                        error_description = "expires_in_minutes must be between 1 and 1440 (24 hours)"
                    });
                }

                // Get Azure AD tenant configuration
                var tenantId = _config["AzureAd:TenantId"];
                if (string.IsNullOrEmpty(tenantId))
                {
                    return StatusCode(500, new { error = "configuration_error", error_description = "Azure AD tenant configuration is missing" });
                }

                // Use the scope provided by user or default to Microsoft Graph
                var scope = request.scope ?? "https://graph.microsoft.com/.default";

                // Create token request using client credentials flow
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", request.client_id),
                    new KeyValuePair<string, string>("client_secret", request.client_secret),
                    new KeyValuePair<string, string>("scope", scope)
                });

                // Request token from Azure AD
                var tokenResponse = await _httpClient.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", tokenRequest);

                if (tokenResponse.IsSuccessStatusCode)
                {
                    var responseContent = await tokenResponse.Content.ReadAsStringAsync();
                    var tokenData = JsonSerializer.Deserialize<AzureAdTokenResponse>(responseContent);

                    // Enhance response with custom expiration information
                    var issuedAt = DateTime.UtcNow;
                    var azureExpiresAt = issuedAt.AddSeconds(tokenData.expires_in);
                    var customExpiresAt = issuedAt.AddMinutes(customExpirationMinutes);

                    tokenData.issued_at = issuedAt;
                    tokenData.expires_at = azureExpiresAt;
                    tokenData.expires_in_human = FormatTimespan(TimeSpan.FromSeconds(tokenData.expires_in));
                    tokenData.custom_expires_in_minutes = customExpirationMinutes;
                    tokenData.custom_expires_at = customExpiresAt;
                    tokenData.token_refresh_guidance = customExpirationMinutes < (tokenData.expires_in / 60)
                        ? $"Recommended to refresh token after {customExpirationMinutes} minutes for security"
                        : $"Token will expire from Azure AD in {tokenData.expires_in / 60} minutes, refresh before then";

                    return Ok(tokenData);
                }
                else
                {
                    var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                    _logger.LogError($"Azure AD token request failed: {tokenResponse.StatusCode} - {errorContent}");

                    // Try to parse error response
                    try
                    {
                        var errorData = JsonSerializer.Deserialize<AzureAdErrorResponse>(errorContent);
                        return BadRequest(errorData);
                    }
                    catch
                    {
                        return BadRequest(new { error = "azure_ad_error", error_description = $"Azure AD token request failed: {errorContent}" });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating Azure AD token for client_id: {ClientId}", request?.client_id);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        private string FormatTimespan(TimeSpan timespan)
        {
            if (timespan.TotalDays >= 1)
                return $"{(int)timespan.TotalDays} day(s), {timespan.Hours} hour(s)";
            else if (timespan.TotalHours >= 1)
                return $"{(int)timespan.TotalHours} hour(s), {timespan.Minutes} minute(s)";
            else
                return $"{timespan.Minutes} minute(s), {timespan.Seconds} second(s)";
        }

    }

    public class AzureAdClientCredentialsRequest
    {
        /// <summary>
        /// Your Azure AD application client ID
        /// </summary>
        [Required]
        [SwaggerSchema(Description = "Azure AD application client ID")]
        public string client_id { get; set; }

        /// <summary>
        /// Your Azure AD application client secret
        /// </summary>
        [Required]
        [SwaggerSchema(Description = "Azure AD application client secret")]
        public string client_secret { get; set; }

        /// <summary>
        /// OAuth2 scope (default: https://graph.microsoft.com/.default)
        /// </summary>
        [SwaggerSchema(Description = "OAuth2 scope for Microsoft Graph access")]
        public string scope { get; set; }

        /// <summary>
        /// Custom expiration time in minutes for manual token refresh cycles (default: 60, min: 1, max: 1440)
        /// This controls when you should manually generate a new token for enhanced security.
        /// Example: Set to 30 for high-security environments requiring 30-minute refresh cycles.
        /// </summary>
        [Range(1, 1440, ErrorMessage = "Expiration time must be between 1 and 1440 minutes (24 hours)")]
        [SwaggerSchema(
            Description = "Custom token expiration time in minutes. Controls manual refresh intervals for enhanced security. Range: 1-1440 minutes (24 hours). Default: 60 minutes."
        )]
        public int? expires_in_minutes { get; set; }
    }

    public class AzureAdTokenResponse
    {
        /// <summary>Azure AD access token</summary>
        [SwaggerSchema(Description = "Azure AD access token for Microsoft Graph API")]
        public string access_token { get; set; }

        /// <summary>Token type (always 'Bearer')</summary>
        [SwaggerSchema(Description = "Token type, always 'Bearer'")]
        public string token_type { get; set; }

        /// <summary>Azure AD token expiration in seconds</summary>
        [SwaggerSchema(Description = "Azure AD token expiration time in seconds (typically 3600)")]
        public int expires_in { get; set; }

        /// <summary>OAuth2 scope granted</summary>
        [SwaggerSchema(Description = "OAuth2 scope that was granted")]
        public string scope { get; set; }

        /// <summary>Refresh token (if available)</summary>
        [SwaggerSchema(Description = "Refresh token for obtaining new access tokens")]
        public string refresh_token { get; set; }

        /// <summary>ID token (if available)</summary>
        [SwaggerSchema(Description = "OpenID Connect ID token")]
        public string id_token { get; set; }

        // Enhanced expiration information
        /// <summary>When the Azure AD token expires (UTC)</summary>
        [SwaggerSchema(Description = "Absolute expiration time of the Azure AD token (UTC)")]
        public DateTime expires_at { get; set; }

        /// <summary>When the token was issued (UTC)</summary>
        [SwaggerSchema(Description = "Token issue timestamp (UTC)")]
        public DateTime issued_at { get; set; }

        /// <summary>Human-readable expiration time</summary>
        [SwaggerSchema(Description = "Human-readable format of token expiration duration")]
        public string expires_in_human { get; set; }

        /// <summary>Your custom expiration setting in minutes</summary>
        [SwaggerSchema(Description = "Custom expiration time you specified for manual refresh cycles")]
        public int custom_expires_in_minutes { get; set; }

        /// <summary>When you should manually refresh the token (UTC)</summary>
        [SwaggerSchema(Description = "Recommended time to manually generate a new token (UTC)")]
        public DateTime custom_expires_at { get; set; }

        /// <summary>Token refresh guidance message</summary>
        [SwaggerSchema(Description = "Guidance on when to refresh the token based on your settings")]
        public string token_refresh_guidance { get; set; }
    }

    public class AzureAdErrorResponse
    {
        public string error { get; set; }
        public string error_description { get; set; }
        public string error_codes { get; set; }
        public string timestamp { get; set; }
        public string trace_id { get; set; }
        public string correlation_id { get; set; }
    }
}
