using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OIDC_ExternalID_API.Utilities
{
    /// <summary>
    /// Utility class for token extraction and validation
    /// </summary>
    public static class TokenUtility
    {
        /// <summary>
        /// Extracts the access token from the request's authorization header
        /// </summary>
        /// <param name="request">The HTTP request</param>
        /// <returns>The access token or null if not found</returns>
        public static string GetAccessTokenFromRequest(HttpRequest request)
        {
            try
            {
                var authHeader = request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return null;
                }

                return authHeader.Substring("Bearer ".Length);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Extracts user information from a JWT token
        /// </summary>
        /// <param name="accessToken">The JWT access token</param>
        /// <returns>UserInfo object or null if token is invalid</returns>
        public static UserInfo GetUserFromToken(string accessToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                if (!tokenHandler.CanReadToken(accessToken))
                {
                    return null;
                }

                var jwtToken = tokenHandler.ReadJwtToken(accessToken);

                return new UserInfo
                {
                    ObjectId = jwtToken.Claims.FirstOrDefault(c => c.Type == "oid")?.Value,
                    UserPrincipalName = jwtToken.Claims.FirstOrDefault(c => c.Type == "upn")?.Value,
                    Email = jwtToken.Claims.FirstOrDefault(c => c.Type == "unique_name")?.Value ??
                           jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
                    DisplayName = jwtToken.Claims.FirstOrDefault(c => c.Type == "name")?.Value,
                    GivenName = jwtToken.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value,
                    Surname = jwtToken.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Validates if a token is an Azure AD token
        /// </summary>
        /// <param name="token">The token to validate</param>
        /// <returns>True if the token is an Azure AD token, otherwise false</returns>
        public static bool IsAzureAdToken(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token) || token.Length < 100)
                {
                    // Log token validation failure
                    return false;
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                if (tokenHandler.CanReadToken(token))
                {
                    var jwtToken = tokenHandler.ReadJwtToken(token);

                    var issuer = jwtToken.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
                    var audience = jwtToken.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;

                    if (!string.IsNullOrEmpty(issuer) &&
                        (issuer.Contains("login.microsoftonline.com") || issuer.Contains("sts.windows.net")))
                    {
                        // Log successful Azure AD token validation
                        return true;
                    }

                    if (!string.IsNullOrEmpty(audience) &&
                        audience.Contains("graph.microsoft.com"))
                    {
                        // Log successful Azure AD token validation
                        return true;
                    }
                }

                // Log token validation failure
                return false;
            }
            catch (Exception ex)
            {
                // Log token validation error
                return false;
            }
        }
    }

    /// <summary>
    /// Simple user info class to hold data extracted from token
    /// </summary>
    public class UserInfo
    {
        public string? ObjectId { get; set; }
        public string? UserPrincipalName { get; set; }
        public string? Email { get; set; }
        public string? DisplayName { get; set; }
        public string? GivenName { get; set; }
        public string? Surname { get; set; }
    }
}
