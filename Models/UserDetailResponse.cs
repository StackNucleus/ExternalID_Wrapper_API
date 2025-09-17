using System.ComponentModel;

namespace OIDC_ExternalID_API.Models
{
    /// <summary>
    /// Response model for retrieving specific user details from Microsoft Graph API beta endpoint
    /// </summary>
    public class UserDetailResponse
    {
        /// <summary>
        /// The display name of the user
        /// </summary>
        /// <example>John Doe</example>
        [Description("The display name of the user")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The given name (first name) of the user
        /// </summary>
        /// <example>John</example>
        [Description("The given name (first name) of the user")]
        public string? GivenName { get; set; }

        /// <summary>
        /// The identities associated with this user account from various authentication providers
        /// </summary>
        [Description("User identities from various authentication providers")]
        public List<UserIdentity>? Identities { get; set; }
    }

    /// <summary>
    /// Represents a user identity from an authentication provider
    /// </summary>
    public class UserIdentity
    {
        /// <summary>
        /// The type of sign-in (e.g., "userName", "emailAddress", "federated")
        /// </summary>
        /// <example>emailAddress</example>
        [Description("The type of sign-in")]
        public string? SignInType { get; set; }

        /// <summary>
        /// The issuer of the identity (authentication provider)
        /// </summary>
        /// <example>yourtenant.onmicrosoft.com</example>
        [Description("The issuer of the identity (authentication provider)")]
        public string? Issuer { get; set; }

        /// <summary>
        /// The unique identifier assigned by the issuer
        /// </summary>
        /// <example>user@yourtenant.onmicrosoft.com</example>
        [Description("The unique identifier assigned by the issuer")]
        public string? IssuerAssignedId { get; set; }
    }
}