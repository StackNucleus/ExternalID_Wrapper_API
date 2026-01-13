using System.Text.Json.Serialization;

namespace OIDC_ExternalID_API.Models
{
    public class PhoneAuthenticationMethodModel
    {
        /// <summary>
        /// The phone number to use for authentication.
        /// </summary>
        [JsonPropertyName("phoneNumber")]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// The type of phone. Possible values are: mobile, alternateMobile, office.
        /// </summary>
        [JsonPropertyName("phoneType")]
        public string PhoneType { get; set; }

        /// <summary>
        /// The ID of the phone authentication method.
        /// </summary>
        [JsonPropertyName("id")]
        public string Id { get; set; }

        /// <summary>
        /// The SMS sign-in state. Possible values are: default, notAllowed, required.
        /// </summary>
        [JsonPropertyName("smsSignInState")]
        public string SmsSignInState { get; set; }
    }

    public class PhoneAuthenticationMethodCreationModel
    {
        /// <summary>
        /// The phone number to use for authentication.
        /// </summary>
        [JsonPropertyName("phoneNumber")]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// The type of phone. Possible values are: mobile, alternateMobile, office.
        /// </summary>
        [JsonPropertyName("phoneType")]
        public string PhoneType { get; set; }
    }

    public class PhoneAuthenticationMethodUpdateModel
    {
        /// <summary>
        /// The phone number to use for authentication.
        /// </summary>
        [JsonPropertyName("phoneNumber")]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// The type of phone. Possible values are: mobile, alternateMobile, office.
        /// </summary>
        [JsonPropertyName("phoneType")]
        public string PhoneType { get; set; }
    }
}