using System.ComponentModel.DataAnnotations;

namespace OIDC_ExternalID_API.Models
{
    public class RequestPasswordResetModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
} 