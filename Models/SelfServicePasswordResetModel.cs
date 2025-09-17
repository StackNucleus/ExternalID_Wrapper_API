using System.ComponentModel.DataAnnotations;

namespace OIDC_ExternalID_API.Models
{
    public class SelfServicePasswordResetModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string NewPassword { get; set; }

        [Required]
        public string VerificationCode { get; set; }

        public bool ForceChangePasswordNextSignIn { get; set; } = true;

        public bool ForceChangePasswordNextSignInWithMfa { get; set; } = false;
    }
} 