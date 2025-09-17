using System.ComponentModel.DataAnnotations;

namespace OIDC_ExternalID_API.Models
{
    public class ResetPasswordModel
    {
        [Required]
        public string NewPassword { get; set; }

       // [Required]
       // public bool ForceChangePasswordNextSignIn { get; set; } = true;

       // public bool ForceChangePasswordNextSignInWithMfa { get; set; } = false;
    }
} 