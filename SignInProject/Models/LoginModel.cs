using System.ComponentModel.DataAnnotations;

namespace SignInProject.Models
{
    public class LoginModel
    {
        [Required]
        [EmailAddress(ErrorMessage = "Email is required . . .")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password, ErrorMessage = "Password is required . . .")]
        public string Password { get; set; }
    }
}
