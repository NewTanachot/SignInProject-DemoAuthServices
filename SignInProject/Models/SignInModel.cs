using System.ComponentModel.DataAnnotations;

namespace SignInProject.Models
{
    public class SignInModel
    {
        [Required]
        [EmailAddress(ErrorMessage = "Email is required . . .")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password, ErrorMessage = "Password is required . . .")]
        public string Password { get; set; }

        [Required(ErrorMessage = "FirstName is required . . .")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "LastName is required . . .")]
        public string LastName { get; set; }

        public string age { get; set; }
    }
}
