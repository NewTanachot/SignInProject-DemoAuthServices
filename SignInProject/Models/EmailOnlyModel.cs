using System.ComponentModel.DataAnnotations;

namespace SignInProject.Models
{
    public class EmailOnlyModel
    {
        [Required]
        [EmailAddress(ErrorMessage = "Email is required . . .")]
        public string Email { get; set; }
    }
}
