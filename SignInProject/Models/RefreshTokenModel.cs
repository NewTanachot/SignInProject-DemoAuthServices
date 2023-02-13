namespace SignInProject.Models
{
    public class RefreshTokenModel
    {
        public string RefreshToken { get; set; }
        public DateTime CreateDate { get; set; } = DateTime.Now;
        public DateTime ExpireDate { get; set; }
    }
}
