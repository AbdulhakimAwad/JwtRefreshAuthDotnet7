namespace JwtAuthDotnet7.Models
{
    public class User
    {
        public string userName { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}
