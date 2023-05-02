namespace JwtAuthDotnet7.Models
{
    public class RefreshToken
    {
        public required string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; }=DateTime.Now;
        public DateTime Expires { get; set; }
    }
}
