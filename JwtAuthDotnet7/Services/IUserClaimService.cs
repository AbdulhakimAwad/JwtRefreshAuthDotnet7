using Microsoft.AspNetCore.Mvc;

namespace JwtAuthDotnet7.Services
{
    public interface IUserClaimService
    {
        public List<string> GetName();
    }
}
