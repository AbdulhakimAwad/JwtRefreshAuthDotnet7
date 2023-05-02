
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtAuthDotnet7.Services
{
    public class UserClaimService : IUserClaimService
    {
        public IHttpContextAccessor _Context;

        public UserClaimService(IHttpContextAccessor context)
        {
            _Context = context;
        }

        public List<string> GetName()
        {
            List<string> name; 
            
            if (_Context.HttpContext is not null)
            {
                name = _Context.HttpContext.User!.FindAll(ClaimTypes.Name).Select(c=>c.Value).ToList();
                var claims = _Context.HttpContext.User!.FindAll(ClaimTypes.Role);
                var roles = claims.Select(c => c.Value).ToList();

                var res = new List<string>();
                res.AddRange(name);
                res.AddRange(roles);
                return res ;
            }
            else
            {
                return new List<string>();
            }
        }
    }
}
