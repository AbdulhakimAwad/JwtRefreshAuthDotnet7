using BCrypt.Net;
using JwtAuthDotnet7.Models;
using JwtAuthDotnet7.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthDotnet7.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserClaimService _userClaimService;
        public AuthController(IConfiguration configuration,IUserClaimService userClaimService)
        {
            _configuration = configuration;
            _userClaimService=userClaimService;
        }

        [HttpGet,Authorize]
        public async Task<ActionResult<string>> GetName()
        {
            var res=_userClaimService.GetName();
            return Ok(new {res});
        }

        [Produces("application/json")]
        [HttpPost("register")]
        public async Task<ActionResult<User>>Register([FromBody]UserDto req)
        {
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(req.password);
            user.userName = req.userName;
            user.password = hashedPassword;
            return Ok(user);
        }
        [HttpGet("get")]
        public async Task<ActionResult<User>> GetUser()
        {
            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>>Login(UserDto req)
        {
            if (req.userName != user.userName)
            {
                return BadRequest("User is not exists");
            }

            if(!BCrypt.Net.BCrypt.Verify(req.password,user.password)) 
            {
                return BadRequest("Password is wrong");
            }
            var token = CreateToken(user);
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);
            return Ok(token);
        }
        [HttpPost("refresh")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (!user.RefreshToken.Equals(refreshToken)) 
            {
                return Unauthorized("Invalid Token");
            }
            else if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token has expired");
            }
            var token= CreateToken(user);
            var refresh= GenerateRefreshToken();
            SetRefreshToken(refresh);
            return Ok(token);
        }
        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(1)
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken refreshToken)
        {
            var CookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.Expires
            };
            Response.Cookies.Append("refreshToken", refreshToken.Token, CookieOptions);
            user.RefreshToken = refreshToken.Token;
            user.TokenCreated = refreshToken.Created;
            user.TokenExpires= refreshToken.Expires;

        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.userName),
                new Claim(ClaimTypes.Role,"Admin,User")
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("jwt:token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds,
                expires: DateTime.Now.AddDays(1));
            var jwt=new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
