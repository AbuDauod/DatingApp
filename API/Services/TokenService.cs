using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services;

public class TokenService (IConfiguration config): ITokenService
{
    public string CreateToken(AppUser user)
    {
        var tokenKey=config["TokenKey"]?? throw new Exception("cannot access token from appsettings");
        if (tokenKey.Length<64) throw new Exception("Your tokenkey needs be longer");
        var key=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

        var claims=new List<Claim>
        {
            new(ClaimTypes.NameIdentifier,user.UserName)
        };

        var creds=new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

        var tokenDEscriptor=new SecurityTokenDescriptor
        {
            Subject=new ClaimsIdentity(claims),
            Expires=DateTime.UtcNow.AddDays(7),
            SigningCredentials=creds
        };

        var tokenHndler=new JwtSecurityTokenHandler();
        var token=tokenHndler.CreateToken(tokenDEscriptor);

        return tokenHndler.WriteToken(token);
    }
}
