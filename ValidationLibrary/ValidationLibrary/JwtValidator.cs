using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;

namespace JWTValidation
{
    public static class JwtValidator
    {
        private static string publicKey = "MIIBCgKCAQEAz8gU7Dr6Gte4d4vKqtXGEARpAzhCYu930gjRdd+5Ew8XMGANc3XyOeSAcE0QtBnwCXs9Vp5OhOLOVTUetS+Bxdgub6iefdZovIisKaVi5rBaZzVenZYZh8bra1u2yTJad3U+HmGg/Kkpkbw9HUygDdwO0u9VvNxtB3fLS/MnxCmjBAHpgD5m4Lzqg5SCz2ouAPaW9FHnYATVMAN3qya1a0DTclm4UqCLYD85KbGaqIPgIBhDFX7YzxtHnOeCQcqcjx7DwIm/XgMN1kWLwkAlq3OPPyTuBQ2Cm+3+YxnbEaJaOwP/PYxFkAwOrs5VHMOdO9O6/DGAiNdPl+I7qkTSqQIDAQAB";
        public static async Task TokenValidate(this HttpContext httpContext)
        {
            try
            {
                var accessToken = httpContext.Request.Headers.Authorization.ToString().Split(" ")[1];
                if (string.IsNullOrEmpty(accessToken))
                {
                    httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    httpContext.Response.WriteAsync("Token not found.");
                    return;
                }

                var key = Encoding.UTF8.GetBytes(publicKey);
                var tokenHandler = new JwtSecurityTokenHandler();

                tokenHandler.ValidateToken(accessToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var sessionId = jwtToken?.Claims.FirstOrDefault(c => c.Type == "session").Value;
                if (sessionId == null)
                {
                    httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    httpContext.Response.WriteAsync("sessionId not found.");
                    return;
                }

                if (!DataStorage.ContainsData(sessionId))
                {
                    // validating sessionId with user mock service ...
                    //
                    //


                }
                else
                {
                    DataStorage.StoreData(sessionId);
                }
            }
            catch (SecurityTokenExpiredException ex)
            {
                httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                httpContext.Response.WriteAsync("Token expired.");
                return;
            }
        }

    }
}
