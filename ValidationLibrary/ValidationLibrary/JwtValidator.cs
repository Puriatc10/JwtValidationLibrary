using Microsoft.AspNetCore.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using ValidationLibrary.Dto;

namespace JWTValidation
{
    public static class JwtValidator
    {
        private static string publicKey = "MIIBCgKCAQEAz8gU7Dr6Gte4d4vKqtXGEARpAzhCYu930gjRdd+5Ew8XMGANc3XyOeSAcE0QtBnwCXs9Vp5OhOLOVTUetS+Bxdgub6iefdZovIisKaVi5rBaZzVenZYZh8bra1u2yTJad3U+HmGg/Kkpkbw9HUygDdwO0u9VvNxtB3fLS/MnxCmjBAHpgD5m4Lzqg5SCz2ouAPaW9FHnYATVMAN3qya1a0DTclm4UqCLYD85KbGaqIPgIBhDFX7YzxtHnOeCQcqcjx7DwIm/XgMN1kWLwkAlq3OPPyTuBQ2Cm+3+YxnbEaJaOwP/PYxFkAwOrs5VHMOdO9O6/DGAiNdPl+I7qkTSqQIDAQAB";
        public static async Task<ValidationResponse> TokenValidate(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token))
                {
                    return new ValidationResponse { 
                        StatusCode = StatusCodes.Status401Unauthorized,
                        Message = "Token not found." };
                }

                var rsaSecurityKey = CreateRsaSecurityKeyFromPublicKey(publicKey);
                var tokenHandler = new JwtSecurityTokenHandler();

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = rsaSecurityKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var sessionId = jwtToken?.Claims.FirstOrDefault(c => c.Type == "session").Value;
                if (sessionId == null)
                {
                    return new ValidationResponse
                    {
                        StatusCode = StatusCodes.Status401Unauthorized,
                        Message = "sessionId not found."
                    };
                }

                if (!DataStorage.ContainsData(sessionId))
                {
                    // validating sessionId with user mock service ...
                    //
                    //



                    DataStorage.StoreData(sessionId);
                }
            }
            catch (SecurityTokenExpiredException ex)
            {

                return new ValidationResponse
                {
                    StatusCode = StatusCodes.Status401Unauthorized,
                    Message = "Token expired."
                };
            }

            return new ValidationResponse
            {
                StatusCode = StatusCodes.Status200OK,
                Message = "Token Authorized Successfully."
            };
        }

        private static RsaSecurityKey CreateRsaSecurityKeyFromPublicKey(string publicKey)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                RSAParameters rsaParameters = rsa.ExportParameters(includePrivateParameters: false);
                var rsaSecurityKey = new RsaSecurityKey(rsaParameters);
                return rsaSecurityKey;
            }
        }

    }
}
