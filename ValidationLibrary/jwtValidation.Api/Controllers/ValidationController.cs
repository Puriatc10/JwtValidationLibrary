using JWTValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace jwtValidation.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValidationController : ControllerBase
    {
        private string sampleToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6ImQ5MzQ3YjBmLTcyYzAtNDFhNy04MzZjLTZlN2Q4ZWE4MGViNSIsInRva2VudHlwZSI6ImFjY2VzcyIsInNsIjoiNTQxQ0UzNzc5QTg0NDBDNzZENTlBQjExQUUwQkY2NDMiLCJwb3J0YWwiOiJNYW5hZ2VtZW50Iiwic2Vzc2lvbiI6ImM1NTcwZjkwLWQzNGMtNDA2Ni05NGEwLWU4YjY1MDI1NTg0NCIsImp0aSI6IjRhZTNmZGY5LWViNmQtNGE2MS04YmQyLTJmZjUzZmNlNzIyOCIsIm5iZiI6MTcxMDA2MTY5MCwiZXhwIjoxNzEwNTExNjkwfQ.HmSqxodyB-mZ85PG_k85Qf_GMpNNyNQ3P9e26KFaT4q71NTOoBPD5UutL7wZlveh2B-g75PS2mP7pKHoHY9iUQXWRQay-gQd9dv8YRvUrqxzQJZCD8TWiJc1Z-3wk8TMQz31EItbJvAiv5WDaUoECX7U5ryVgv3NkZxIvpQOArz4HqjbqPmbD1MKBbAe4CyeDZrqJzPlQsZdji0Frhg3A61siqp7XO7YrFoFn8czt5yfTHaP0uBiIQwp3qt-yQN80UGLPo-DowO0zyeLDFzqTKpxC9e3c9gBzBeCLoUFB4CHZOV5puaTFhgDcF0OTnZ-p_n5u2ilbg9b0cvGaL_Q6g";
        [HttpPost("test")]
        public async Task<IActionResult> Test()
        {
            var res = await JwtValidator.TokenValidate(sampleToken);
            if(res.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(res);
            }
            else
            {
                return BadRequest(res);
            }
        }
    }
}
