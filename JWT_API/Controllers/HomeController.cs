using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT_API.Controllers
{
    [ApiController]
    public class HomeController : Controller
    {
        readonly JwtOptions jwtOptions;

        public HomeController(JwtOptions jwtOptions)
        {
            this.jwtOptions = jwtOptions;
        }

        [AllowAnonymous]
        [HttpGet("/")]
        public IActionResult Index()
        {
            return Ok("Hello World");
        }

        [AllowAnonymous]
        [HttpGet("/public")]
        public IActionResult IndexPublic()
        {
            return Ok("Hello Public World");
        }

        [Authorize]
        [HttpGet("/private")]
        public IActionResult IndexPrivate()
        {
            return Ok("Private Hello World!");
        }

        [AllowAnonymous]
        [HttpPost("/tokens/connect")]
        public async Task<IResult> Token() // Returning an IResult is only fully support in .NET 7 and above. Other it gets wrapped in an IActionResult which messes up with the status code.
        {
            var result = await TokenEndpoint.Connect(HttpContext, jwtOptions);

            return result;
        }
    }
}