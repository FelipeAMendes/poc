using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Poc.Admin.Controllers;

[Authorize]
[ApiController]
[Route("[controller]")]
public class HomeController : ControllerBase
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return Ok();
    }

    [Authorize("IsDefaultUser")]
    [HttpPost("User")]
    public IActionResult PostUser()
    {
        return Ok();
    }

    [Authorize("IsAdmin")]
    [HttpPost("Admin")]
    public IActionResult PostAdmin()
    {
        return Ok();
    }
}
