using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MyResume.Auth.Dtos;
using MyResume.Auth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MyResume.Auth.Controllers;

[Authorize]//TODO: fix
[ApiController]
[Route("[controller]")]
public class ManageController : Controller
{
    private readonly UserManager<UserModel> _userManager;
    private readonly SignInManager<UserModel> _signInManager;

    public ManageController(
        UserManager<UserModel> userManager,
        SignInManager<UserModel> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("2fa")]
    public async Task<IActionResult> Manage2fa([FromBody] TwoFactorRequest tfaRequest)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(Request.Headers["AccessToken"]);
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(token.Claims));
        var userManager = _signInManager.UserManager;
        if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
        {
            return NotFound();
        }

        if (tfaRequest.Enable is true)
        {
            if (tfaRequest.ResetSharedKey)
            {
                return BadRequest("CannotResetSharedKeyAndEnable: Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
            }
            else if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
            {
                return BadRequest("RequiresTwoFactor: No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
            }
            else if (!await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
            {
                return BadRequest("InvalidTwoFactorCode: The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
            }

            await userManager.SetTwoFactorEnabledAsync(user, true);
        }
        else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
        {
            await userManager.SetTwoFactorEnabledAsync(user, false);
        }

        if (tfaRequest.ResetSharedKey)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
        }

        string[] recoveryCodes = null;
        if (tfaRequest.ResetRecoveryCodes || (tfaRequest.Enable == true && await userManager.CountRecoveryCodesAsync(user) == 0))
        {
            var recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            recoveryCodes = recoveryCodesEnumerable?.ToArray();
        }

        if (tfaRequest.ForgetMachine)
        {
            await _signInManager.ForgetTwoFactorClientAsync();
        }

        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            key = await userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key))
            {
                throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
            }
        }

        return Ok(new TwoFactorResponse
        {
            SharedKey = key,
            RecoveryCodes = recoveryCodes,
            RecoveryCodesLeft = recoveryCodes?.Length ?? await userManager.CountRecoveryCodesAsync(user),
            IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user),
            IsMachineRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user),
        });
    }

    [HttpGet("user")]
    public async Task<IActionResult> GetUserAsync()
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(Request.Headers.Authorization.ToString().Replace("Bearer ", ""));
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(token.Claims));

        var id = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.NameId)?.Value;
        if (string.IsNullOrEmpty(id))
            return NotFound();

        if (await _signInManager.UserManager.Users.SingleOrDefaultAsync(x => x.Id == id) is not { } user)
            return NotFound();

        var userDto = new UserDto
        {
            Id = user.Id,
            UserName = user.UserName,
            PrivateProfile = user.PrivateProfile,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            LockoutEnabled = user.LockoutEnabled
        };

        return Ok(userDto);
    }

    [HttpPost("changeUser")]
    public async Task<IActionResult> ChangeUserAsync([FromBody] ChangeUserDto userDto)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(Request.Headers.Authorization.ToString().Replace("Bearer ", ""));
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(token.Claims));

        var id = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.NameId)?.Value;
        if (string.IsNullOrEmpty(id))
            return NotFound();

        if (await _signInManager.UserManager.Users.SingleOrDefaultAsync(x => x.Id == id) is not { } user)
            return NotFound();

        user.PrivateProfile = userDto.PrivateProfile;
        await _userManager.UpdateAsync(user);
        
        if (!string.IsNullOrEmpty(userDto.PhoneNumber))
        {
            var changePhoneResult = await _userManager.SetPhoneNumberAsync(user, userDto.PhoneNumber);
            if (!changePhoneResult.Succeeded)
            {
                return BadRequest(changePhoneResult);
            }
        }

        var userDtoResult = new UserDto
        {
            Id = user.Id,
            UserName = user.UserName,
            PrivateProfile = userDto.PrivateProfile,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            LockoutEnabled = user.LockoutEnabled
        };

        return Ok(userDtoResult);
    }

    [HttpPost("changeEmail")]
    public async Task<IActionResult> ChangeEmailAsync([FromBody] ChangeEmailDto emailDto)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(Request.Headers.Authorization.ToString().Replace("Bearer ", ""));
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(token.Claims));

        var id = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.NameId)?.Value;
        if (string.IsNullOrEmpty(id))
            return NotFound();

        if (await _signInManager.UserManager.Users.SingleOrDefaultAsync(x => x.Id == id) is not { } user)
            return NotFound();

        var email = await _userManager.GetEmailAsync(user);

        if (email != emailDto.NewEmail)
        {
            //await SendConfirmationEmailAsync(user, emailDto.NewEmail);
        }

        return Ok();
    }

    [HttpPost("changePassword")]
    public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePasswordDto passwordDto)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(Request.Headers.Authorization.ToString().Replace("Bearer ", ""));
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(token.Claims));

        var id = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.NameId)?.Value;
        if (string.IsNullOrEmpty(id))
            return NotFound();

        if (await _signInManager.UserManager.Users.SingleOrDefaultAsync(x => x.Id == id) is not { } user)
            return NotFound();

        if (!string.IsNullOrEmpty(passwordDto.NewPassword))
        {
            if (string.IsNullOrEmpty(passwordDto.OldPassword))
                return BadRequest("OldPasswordRequired: The old password is required to set a new password. If the old password is forgotten, use /resetPassword.");

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, passwordDto.OldPassword, passwordDto.NewPassword);
            if (!changePasswordResult.Succeeded)
                return BadRequest(changePasswordResult);
        }

        return Ok();
    }
}