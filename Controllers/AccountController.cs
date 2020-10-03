using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using Server.Entities;
using Server.Models.Accounts;
using Server.Services;


using System.Threading.Tasks;


using Server.Helpers;

namespace Server.Controllers
{

    [Route("api/v1/[controller]")]
    [ApiController]
    public class AccountController : BaseController
    {

        private readonly AccountService _accountService;

        public AccountController(AccountService accountService)
        {
            _accountService = accountService;
        }





        /// <summary>
        /// API endpoint which accepts a post request to authenticate account credentials
        /// </summary>
        [HttpPost("authenticate")]
        public async Task<ActionResult<AuthenticateResponse>> Authenticate([FromForm] AuthenticateRequest model)
        {
            var response = await _accountService.Authenticate(model, ipAddress());
            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }





        /// <summary>
        /// API endpoint which accepts a post request to register a new account
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromForm] RegisterRequest model)
        {
            if (await _accountService.Exists(model.Email) == true)
            {
                return StatusCode(409, new { message = $"'{model.Email}' already exists." });
            }
            
            await _accountService.Register(model, Request.Headers["origin"]);
            return Ok(new { message = "Registration successful, please check your email for verification instructions" });
        }






        /// <summary>
        /// API endpoint which accepts a post request to provide the requester with a link to reset their password
        /// </summary>
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromForm] ForgotPasswordRequest model)
        {
            await _accountService.ForgotPassword(model, Request.Headers["origin"]);
            return Ok(new { message = "Please check your email for password reset instructions" });
        }





        /// <summary>
        /// API endpoint which accepts a post request to reset the requesters password
        /// </summary>
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromQuery] ResetPasswordRequest model)
        {
            await _accountService.ResetPassword(model);
            return Ok(new { message = "Password reset successful." });
        }





        /// <summary>
        /// API endpoint which accepts a post request to verify a new account
        /// </summary>
        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromQuery] VerifyEmailRequest model)
        {
            await _accountService.VerifyEmail(model.Token);
            return Ok(new { message = "Verification successful, you can now login" });
        }





        /// <summary>
        /// API endpoint to get a list of all accounts, only accessible by admins.
        /// </summary>
        [Authorize(Role.Admin)]
        [HttpGet("accounts")]
        public async Task<ActionResult<IEnumerable<AccountResponse>>> GetAll()
        {

            var accounts = await _accountService.GetAll();
            return Ok(accounts);
        }









        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }

    }
}