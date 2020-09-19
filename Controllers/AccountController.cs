using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Server.Models;
using Server.Services;


namespace Server.Controllers
{

    [Route("api/v1/[controller]")]
    [Authorize]
    [ApiController]
    public class AccountController : ControllerBase
    {

        private readonly AccountService _accountService;

        public AccountController(AccountService accountService)
        {
            _accountService = accountService;
        }



        /// <summary>
        /// API endpoint which accepts a post request to register a new account
        /// </summary>
        [AllowAnonymous]
        [HttpPost]
        public async Task<ActionResult<Account>> Create([FromForm] Account account)
        {
            if (await _accountService.Exists(account) == true)
            {
                return StatusCode(409, new { message = $"'{account.Email}' already exists." });
            }
            
            var response = await _accountService.Create(account, Request.Host);
            return Ok(new { message = response });  
        }




        /// <summary>
        /// API endpoint which accepts a post request to register a new account
        /// </summary>
        [AllowAnonymous]
        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string Token)
        {
            var verify = await _accountService.Verify(Token);
            if(verify)
            {
                return Ok(new { message = "Verification successful, you can now login" });
            }

            return StatusCode(401, new { message = $"'{Token}' could not be verified." });
        }
    }

}