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

    [Route("api/v1/")]
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
        [HttpPost("account")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        public async Task<ActionResult<Account>> Create([FromBody] Account account)
        {
            if(await _accountService.Exists(account) == true)
            {
                var response = await _accountService.Create(account, Request.Headers["origin"]);
                return StatusCode(200, response);
            }
            
            return StatusCode(409, $"'{account.Email}' already exists.");
        }

    }

}