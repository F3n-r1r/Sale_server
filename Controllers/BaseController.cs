using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Server.Entities;

namespace Server.Controllers
{
    /// <summary>
    /// The base controller is inherited by all other controllers in the boilerplate api and includes common properties and methods that are accessible to all controllers.
    /// The Account property returns the current authenticated account for the request from the HttpContext.Items collection, or returns null if the request is not authenticated.
    /// The current account is added to the HttpContext.Items collection by the custom jwt middleware when the request contains a valid JWT token in the authorization header.
    /// </summary>
    [Controller]
    public abstract class BaseController : ControllerBase
    {
        public Account Account => (Account)HttpContext.Items["Account"];
    }
}