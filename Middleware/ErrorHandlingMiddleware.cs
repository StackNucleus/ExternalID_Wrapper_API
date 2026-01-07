using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OIDC_ExternalID_API.Models;
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace OIDC_ExternalID_API.Middleware
{
    /// <summary>
    /// Middleware for centralized error handling
    /// </summary>
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ErrorHandlingMiddleware"/> class.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="logger">The logger.</param>
        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        /// <summary>
        /// Invokes the middleware.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <returns>A task that represents the completion of the middleware.</returns>
        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        /// <summary>
        /// Handles the exception and returns a standardized error response.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <param name="exception">The exception.</param>
        /// <returns>A task that represents the completion of the exception handling.</returns>
        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            _logger.LogError(exception, "An unhandled exception occurred.");

            var response = ApiResponse<object>.CreateError(
                message: "An error occurred while processing your request.",
                details: exception.Message,
                errorType: exception.GetType().Name,
                statusCode: HttpStatusCode.InternalServerError
            );

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)response.StatusCode;

            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
    }
}
