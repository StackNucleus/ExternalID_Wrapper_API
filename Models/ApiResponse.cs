using System.Net;

namespace OIDC_ExternalID_API.Models
{
    /// <summary>
    /// Standardized API response model
    /// </summary>
    public class ApiResponse<T>
    {
        /// <summary>
        /// Indicates whether the request was successful
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// The HTTP status code
        /// </summary>
        public HttpStatusCode StatusCode { get; set; }

        /// <summary>
        /// The response data
        /// </summary>
        public T Data { get; set; }

        /// <summary>
        /// The error message (if any)
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// The error details (if any)
        /// </summary>
        public string Details { get; set; }

        /// <summary>
        /// The error type (if any)
        /// </summary>
        public string ErrorType { get; set; }

        /// <summary>
        /// Creates a successful API response
        /// </summary>
        /// <param name="data">The response data</param>
        /// <param name="statusCode">The HTTP status code</param>
        /// <returns>A successful API response</returns>
        public static ApiResponse<T> CreateSuccess(T data, HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            return new ApiResponse<T>
            {
                Success = true,
                StatusCode = statusCode,
                Data = data,
                Message = "Request processed successfully."
            };
        }

        /// <summary>
        /// Creates an error API response
        /// </summary>
        /// <param name="message">The error message</param>
        /// <param name="details">The error details</param>
        /// <param name="errorType">The error type</param>
        /// <param name="statusCode">The HTTP status code</param>
        /// <returns>An error API response</returns>
        public static ApiResponse<T> CreateError(string message, string details = null, string errorType = null, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
        {
            return new ApiResponse<T>
            {
                Success = false,
                StatusCode = statusCode,
                Message = message,
                Details = details,
                ErrorType = errorType
            };
        }
    }
}
