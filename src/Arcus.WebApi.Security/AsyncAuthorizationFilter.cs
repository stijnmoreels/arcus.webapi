using System;
using System.Linq;
using System.Threading.Tasks;
using GuardNet;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.WebApi.Security
{
    /// <summary>
    /// Represents the groundwork for an <see cref="IAsyncAuthorizationFilter"/> implementation with common boilerplate infrastructure for the deriving implementations.
    /// </summary>
    public abstract class AsyncAuthorizationFilter : IAsyncAuthorizationFilter
    {
        /// <summary>
        /// Called early in the filter pipeline to confirm request is authorized.
        /// </summary>
        /// <param name="context">The <see cref="T:Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext" />.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that on completion indicates the filter has executed.
        /// </returns>
        /// <exception cref="ArgumentNullException">Throw when the <paramref name="context"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="context"/> doesn't contain the required HTTP request information.</exception>
        public abstract Task OnAuthorizationAsync(AuthorizationFilterContext context);

        /// <summary>
        /// Gets the category <see cref="ILogger{TCategoryName}"/> implementation from the current HTTP context request services.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        /// <returns>
        ///     Either an <see cref="ILogger{TCategoryName}"/> implementation
        ///     or the default <see cref="NullLogger{TCategoryName}.Instance"/> when no logging infrastructure was registered.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="context"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="context"/> doesn't contain any request services.</exception>
        protected ILogger<TFilter> GetLogger<TFilter>(AuthorizationFilterContext context)
        {
            Guard.NotNull(context, nameof(context), "Requires an HTTP context implementation with request services to retrieve a category logger");
            Guard.For(() => context.HttpContext?.RequestServices is null, new ArgumentException(
                "Requires an HTTP context implementation with request services to retrieve a category logger"));
            
            ILogger<TFilter> logger = context.HttpContext.RequestServices.GetLoggerOrDefault<TFilter>();
            return logger;
        }

        /// <summary>
        /// Determines whether or not the current endpoint was decorated with a route attribute.
        /// </summary>
        /// <typeparam name="TAttribute">The type of route attribute that needs to be verified.</typeparam>
        /// <param name="context">The current HTTP context of this HTTP request.</param>
        /// <returns>
        ///     [true] when the current endpoint was decorated with the provided <typeparamref name="TAttribute"/> route attribute type; [false] otherwise.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="context"/> is <c>null</c>.</exception>
        protected bool HasRouteAttribute<TAttribute>(AuthorizationFilterContext context) where TAttribute : Attribute
        {
            Guard.NotNull(context, nameof(context), "Requires an HTTP context implementation to retrieve the current endpoint metadata information");
            return context.ActionDescriptor?.EndpointMetadata?.Any(metadata => metadata is TAttribute) == true;
        }
    }
}
