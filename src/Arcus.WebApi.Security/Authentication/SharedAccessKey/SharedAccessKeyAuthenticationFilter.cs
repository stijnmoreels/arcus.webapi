using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using GuardNet;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Arcus.WebApi.Security.Authentication.SharedAccessKey
{
    /// <summary>
    /// Authentication filter to secure HTTP requests with shared access keys.
    /// </summary>
    /// <remarks>
    ///     Please provide an <see cref="ISecretProvider"/> implementation in the configured services of the request.
    /// </remarks>
    public class SharedAccessKeyAuthenticationFilter : AsyncAuthorizationFilter
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SharedAccessKeyAuthenticationFilter"/> class.
        /// </summary>
        /// <param name="headerName">The name of the request header which value must match the stored secret.</param>
        /// <param name="queryParameterName">The name of the query parameter which value must match the stored secret.</param>
        /// <param name="secretName">The name of the secret that's being retrieved using the <see cref="ISecretProvider.GetRawSecretAsync"/> call.</param>
        /// <exception cref="ArgumentException">Thrown when the both <paramref name="headerName"/> and <paramref name="queryParameterName"/> are blank.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        public SharedAccessKeyAuthenticationFilter(string headerName, string queryParameterName, string secretName)
            : this(headerName, queryParameterName, secretName, new SharedAccessKeyAuthenticationOptions())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SharedAccessKeyAuthenticationFilter"/> class.
        /// </summary>
        /// <param name="headerName">The name of the request header which value must match the stored secret.</param>
        /// <param name="queryParameterName">The name of the query parameter which value must match the stored secret.</param>
        /// <param name="secretName">The name of the secret that's being retrieved using the <see cref="ISecretProvider.GetRawSecretAsync"/> call.</param>
        /// <param name="options">The set of additional consumer-configurable options to change the behavior of the shared access authentication.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="headerName"/> and <paramref name="queryParameterName"/> are blank.</exception>
        public SharedAccessKeyAuthenticationFilter(string headerName, string queryParameterName, string secretName, SharedAccessKeyAuthenticationOptions options)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name");
            Guard.For<ArgumentException>(
                () => String.IsNullOrWhiteSpace(headerName) && String.IsNullOrWhiteSpace(queryParameterName), 
                "Requires either a non-blank header name or query parameter name");

            HeaderName = headerName;
            QueryParameterName = queryParameterName;
            SecretName = secretName;
            Options = options;
        }

        /// <summary>
        /// Gets the configured name of the request header which value must match the stored secret.
        /// </summary>
        protected string HeaderName { get; }
        
        /// <summary>
        /// Gets the configured name of the request query parameter which value must match the stored secret.
        /// </summary>
        protected string QueryParameterName { get; }
        
        /// <summary>
        /// Gets the name of the secret that's being retrieved using the <see cref="ISecretProvider"/>.
        /// </summary>
        protected string SecretName { get; }
        
        /// <summary>
        /// Gets the set of additional consumer-configurable options to change the behavior of the shared access authentication.
        /// </summary>
        protected SharedAccessKeyAuthenticationOptions Options { get; }

        /// <summary>
        /// Called early in the filter pipeline to confirm request is authorized.
        /// </summary>
        /// <param name="context">The <see cref="T:Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext" />.</param>
        /// <returns>
        ///     A <see cref="T:System.Threading.Tasks.Task" /> that on completion indicates the filter has executed.
        /// </returns>
        /// <exception cref="ArgumentNullException">Throw when the <paramref name="context"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="context"/> doesn't contain the required HTTP request information.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no <see cref="ISecretProvider"/> or <see cref="ICachedSecretProvider"/> could be found in the request services.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the configured <see cref="ISecretProvider"/> or <see cref="ICachedSecretProvider"/> was not implemented correctly.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret value could be found to match with the request's header or query parameter.</exception>
        public override async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            Guard.NotNull(context, nameof(context));
            Guard.NotNull(context.HttpContext, nameof(context.HttpContext));
            Guard.For<ArgumentException>(() => context.HttpContext.Request is null, "Invalid action context given without any HTTP request");
            Guard.For<ArgumentException>(() => context.HttpContext.Request.Headers is null, "Invalid action context given without any HTTP request headers");
            Guard.For<ArgumentException>(() => context.HttpContext.RequestServices is null, "Invalid action context given without any HTTP request services");

            ILogger logger = GetLogger<SharedAccessKeyAuthenticationFilter>(context);
            
            if (HasRouteAttribute<BypassSharedAccessKeyAuthenticationAttribute>(context) 
                || HasRouteAttribute<AllowAnonymousAttribute>(context))
            {
                logger.LogTrace("Bypass shared access key authentication because the '{SpecificAttribute}' or '{GeneralAttribute}' was found", nameof(BypassSharedAccessKeyAuthenticationAttribute), nameof(AllowAnonymousAttribute));
                return;
            }
            
            string accessKey = await GetSharedAccessKeyAsync(context);

            if (!context.HttpContext.Request.Headers.ContainsKey(HeaderName) 
                && !context.HttpContext.Request.Query.ContainsKey(QueryParameterName))
            {
                LogSecurityEvent(logger, $"Cannot verify shared access key because neither a request header '{HeaderName}' or query parameter '{QueryParameterName}' was found in the incoming request that was configured for shared access authentication", HttpStatusCode.Unauthorized);
                context.Result = new UnauthorizedResult();
            }
            else
            {
                ValidateSharedAccessKeyInRequestHeader(context, accessKey, logger);
                ValidateSharedAccessKeyInQueryParameter(context, accessKey, logger);
            }
        }

        /// <summary>
        /// Get the shared access key from an <see cref="ISecretProvider"/> or <see cref="ICachedSecretProvider"/> implementation in the <paramref name="context"/>.
        /// </summary>
        /// <param name="context">The HTTP context, containing the registered dependency services.</param>
        /// <exception cref="ArgumentNullException">Throw when the <paramref name="context"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="context"/> doesn't have registered request dependency services.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no <see cref="ISecretProvider"/> or <see cref="ICachedSecretProvider"/> could be found in the request services.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the configured <see cref="ISecretProvider"/> or <see cref="ICachedSecretProvider"/> was not implemented correctly.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret value could be found to match with the request's header or query parameter.</exception>
        protected async Task<string> GetSharedAccessKeyAsync(AuthorizationFilterContext context)
        {
            Guard.NotNull(context, nameof(context), "Requires a HTTP context to access the registered request dependency services");
            Guard.For(() => context.HttpContext?.RequestServices is null, new ArgumentException(
                "Requires a HTTP context with registered request dependency services", nameof(context)));
            
            ISecretProvider userDefinedSecretProvider =
                context.HttpContext.RequestServices.GetService<ICachedSecretProvider>()
                ?? context.HttpContext.RequestServices.GetService<ISecretProvider>();

            if (userDefinedSecretProvider is null)
            {
                throw new KeyNotFoundException(
                    $"No configured {nameof(ICachedSecretProvider)} or {nameof(ISecretProvider)} implementation found in the request service container. "
                    + "Please configure such an implementation (ex. in the Startup) of your application");
            }

            Task<string> rawSecretAsync = userDefinedSecretProvider.GetRawSecretAsync(SecretName);
            if (rawSecretAsync is null)
            {
                throw new InvalidOperationException(
                    $"Configured {nameof(ISecretProvider)} is not implemented correctly as it returns 'null' for a {nameof(Task)} value when calling {nameof(ISecretProvider.GetRawSecretAsync)}");
            }

            string foundSecret = await rawSecretAsync;
            if (foundSecret is null)
            {
                throw new SecretNotFoundException(SecretName);
            }

            return foundSecret;
        }

        /// <summary>
        /// Verifies that the HTTP request header's value matches the given <paramref name="accessKey"/>;
        /// placing the <paramref name="context"/>'s result to <see cref="UnauthorizedObjectResult"/> if that's not the case.
        /// </summary>
        /// <param name="context">The HTTP context where the HTTP request's header will be verified and authentication failures will be set.</param>
        /// <param name="accessKey">The secret value that should match with the HTTP request's header.</param>
        /// <param name="logger">The logger instance to write authentication security events during the verification.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="context"/> or the <paramref name="logger"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="context"/> doesn't have a HTTP request headers.</exception>
        protected void ValidateSharedAccessKeyInRequestHeader(AuthorizationFilterContext context, string accessKey, ILogger logger)
        {
            Guard.NotNull(context, nameof(context), "Requires a HTTP context to verify the shared access key in the HTTP request's header");
            Guard.NotNull(logger, nameof(logger), "Requires an logger instance to write authentication security events");
            Guard.For(() => context.HttpContext?.Request?.Query is null, new ArgumentException(
                "Requires a HTTP context with a HTTP request headers to verify the shared access key in the HTTP request's header", nameof(context)));
            
            if (String.IsNullOrWhiteSpace(HeaderName))
            {
                return;
            }

            if (context.HttpContext.Request.Headers.TryGetValue(HeaderName, out StringValues requestSecretHeaders))
            {
                if (requestSecretHeaders.Any(headerValue => headerValue != accessKey))
                {
                    LogSecurityEvent(logger, $"Shared access key in request header '{HeaderName}' doesn't match expected access key", HttpStatusCode.Unauthorized);
                    context.Result = new UnauthorizedObjectResult("Shared access key in request doesn't match expected access key");
                }
                else
                {
                    LogSecurityEvent(logger, $"Shared access key in request header '{HeaderName}' matches expected access key");
                }
            }
            else
            {
                LogSecurityEvent(logger, $"No shared access key found in request header '{HeaderName}'", HttpStatusCode.Unauthorized);
                context.Result = new UnauthorizedObjectResult("No shared access key found in request");
            }
        }

        /// <summary>
        /// Verifies that the HTTP request query parameter's value matches the given <paramref name="accessKey"/>;
        /// placing the <paramref name="context"/>'s result to <see cref="UnauthorizedObjectResult"/> if that's not the case.
        /// </summary>
        /// <param name="context">The HTTP context where the HTTP request's query parameter will be verified and authentication failures will be set.</param>
        /// <param name="accessKey">The secret value that should match with the HTTP request's query parameter.</param>
        /// <param name="logger">The logger instance to write authentication security events during the verification.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="context"/> or the <paramref name="logger"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="context"/> doesn't have a HTTP request query parameters.</exception>
        protected void ValidateSharedAccessKeyInQueryParameter(AuthorizationFilterContext context, string accessKey, ILogger logger)
        {
            Guard.NotNull(context, nameof(context), "Requires a HTTP context to verify the shared access key in the HTTP request's query parameter");
            Guard.NotNull(logger, nameof(logger), "Requires an logger instance to write authentication security events");
            Guard.For(() => context.HttpContext?.Request?.Query is null, new ArgumentException(
                "Requires a HTTP context with a HTTP request query to verify the shared access key in the HTTP request's query parameter", nameof(context)));
            
            if (String.IsNullOrWhiteSpace(QueryParameterName))
            {
                return;
            }

            if (context.HttpContext.Request.Query.ContainsKey(QueryParameterName))
            {
                if (context.HttpContext.Request.Query[QueryParameterName] != accessKey)
                {
                    LogSecurityEvent(logger, $"Shared access key in query parameter '{QueryParameterName}' doesn't match expected access key", HttpStatusCode.Unauthorized);
                    context.Result = new UnauthorizedObjectResult("Shared access key in request doesn't match expected access key");
                }
                else
                {
                    LogSecurityEvent(logger, $"Shared access key in query parameter '{QueryParameterName}' matches expected access key");
                }
            }
            else
            {
                LogSecurityEvent(logger, $"No shared access key found in query parameter '{QueryParameterName}'", HttpStatusCode.Unauthorized);
                context.Result = new UnauthorizedObjectResult("No shared access key found in request");
            }
        }

        /// <summary>
        /// Logs an event related to the shared access key authentication security activity.
        /// </summary>
        /// <param name="logger">The logger to where the security event should be written.</param>
        /// <param name="description">The description of what the authentication process has encountered.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="logger"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="description"/> is blank.</exception>
        protected void LogSecurityEvent(ILogger logger, string description)
        {
            Guard.NotNull(logger, nameof(logger), "Requires an logger instance to write an authentication security event");
            Guard.NotNullOrWhitespace(description, nameof(description), "Requires a non-blank description of what the authentication process encountered");
            
            LogSecurityEvent(logger, description, responseStatusCode: default(HttpStatusCode));
        }

        /// <summary>
        /// Logs an event related to the shared access key authentication security activity.
        /// </summary>
        /// <param name="logger">The logger to where the security event should be written.</param>
        /// <param name="description">The description of what the authentication process has encountered.</param>
        /// <param name="responseStatusCode">The response HTTP status code that relates to the authentication security activity.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="logger"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="description"/> is blank.</exception>
        protected void LogSecurityEvent(ILogger logger, string description, HttpStatusCode responseStatusCode)
        {
            Guard.NotNull(logger, nameof(logger), "Requires an logger instance to write an authentication security event");
            Guard.NotNullOrWhitespace(description, nameof(description), "Requires a non-blank description of what the authentication process encountered");

            if (!Options.EmitSecurityEvents)
            {
                return;
            }
            
            var telemetryContext = new Dictionary<string, object>
            {
                ["EventType"] = "Security",
                ["AuthenticationType"] = "Shared access key",
                ["Description"] = description
            };

            if (responseStatusCode != default(HttpStatusCode))
            {
                telemetryContext["StatusCode"] = responseStatusCode.ToString();
            }

            logger.LogSecurityEvent("Authentication", telemetryContext);
        }
    }
}
