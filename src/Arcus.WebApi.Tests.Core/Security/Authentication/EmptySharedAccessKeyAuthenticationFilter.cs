using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.WebApi.Security.Authentication.SharedAccessKey;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Arcus.WebApi.Tests.Core.Security.Authentication
{
    /// <summary>
    /// Represents a stubbed-out <see cref="SharedAccessKeyAuthenticationFilter"/>.
    /// </summary>
    public class StubSharedAccessKeyAuthenticationFilter : SharedAccessKeyAuthenticationFilter
    {
        /// <inheritdoc />
        public StubSharedAccessKeyAuthenticationFilter(string headerName, string queryParameterName, string secretName) 
            : base(headerName, queryParameterName, secretName)
        {
        }

        /// <inheritdoc />
        public StubSharedAccessKeyAuthenticationFilter(string headerName, string queryParameterName, string secretName, SharedAccessKeyAuthenticationOptions options) 
            : base(headerName, queryParameterName, secretName, options)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="StubSharedAccessKeyAuthenticationFilter" /> class.
        /// </summary>
        public StubSharedAccessKeyAuthenticationFilter() : this("x-api-key", queryParameterName: null, secretName: "MySecret")
        {
        }

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
        public override Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            return Task.CompletedTask;
        }
    }
}
