﻿using Arcus.WebApi.Logging.Correlation;
using GuardNet;

// ReSharper disable once CheckNamespace
namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Adds the <see cref="CorrelationMiddleware"/> to the application pipeline.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class IApplicationBuilderExtensions
    {
        /// <summary>
        /// Adds operation and transaction correlation to the application by using the <see cref="CorrelationMiddleware"/> in the request pipeline.
        /// </summary>
        public static IApplicationBuilder UseHttpCorrelation(this IApplicationBuilder applicationBuilder)
        {
            Guard.NotNull(applicationBuilder, nameof(applicationBuilder));

            applicationBuilder.UseMiddleware<CorrelationMiddleware>();

            return applicationBuilder;
        }
    }
}