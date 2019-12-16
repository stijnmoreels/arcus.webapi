﻿namespace Arcus.WebApi.Correlation
{
    /// <summary>
    /// Correlation options specific for the operation ID.
    /// </summary>
    public class CorrelationOptionsOperation
    {
        /// <summary>
        /// Gets or sets whether to include the operation ID in the response.
        /// </summary>
        /// <remarks>
        ///     A common use case is to disable tracing info in edge services, so that such details are not exposed to the outside world.
        /// </remarks>
        public bool IncludeInResponse { get; set; } = true;
    }
}
