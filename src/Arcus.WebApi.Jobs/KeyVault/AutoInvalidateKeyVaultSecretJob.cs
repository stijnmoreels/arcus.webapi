﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Messaging.Abstractions;
using Arcus.Messaging.Pumps.ServiceBus;
using Arcus.Security.Core.Caching;
using CloudNative.CloudEvents;
using GuardNet;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Rest.Azure;

namespace Arcus.WebApi.Jobs.KeyVault
{
    /// <summary>
    /// Message pump implementation to automatically invalidate Azure Key Vault secrets based on the <see cref="SecretNewVersionCreated"/> emitted event.
    /// </summary>
    public class AutoInvalidateKeyVaultSecretJob : TempSubscriptionAzureServiceBusMessagePump<CloudEvent>
    {
        private static readonly JsonEventFormatter JsonEventFormatter = new JsonEventFormatter();

        /// <summary>Constructor</summary>
        /// <param name="configuration">Configuration of the application</param>
        /// <param name="serviceProvider">Collection of services that are configured</param>
        /// <param name="logger">Logger to write telemetry to</param>
        public AutoInvalidateKeyVaultSecretJob(
            IConfiguration configuration,
            IServiceProvider serviceProvider,
            ILogger logger) : base(configuration, serviceProvider, logger)
        {
        }

        /// <inheritdoc />
        protected override async Task ProcessMessageAsync(
            CloudEvent message,
            AzureServiceBusMessageContext messageContext,
            MessageCorrelationInfo correlationInfo,
            CancellationToken cancellationToken)
        {
            var secretNewVersionCreated = message.GetPayload<SecretNewVersionCreated>();
            if (secretNewVersionCreated is null)
            {
                throw new CloudException("Azure Key Vault job cannot map EventGrid event to CloudEvent with 'SecretNewVersionCreated' data");
            }

            var secretProvider = ServiceProvider.GetService<ICachedSecretProvider>();
            if (secretProvider is null)
            {
                throw new KeyNotFoundException(
                    $"No {nameof(ICachedSecretProvider)} implementation in the services dependency injection container was found to invalidate the cached secret");
            }

            await secretProvider.InvalidateSecretAsync(secretNewVersionCreated.ObjectName);
            Logger.LogInformation($"Invalidated Azure KeyVault secret in '{secretProvider.GetType().Name}'");
        }

        /// <summary>
        /// Deserializes a raw JSON message body.
        /// </summary>
        /// <param name="rawMessageBody">Raw message body to deserialize</param>
        /// <param name="messageContext">Context concerning the message</param>
        /// <returns>Deserialized message</returns>
        protected override CloudEvent DeserializeJsonMessageBody(byte[] rawMessageBody, MessageContext messageContext)
        {
            Guard.NotNull(rawMessageBody, nameof(rawMessageBody), "Cannot deserialize raw JSON body from 'null' input");
            Guard.NotAny(rawMessageBody, nameof(rawMessageBody), "Cannot deserialize raw JSON body from empty input");

            CloudEvent cloudEvent = JsonEventFormatter.DecodeStructuredEvent(rawMessageBody);
            return cloudEvent;
        }
    }
}