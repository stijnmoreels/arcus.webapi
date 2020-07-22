﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Xunit;

namespace Arcus.WebApi.Tests.Integration.Logging.Correlation
{
    public class AzureFunctionCorrelationTests
    {
        private const string DefaultOperationId = "RequestId",
                             DefaultTransactionId = "X-Transaction-ID",
                            DefaultRoute = "http://localhost:5000/";

        private static readonly HttpClient HttpClient = new HttpClient();

        [Fact]
        public async Task SendRequest_WithoutCorrelationHeaders_ResponseWithCorrelationHeadersAndCorrelationAccess()
        {
            // Act
            using (HttpResponseMessage response = await HttpClient.GetAsync(DefaultRoute))
            {
                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);

                string correlationId = GetResponseHeader(response, DefaultTransactionId);
                string requestId = GetResponseHeader(response, DefaultOperationId);

                string json = await response.Content.ReadAsStringAsync();
                var content = JsonConvert.DeserializeAnonymousType(json, new { TransactionId = "", OperationId = "" });
                Assert.False(String.IsNullOrWhiteSpace(content.TransactionId), "Accessed 'X-Transaction-ID' cannot be blank");
                Assert.False(String.IsNullOrWhiteSpace(content.OperationId), "Accessed 'X-Operation-ID' cannot be blank");

                Assert.Equal(correlationId, content.TransactionId);
                Assert.Equal(requestId, content.OperationId);
            }
        }

        [Fact]
        public async Task SendRequest_WithCorrelationHeader_ResponseWithSameCorrelationHeader()
        {
            // Arrange
            string expected = $"transaction-{Guid.NewGuid()}";
            var request = new HttpRequestMessage(HttpMethod.Get, DefaultRoute);
            request.Headers.Add(DefaultTransactionId, expected);

            // Act
            using (HttpResponseMessage response = await HttpClient.SendAsync(request))
            {
                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);

                string actual = GetResponseHeader(response, DefaultTransactionId);
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task SendRequest_WithRequestIdHeader_ResponseWithDifferentRequestIdHeader()
        {
            // Arrange
            string expected = $"operation-{Guid.NewGuid()}";
            var request = new HttpRequestMessage(HttpMethod.Get, DefaultRoute);
            request.Headers.Add(DefaultOperationId, expected);

            // Act
            using (HttpResponseMessage response = await HttpClient.SendAsync(request))
            {
                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);

                string actual = GetResponseHeader(response, DefaultOperationId);
                Assert.NotEqual(expected, actual);
            }
        }

        private static string GetResponseHeader(HttpResponseMessage response, string headerName)
        {
            (string key, IEnumerable<string> values) = Assert.Single(response.Headers, header => header.Key == headerName);

            Assert.NotNull(values);
            string value = Assert.Single(values);
            Assert.False(String.IsNullOrWhiteSpace(value), $"Response header '{headerName}' cannot be blank");

            return value;
        }
    }
}
