// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.CommandLine;
using System.CommandLine.Invocation;
using Azure.Core;
using Azure.Identity;
using Sign.Core;

namespace Sign.Cli
{
    internal static class InvocationContextExtensions
    {
        public static TokenCredential? CreateCredential(this InvocationContext context, Option<bool> useManagedIdentityOption, Option<string?> tenantIdOption, Option<string?> clientIdOption, Option<string?> clientSecretOption)
        {
            bool useManagedIdentity = context.ParseResult.GetValueForOption(useManagedIdentityOption);

            if (useManagedIdentity)
            {
                return new DefaultAzureCredential();
            }

            string? tenantId = context.ParseResult.GetValueForOption(tenantIdOption);
            string? clientId = context.ParseResult.GetValueForOption(clientIdOption);
            string? clientSecret = context.ParseResult.GetValueForOption(clientSecretOption);

            if (string.IsNullOrEmpty(tenantId) ||
                string.IsNullOrEmpty(clientId) ||
                string.IsNullOrEmpty(clientSecret))
            {
                context.Console.Error.WriteFormattedLine(
                            AzureKeyVaultResources.InvalidClientSecretCredential,
                            tenantIdOption,
                            clientIdOption,
                            clientSecretOption);
                context.ExitCode = ExitCode.NoInputsFound;
                return null;
            }

            return new ClientSecretCredential(tenantId, clientId, clientSecret);
        }
    }
}
