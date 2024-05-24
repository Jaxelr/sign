// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using Sign.Core;
using System.CommandLine;

namespace Sign.Cli
{
    internal sealed class TrustedSigningCommand : Command
    {
        internal TrustedSigningCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
            : base("trusted-signing", AzureKeyVaultResources.CommandDescription)
        {
        }
    }
