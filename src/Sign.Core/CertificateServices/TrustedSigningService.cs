// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sign.Core.CertificateServices
{
    internal sealed class TrustedSigningService : ISignatureAlgorithmProvider, ICertificateProvider
    {
        public Task<X509Certificate2> GetCertificateAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<RSA> GetRsaAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }
}