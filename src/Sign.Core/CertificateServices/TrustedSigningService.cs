// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;

namespace Sign.Core.CertificateServices
{
    internal class TrustedSigningService : ISignatureAlgorithmProvider, ICertificateProvider
    {
        private RSATrustedSigning _rsa;

        public TrustedSigningService(
            IServiceProvider serviceProvider,
            TokenCredential credential,
            Uri endpoint,
            string accountName,
            string certificateProfileName)
        {
            _rsa = new RSATrustedSigning(serviceProvider, credential, endpoint, accountName, certificateProfileName);
        }

        public Task<X509Certificate2> GetCertificateAsync(CancellationToken cancellationToken)
            => _rsa.GetPublicKeyAsync(cancellationToken);

        public Task<RSA> GetRsaAsync(CancellationToken cancellationToken)
            => Task.FromResult<RSA>(_rsa);
    }
}
