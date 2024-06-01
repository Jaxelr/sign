// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure;
using Azure.CodeSigning;
using Azure.CodeSigning.Models;
using Azure.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Sign.Core
{
    internal sealed class RSATrustedSigning : RSA
    {
        private static readonly SignRequest _emptyRequest = new(Azure.CodeSigning.Models.SignatureAlgorithm.RS256, new byte[32]);
        private readonly CertificateProfileClient _client;
        private readonly string _accountName;
        private readonly string _certificateProfileName;
        private readonly SemaphoreSlim _mutex = new(1);
        private X509Certificate2? _publicKey;

        private readonly ILogger<RSATrustedSigning> _logger;


        public RSATrustedSigning(
            IServiceProvider serviceProvider,
            TokenCredential credential,
            Uri endpoint,
            string accountName,
            string certificateProfileName)
        {
            _client = new(credential, endpoint);
            _accountName = accountName;
            _certificateProfileName = certificateProfileName;

            _logger = serviceProvider.GetRequiredService<ILogger<RSATrustedSigning>>();
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                throw new NotSupportedException();
            }

            return GetRSAPublicKey().ExportParameters(false);
        }

        public override void ImportParameters(RSAParameters parameters)
            => new NotImplementedException();

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            var signatureAlgorithm = GetSignatureAlgorithm(hash, padding);
            SignRequest request = new(signatureAlgorithm, hash);
            Response<SignStatus> response = Sign(request);
            return response.Value.Signature;
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => GetRSAPublicKey().VerifyHash(hash, signature, hashAlgorithm, padding);

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            using HashAlgorithm hasher = CreateHasher(hashAlgorithm);
            return hasher.ComputeHash(data, offset, count);
        }

        internal async Task<X509Certificate2> GetPublicKeyAsync(CancellationToken cancellationToken)
        {
            if (_publicKey is not null)
            {
                return new X509Certificate2(_publicKey);
            }

            await _mutex.WaitAsync(cancellationToken);
            try
            {
                if (_publicKey is null)
                {
                    Response<SignStatus> response = await SignAsync(_emptyRequest, cancellationToken);

                    byte[] rawData = Convert.FromBase64String(Encoding.UTF8.GetString(response.Value.SigningCertificate));
                    X509Certificate2Collection collection = new();
                    collection.Import(rawData);

                    _publicKey = collection[collection.Count - 1];
                }
            }
            finally
            {
                _mutex.Release();
            }

            return new X509Certificate2(_publicKey);
        }

        private RSA GetRSAPublicKey()
        {
            var publicKey = _publicKey;

            if (publicKey is null)
            {
                // It more likely that the GetPublicKeyAsync was already called and the public key was loaded.
                publicKey = GetPublicKeyAsync(CancellationToken.None).GetAwaiter().GetResult();
            }

            return RSACertificateExtensions.GetRSAPublicKey(publicKey)!;
        }

        private Response<SignStatus> Sign(SignRequest request)
        {
            CertificateProfileSignOperation operation = _client.StartSign(_accountName, _certificateProfileName, request);
            Response<SignStatus> response = operation.WaitForCompletion();
            return response;
        }

        private async Task<Response<SignStatus>> SignAsync(SignRequest request, CancellationToken cancellationToken)
        {
            CertificateProfileSignOperation operation = await _client.StartSignAsync(_accountName, _certificateProfileName, request, cancellationToken: cancellationToken);
            Response<SignStatus> response = await operation.WaitForCompletionAsync(cancellationToken);
            return response;
        }

        private static SignatureAlgorithm GetSignatureAlgorithm(byte[] digest, RSASignaturePadding padding)
            => digest.Length switch
            {
                32 => padding == RSASignaturePadding.Pss ? Azure.CodeSigning.Models.SignatureAlgorithm.PS256 : Azure.CodeSigning.Models.SignatureAlgorithm.RS256,
                48 => padding == RSASignaturePadding.Pss ? Azure.CodeSigning.Models.SignatureAlgorithm.PS384 : Azure.CodeSigning.Models.SignatureAlgorithm.RS384,
                64 => padding == RSASignaturePadding.Pss ? Azure.CodeSigning.Models.SignatureAlgorithm.PS512 : Azure.CodeSigning.Models.SignatureAlgorithm.RS512,
                _ => throw new NotSupportedException(),
            };

        private static HashAlgorithm CreateHasher(HashAlgorithmName hashAlgorithm)
            => hashAlgorithm.Name switch
            {
                nameof(SHA256) => SHA256.Create(),
                nameof(SHA384) => SHA384.Create(),
                nameof(SHA512) => SHA512.Create(),
                _ => throw new NotSupportedException(),
            };
    }
}
