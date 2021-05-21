using Safewhere.ServiceProvider;
using Safewhere.ServiceProvider.Config;
using Safewhere.ServiceProvider.Util;
using System;
using System.IdentityModel.Selectors;

namespace WebsiteDemo
{
    /// <summary>
    /// A factory which returns X509CertificateSigningSecurityTokenResolverFactory for signing key resolver.
    /// </summary>
    public class X509CertificateSigningSecurityTokenResolverFactory : DefaultSecurityTokenResolverFactory
    {
        public X509CertificateSigningSecurityTokenResolverFactory()
            : this(new CertificateHandler()) { }

        public X509CertificateSigningSecurityTokenResolverFactory(CertificateHandler certificateHandler)
            : base(certificateHandler)
        {
        }

        public override SecurityTokenResolver CreateEncryptionKeyResolver(
            ServiceProviderConfiguration serviceProviderConfiguration,
            SecurityTokenResolver myTokenResolver,
            IIdentityProviderHandler idpHandler)
        {
            if (serviceProviderConfiguration == null)
                throw new ArgumentNullException(nameof(serviceProviderConfiguration));
            if (myTokenResolver == null)
                throw new ArgumentNullException(nameof(myTokenResolver));
            if (idpHandler == null)
                throw new ArgumentNullException(nameof(idpHandler));

            var certificate = certificateHandler.GetCertificate();
            var encryptionKeyResolver = new ExtendedX509CertificateEncryptionKeyTokenResolver(certificate);

            return encryptionKeyResolver;
        }

        public override SecurityTokenResolver CreateSigningKeyResolver(ServiceProviderConfiguration serviceProviderConfiguration,
                                                                      SecurityTokenResolver trustedTokenResolver,
                                                                      IIdentityProviderHandler idpHandler)
        {
            if (serviceProviderConfiguration == null)
                throw new ArgumentNullException(nameof(serviceProviderConfiguration));
            if (trustedTokenResolver == null)
                throw new ArgumentNullException(nameof(trustedTokenResolver));
            if (idpHandler == null)
                throw new ArgumentNullException(nameof(idpHandler));

            var signingKeyResolver =
                new X509CertificateSigningKeyTokenResolver(idpHandler, serviceProviderConfiguration);

            return signingKeyResolver;
        }
    }
}