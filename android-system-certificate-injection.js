const CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIRClDpdJeylUmDvNyq5qq+plcwDQYJKoZIhvcNAQELBQAw
QTEYMBYGA1UEAxMPSFRUUCBUb29sa2l0IENBMQswCQYDVQQGEwJYWDEYMBYGA1UE
ChMPSFRUUCBUb29sa2l0IENBMB4XDTIyMTIyNTE5MDQ1MFoXDTIzMTIyNjE5MDQ1
MFowQTEYMBYGA1UEAxMPSFRUUCBUb29sa2l0IENBMQswCQYDVQQGEwJYWDEYMBYG
A1UEChMPSFRUUCBUb29sa2l0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAz4pwm0pLDvf8qVmAiOi2cvu8xDgboetoLWBoONOY2wvoEFRylLUGaieP
UG5Yuofcj798uYPEqPLoF2ugnw8J/lhYhkMqTEbuqoyZT7DooBiqtSbm4b++T/Zt
F6YnpkYeWIkv88UJaRvLG8OHytVbiC71JQ/DFCEjzNzATCKT7UFqyF4ZsT3cnGJe
3x1iiSzWxJsnDkNZmiQ+IDYSM/dx7RJYwrXO5oWbAHC7otdC66O9eB1uBYq9I8gU
4FcVKHbWAH1BYbsoF/pQJLz2mAXD7E92/Vvho7FgTKYOUq0b58LF9UHt+gDRUGUC
L4HtuMeb/Ckiwyoej50jqI//ER1XswIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/
MA4GA1UdDwEB/wQEAwIBxjAdBgNVHQ4EFgQUfsk69D2mzcAFjDX0GV53o3gySMMw
DQYJKoZIhvcNAQELBQADggEBAH08sPexRXFxzuIVWD1aUoarYq8FwNBP+xusgZcg
DmRKr0FpEyUjBxgVIsmd44WSX/TWdXokdd7aLPVnjwQbq2mhYtXAn4aIRn3QBNaj
TvFQovVy+LCSRwZjvlpr/KJnXlVMrqLIxP++I6FqLO5G5zJ+qDF39C7RUkkMpvmU
tiS70/zpt2LSfLUNtnS287P9s4wXEwbrkOOY6oNgKDz7jtNua0ZiPq2uGdqrkyZ2
VPgirbNnuoC1uZmuy0Mvih4+8xrvJWHb9QO7JOH3cXA+ZiZ945V+viMEnV0YkQB6
FL11l3fE9xzkPv357Z3e7QULnC8vDRgFAossuh8WBhNjjmo=
-----END CERTIFICATE-----`;

Java.perform(() => {
    // First, we build a JVM representation of our certificate:
    const String = Java.use("java.lang.String");
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');

    const certFactory = CertFactory.getInstance("X.509");
    const certBytes = String.$new(CERT_PEM).getBytes();
    const cert = certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));

    // Then we hook TrustedCertificateIndex. This is used for caching known trusted certs within Conscrypt -
    // by prepopulating all instances, we ensure that all TrustManagerImpls (and potentially other
    // things) automatically trust our certificate specifically (without disabling validation entirely).
    // This should apply to Android v7+ - previous versions used SSLContext & X509TrustManager.
    const TrustedCertificateIndex = Java.use('com.android.org.conscrypt.TrustedCertificateIndex');
    TrustedCertificateIndex.$init.overloads.forEach((overload) => {
        overload.implementation = function () {
            this.$init(...arguments);
            // Index our cert as already trusted, right from the start:
            this.index(cert);
        }
    });

    TrustedCertificateIndex.reset.overloads.forEach((overload) => {
        overload.implementation = function () {
            const result = this.reset(...arguments);
            // Index our cert in here again, since the reset removes it:
            this.index(cert);
            return result;
        };
    });

    // This effectively adds us to the system certs, and also defeats quite a bit of basic certificate
    // pinning too! It auto-trusts us in any implementation that uses TrustManagerImpl (Conscrypt) as
    // the underlying cert checking component.

    console.log('Inject system certificate trust');
});