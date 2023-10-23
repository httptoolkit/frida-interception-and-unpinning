/******************************************************************************
 *
 * This file defines various config parameters, used later within the other
 * scripts. In all cases, you'll want to set CERT_PEM and likely
 * PROXY_HOST and PROXY_PORT.
 *
 *****************************************************************************/

// Local testing certificate for now
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

// Default emulator address for now:
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 8000;

// If you find issues with non-HTTP traffic being captured (due to the
// native connect hook script) you can add ports here to exempt traffic
// on that port from being redirected. Note that this will only affect
// traffic captured by the raw connection hook - for apps using the
// system HTTP proxy settings, traffic on these ports will still be
// sent via the proxy and intercepted despite this setting.
const IGNORED_NON_HTTP_PORTS = [];

// Set to enable extra logging:
const DEBUG_MODE = false;

if (DEBUG_MODE) {
    // Add logging just for clean output & to separate reloads:
    console.log('\n*** Starting scripts ***');
    Java.perform(() => {
        setTimeout(() => console.log('*** Scripts completed ***\n'), 5);
        // (We assume that nothing else will take more than 5ms, but app startup
        // probably will, so this should separate script & runtime logs)
    });
} else {
    console.log(''); // Add just a single newline, for minimal clarity
}