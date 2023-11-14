/**************************************************************************************************
 *
 * Once we've set up the configuration and certificate, and then disabled all the pinning
 * techniques we're aware of, we add one last touch: a fallback hook, designed to spot and handle
 * unknown unknowns.
 *
 * This can also be useful for heavily obfuscated apps, where 3rd party libraries are obfuscated
 * sufficiently that our hooks no longer recognize the methods we care about.
 *
 * To handle this, we watch for methods that throw known built-in TLS errors (these are *very*
 * widely used, and always recognizable as they're defined natively), and then subsequently patch
 * them for all future calls. Whenever a method throws this, we attempt to recognize it from
 * signatures alone, and automatically hook it.
 *
 * These are very much a fallback! They might not work! They almost certainly won't work on the
 * first request, so applications will see at least one failure. Even when they fail though, they
 * will at least log the method that's failing, so this works well as a starting point for manual
 * reverse engineering. If this does fail and cause problems, you may want to skip this script
 * and use only the known-good patches provided elsewhere.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

// Capture the full fields or methods from a Frida class reference via JVM reflection:
const getFields = (cls) => getFridaValues(cls, cls.class.getDeclaredFields());
const getMethods = (cls) => getFridaValues(cls, cls.class.getDeclaredMethods());

// Take a Frida class + JVM reflection result, and turn it into a clear list
// of names -> Frida values (field or method references)
const getFridaValues = (cls, values) => values.map((value) =>
    [value.getName(), cls[value.getName()]]
);

Java.perform(function () {
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const defaultTrustManager = getCustomX509TrustManager(); // Defined in the unpinning script

        const isX509TrustManager = (cls, methodName) =>
            methodName === 'checkServerTrusted' &&
            X509TrustManager.class.isAssignableFrom(cls.class);

        // There are two standard methods that X509TM implementations might override. We confirm we're
        // matching the methods we expect by double-checking against the argument types:
        const BASE_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String'
        ];
        const EXTENDED_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ];

        const isOkHttpCheckMethod = (errorMessage, method) =>
            errorMessage.startsWith("Certificate pinning failure!" + "\n  Peer certificate chain:") &&
            method.argumentTypes.length === 2 &&
            method.argumentTypes[0].className === 'java.lang.String';

        const isAppmattusOkHttpInterceptMethod = (errorMessage, method) => {
            if (errorMessage !== 'Certificate transparency failed') return;

            // Takes a single OkHttp chain argument:
            if (method.argumentTypes.length !== 1) return;

            // The method must take an Interceptor.Chain, for which we need to
            // call chain.proceed(chain.request()) to return a Response type.
            // To do that, we effectively pattern match our way through all the
            // related types to work out what's what:

            const chainType = Java.use(method.argumentTypes[0].className);
            const responseTypeName = method.returnType.className;

            const matchedChain = matchOkHttpChain(chainType, responseTypeName);
            return !!matchedChain;
        };

        const matchOkHttpChain = (cls, expectedReturnTypeName) => {
            // Find the chain.proceed() method:
            const methods = getMethods(cls);
            const matchingMethods = methods.filter(([_, method]) =>
                method.returnType.className === expectedReturnTypeName
            );
            if (matchingMethods.length !== 1) return;

            const [proceedMethodName, proceedMethod] = matchingMethods[0];
            if (proceedMethod.argumentTypes.length !== 1) return;

            const argumentTypeName = proceedMethod.argumentTypes[0].className;

            // Find the chain.request private field (.request() getter can be
            // optimized out, so we read the field directly):
            const fields = getFields(cls);
            const matchingFields = fields.filter(([_, field]) =>
                field.fieldReturnType?.className === argumentTypeName
            );
            if (matchingFields.length !== 1) return;

            const [requestFieldName] = matchingFields[0];

            return {
                proceedMethodName,
                requestFieldName
            };
        };

        const buildUnhandledErrorPatcher = (errorClassName, originalConstructor) => {
            return function (errorArg) {
                try {
                    console.log('\n !!! --- Unexpected TLS failure --- !!!');

                    // This may be a message, or an cause, or plausibly maybe other types? But
                    // stringifying gives something consistently message-shaped, so that'll do.
                    const errorMessage = errorArg?.toString() ?? '';

                    // Parse the stack trace to work out who threw this error:
                    const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === errorClassName
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    const errorTypeName = errorClassName.split('.').slice(-1)[0];
                    console.log(`      ${errorTypeName}: ${errorMessage}`);
                    console.log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    callingMethod.overloads.forEach((failingMethod) => {
                        if (failingMethod.implementation) {
                            console.warn('      Already patched - but still failing!')
                            return; // Already patched by Frida - skip it
                        }

                        // Try to spot known methods (despite obfuscation) and disable them:
                        if (isOkHttpCheckMethod(errorMessage, failingMethod)) {
                            // See okhttp3.CertificatePinner patches in unpinning script:
                            failingMethod.implementation = () => {
                                if (DEBUG_MODE) console.log(` => Fallback OkHttp patch`);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback OkHttp patch)`);
                        } else if (isAppmattusOkHttpInterceptMethod(errorMessage, failingMethod)) {
                            // See Appmattus CertificateTransparencyInterceptor patch in unpinning script:
                            const chainType = Java.use(failingMethod.argumentTypes[0].className);
                            const responseTypeName = failingMethod.returnType.className;
                            const okHttpChain = matchOkHttpChain(chainType, responseTypeName);
                            failingMethod.implementation = (chain) => {
                                if (DEBUG_MODE) console.log(` => Fallback Appmattus+OkHttp patch`);
                                const proceed = chain[okHttpChain.proceedMethodName].bind(chain);
                                const request = chain[okHttpChain.requestFieldName].value;
                                return proceed(request);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback Appmattus+OkHttp patch)`);
                        } else if (isX509TrustManager(callingClass, methodName)) {
                            const argumentTypes = failingMethod.argumentTypes.map(t => t.className);
                            const returnType = failingMethod.returnType.className;

                            if (
                                argumentTypes.length === 2 &&
                                argumentTypes.every((t, i) => t === BASE_METHOD_ARGUMENTS[i]) &&
                                returnType === 'void'
                            ) {
                                // For the base method, just check against the default:
                                failingMethod.implementation = (certs, authType) => {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } base method`);

                                    const defaultTrustManager = getCustomX509TrustManager(); // Defined in the unpinning script
                                    defaultTrustManager.checkServerTrusted(certs, authType);
                                };
                                console.log(`      [+] ${className}->${methodName} (fallback X509TrustManager base patch)`);
                            } else if (
                                argumentTypes.length === 3 &&
                                argumentTypes.every((t, i) => t === EXTENDED_METHOD_ARGUMENTS[i]) &&
                                returnType === 'java.util.List'
                            ) {
                                // For the extended method, we just ignore the hostname, and if the certs are good
                                // (i.e they're ours), then we say the whole chain is good to go:
                                failingMethod.implementation = function (certs, authType, _hostname) {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } extended method`);

                                    try {
                                        defaultTrustManager.checkServerTrusted(certs, authType);
                                    } catch (e) {
                                        console.error('Default TM threw:', e);
                                    }
                                    return Java.use('java.util.Arrays').asList(certs);
                                };
                                console.log(`      [+] ${className}->${methodName} (fallback X509TrustManager ext patch)`);
                            } else {
                                console.warn(`      [ ] Skipping unrecognized checkServerTrusted signature in class ${
                                    callingClass.class.getName()
                                }`);
                            }
                        } else {
                            console.error('      [ ] Unrecognized TLS error - this must be patched manually');
                            return;
                            // Later we could try to cover other cases here - automatically recognizing other
                            // OkHttp interceptors for example, or potentially other approaches, but we need
                            // to do so carefully to avoid disabling TLS checks entirely.
                        }
                    });
                } catch (e) {
                    console.log('      [ ] Failed to automatically patch failure');
                    console.warn(e);
                }

                return originalConstructor.call(this, ...arguments);
            }
        };

        // These are the exceptions we watch for and attempt to auto-patch out after they're thrown:
        [
            'javax.net.ssl.SSLPeerUnverifiedException',
            'java.security.cert.CertificateException'
        ].forEach((errorClassName) => {
            const ErrorClass = Java.use(errorClassName);
            ErrorClass.$init.overloads.forEach((overload) => {
                overload.implementation = buildUnhandledErrorPatcher(
                    errorClassName,
                    overload
                );
            });
        })

        console.log('== Unpinning fallback auto-patcher installed ==');
    } catch (err) {
        console.error(err);
        console.error(' !!! --- Unpinning fallback auto-patcher installation failed --- !!!');
    }

});