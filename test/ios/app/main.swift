/**
 * A minimal iOS app to intercept, built & installed by setup-simulator.sh.
 *
 * It repeatedly makes the requests the tests want to see, and appends each result to a file in
 * its own data container, which the tests read from the host. That's the equivalent of the
 * Android tests tapping the demo app's buttons and reading the results back from the UI, except
 * that iOS has no UI automation available to us (see IMPROVEMENTS.md) so the app drives itself.
 *
 * Deliberately not the iOS pinning demo: its dependencies don't currently build against recent
 * SDKs, and testing its pinning cases individually would need exactly the UI automation we don't
 * have. This covers the paths our scripts hook, which is what these tests are about.
 */

import UIKit

private let requestInterval: TimeInterval = 5

// A first round early enough to keep the tests quick, but not so early that it could race the
// scripts' own setup, which happens as the process starts:
private let firstRequestDelay: TimeInterval = 3

private let resultsPath = NSSearchPathForDirectoriesInDomains(
    .documentDirectory, .userDomainMask, true
)[0] + "/results.jsonl"

// One writer, so that results from concurrent requests can't interleave mid-line:
private let resultsQueue = DispatchQueue(label: "tech.httptoolkit.test-app.results")

private func record(_ name: String, status: Int? = nil, body: String? = nil, error: String? = nil) {
    var result: [String: Any] = ["case": name]
    if let status = status { result["status"] = status }
    // Truncated: we only ever compare this against the proxy's (short) mocked response, and the
    // real responses these fall back to are entire web pages:
    if let body = body { result["body"] = String(body.prefix(100)) }
    if let error = error { result["error"] = error }

    let outcome = error ?? (status.map { "status \($0)" } ?? "no status")
    NSLog("TEST-APP: \(name): \(outcome)")

    resultsQueue.async {
        guard var data = try? JSONSerialization.data(withJSONObject: result) else { return }
        data.append(0x0a) // A newline, so the tests can read this as it's written

        if let file = FileHandle(forWritingAtPath: resultsPath) {
            file.seekToEndOfFile()
            file.write(data)
            file.closeFile()
        } else {
            try? data.write(to: URL(fileURLWithPath: resultsPath))
        }
    }
}

// Ephemeral & uncached, so that a result from an earlier round (or an earlier launch) can never
// be served back to us as if it were this one's:
private let session: URLSession = {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    configuration.urlCache = nil
    return URLSession(configuration: configuration)
}()

/// A request through the app's own HTTP stack, i.e. CFNetwork on top of Network framework.
private func sendRequest(_ name: String, _ url: String) {
    session.dataTask(with: URL(string: url)!) { data, response, error in
        if let error = error {
            record(name, error: error.localizedDescription)
        } else {
            record(name,
                status: (response as? HTTPURLResponse)?.statusCode,
                body: String(decoding: data ?? Data(), as: UTF8.self)
            )
        }
    }.resume()
}

/// A request over a raw BSD socket, which reaches the network without Network framework at all,
/// so only the native connect() hook can redirect it.
private func sendRawRequest(_ name: String, host: String, port: UInt16, path: String) {
    DispatchQueue.global().async {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM

        var addresses: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &addresses) == 0,
              let address = addresses else {
            return record(name, error: "Could not resolve \(host)")
        }
        defer { freeaddrinfo(addresses) }

        let socketFd = socket(
            address.pointee.ai_family,
            address.pointee.ai_socktype,
            address.pointee.ai_protocol
        )
        guard socketFd >= 0 else {
            return record(name, error: "Could not open a socket: \(errorMessage())")
        }
        defer { close(socketFd) }

        // Otherwise a destination that accepts the connection but never answers would hang this
        // thread indefinitely, and the tests would see nothing at all rather than a failure:
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        guard connect(socketFd, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 else {
            return record(name, error: "Could not connect: \(errorMessage())")
        }

        let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
        guard request.withCString({ write(socketFd, $0, strlen($0)) }) > 0 else {
            return record(name, error: "Could not send the request: \(errorMessage())")
        }

        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while response.count < 16384 {
            let received = read(socketFd, &buffer, buffer.count)
            if received <= 0 { break }
            response.append(contentsOf: buffer[0..<received])
        }

        if response.isEmpty {
            return record(name, error: "No response: \(errorMessage())")
        }

        let text = String(decoding: response, as: UTF8.self)
        let headersAndBody = text.components(separatedBy: "\r\n\r\n")
        let statusLine = headersAndBody[0].components(separatedBy: "\r\n")[0]

        record(name,
            status: Int(statusLine.split(separator: " ").dropFirst().first ?? ""),
            body: headersAndBody.count > 1 ? headersAndBody[1] : ""
        )
    }
}

private func errorMessage() -> String {
    return String(cString: strerror(errno))
}

private func sendAllRequests() {
    sendRequest("https", "https://example.com/https-request")
    sendRequest("http", "http://example.com/http-request")
    sendRawRequest("raw", host: "example.com", port: 80, path: "/raw-request")
}

class AppDelegate: NSObject, UIApplicationDelegate {

    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        let controller = UIViewController()
        controller.view.backgroundColor = .white
        window?.rootViewController = controller
        window?.makeKeyAndVisible()

        NSLog("TEST-APP: launched")

        // Repeated, so that a test can always wait for a fresh round rather than depending on
        // when exactly it launched us:
        Timer.scheduledTimer(withTimeInterval: firstRequestDelay, repeats: false) { _ in
            sendAllRequests()
            Timer.scheduledTimer(withTimeInterval: requestInterval, repeats: true) { _ in
                sendAllRequests()
            }
        }

        return true
    }

}

UIApplicationMain(
    CommandLine.argc,
    CommandLine.unsafeArgv,
    nil,
    NSStringFromClass(AppDelegate.self)
)
