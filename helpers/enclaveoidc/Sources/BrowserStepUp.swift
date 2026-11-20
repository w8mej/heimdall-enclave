import AppKit
import AuthenticationServices
import CryptoKit
import Darwin
import Foundation
import Security

/// Public-client OAuth code flow. The authentication UI runs in the system
/// authentication browser, outside both this process and custody. Custody still
/// verifies the genuine signed ID token and every inherited factor itself.
final class BrowserStepUp: NSObject, ASWebAuthenticationPresentationContextProviding, URLSessionDataDelegate, URLSessionTaskDelegate {
    private let request: BrokerRequest
    private let identityPath: String
    private let oauthPath: String
    private let identityDigest: Data
    private let oauthDigest: Data
    private let identity: BrokerIdentityConfig
    private let oauth: BrokerOAuthConfig
    private var fd: Int32
    private var complete: (() -> Void)?
    private var authentication: ASWebAuthenticationSession?
    private var network: URLSession?
    private var task: URLSessionDataTask?
    private var responseBytes = Data()
    private var responseAccepted = false
    private var timer: Timer?
    private var verifier = ""
    private var state = ""
    private var anchor: NSWindow
    private var done = false

    init(request: BrokerRequest, connection: Int32, identityPath: String, oauthPath: String,
         identity: BrokerIdentityConfig, oauth: BrokerOAuthConfig, identityDigest: Data, oauthDigest: Data,
         complete: @escaping () -> Void) {
        self.request = request; self.fd = connection; self.identityPath = identityPath; self.oauthPath = oauthPath
        self.identity = identity; self.oauth = oauth; self.identityDigest = identityDigest; self.oauthDigest = oauthDigest
        self.complete = complete
        anchor = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1), styleMask: [], backing: .buffered, defer: false)
        anchor.sharingType = .none
        super.init()
    }

    static func randomURLToken() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        defer { _ = bytes.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw BrokerFailure.refused }
        return base64URL(Data(bytes))
    }
    static func base64URL(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func current() -> Bool {
        guard !done, HelperWire.nowNs() < request.deadline, !HelperWire.connectionChanged(fd),
              PeerIdentity.verifyCustody(fd), BrokerSession.matches(request.uid, request.audit),
              let (currentIdentity, identityHash) = try? BrokerIdentityConfig.load(identityPath),
              let (currentOAuth, oauthHash) = try? BrokerOAuthConfig.load(oauthPath),
              identityHash == identityDigest, oauthHash == oauthDigest,
              currentIdentity.expires_unix > Int64(Date().timeIntervalSince1970),
              currentOAuth.expires_unix > Int64(Date().timeIntervalSince1970) else { return false }
        return true
    }

    func start() {
        guard current() else { finish(); return }
        do {
            verifier = try Self.randomURLToken(); state = try Self.randomURLToken()
            let challenge = Self.base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
            guard var url = URLComponents(string: oauth.authorization_endpoint) else { throw BrokerFailure.refused }
            url.queryItems = [URLQueryItem(name: "response_type", value: "code"),
                URLQueryItem(name: "client_id", value: oauth.client_id), URLQueryItem(name: "redirect_uri", value: oauth.redirect_uri),
                URLQueryItem(name: "scope", value: "openid"), URLQueryItem(name: "state", value: state),
                URLQueryItem(name: "nonce", value: request.nonce), URLQueryItem(name: "code_challenge", value: challenge),
                URLQueryItem(name: "code_challenge_method", value: "S256"), URLQueryItem(name: "max_age", value: "0"),
                URLQueryItem(name: "prompt", value: "login"), URLQueryItem(name: "audience", value: oauth.audience)]
            guard let url = url.url else { throw BrokerFailure.refused }
            let authentication = ASWebAuthenticationSession(url: url, callbackURLScheme: oauth.callback_scheme) { [weak self] callback, error in
                DispatchQueue.main.async {
                    guard let self, self.current(), error == nil, let callback else { self?.finish(); return }
                    self.callback(callback)
                }
            }
            authentication.prefersEphemeralWebBrowserSession = true
            authentication.presentationContextProvider = self
            self.authentication = authentication
            let timer = Timer(timeInterval: 0.02, repeats: true) { [weak self] _ in
                guard let self else { return }; if !self.current() { self.finish() }
            }
            self.timer = timer; RunLoop.main.add(timer, forMode: .common)
            guard current(), authentication.start() else { throw BrokerFailure.refused }
        } catch { finish() }
    }

    static func authorizationCode(_ callback: URL, redirect: String, state: String) throws -> String {
        guard var parts = URLComponents(url: callback, resolvingAgainstBaseURL: false), parts.fragment == nil,
              let query = parts.queryItems else { throw BrokerFailure.refused }
        parts.query = nil
        guard parts.url?.absoluteString == redirect else { throw BrokerFailure.refused }
        var fields = [String: String]()
        for item in query {
            guard ["code", "state", "iss"].contains(item.name), fields[item.name] == nil,
                  let value = item.value else { throw BrokerFailure.refused }
            fields[item.name] = value
        }
        guard fields["state"] == state, let code = fields["code"], !code.isEmpty,
              code.utf8.count <= 4096, !code.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw BrokerFailure.refused }
        return code
    }

    private func callback(_ callback: URL) {
        guard current() else { finish(); return }
        do {
            let code = try Self.authorizationCode(callback, redirect: oauth.redirect_uri, state: state)
            if let issuer = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "iss" })?.value,
               issuer != oauth.issuer { throw BrokerFailure.refused }
            guard let endpoint = BrokerOAuthConfig.https(oauth.token_endpoint) else { throw BrokerFailure.refused }
            var form = URLComponents()
            form.queryItems = [URLQueryItem(name: "grant_type", value: "authorization_code"),
                URLQueryItem(name: "client_id", value: oauth.client_id), URLQueryItem(name: "redirect_uri", value: oauth.redirect_uri),
                URLQueryItem(name: "code", value: code), URLQueryItem(name: "code_verifier", value: verifier)]
            guard let body = form.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B").data(using: .utf8) else { throw BrokerFailure.refused }
            var tokenRequest = URLRequest(url: endpoint)
            tokenRequest.httpMethod = "POST"; tokenRequest.httpBody = body
            tokenRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            tokenRequest.setValue("application/json", forHTTPHeaderField: "Accept")
            tokenRequest.cachePolicy = .reloadIgnoringLocalCacheData
            let now = HelperWire.nowNs()
            guard now < request.deadline else { throw BrokerFailure.refused }
            let remaining = Double(request.deadline - now) / 1_000_000_000
            tokenRequest.timeoutInterval = remaining
            let configuration = URLSessionConfiguration.ephemeral
            configuration.urlCache = nil; configuration.httpCookieStorage = nil; configuration.urlCredentialStorage = nil
            configuration.httpShouldSetCookies = false; configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.timeoutIntervalForRequest = remaining; configuration.timeoutIntervalForResource = remaining
            let network = URLSession(configuration: configuration, delegate: self, delegateQueue: .main)
            self.network = network
            let task = network.dataTask(with: tokenRequest); self.task = task; task.resume()
        } catch { finish() }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    static func authenticationDisposition(_ method: String) -> URLSession.AuthChallengeDisposition {
        method == NSURLAuthenticationMethodServerTrust ? .performDefaultHandling : .cancelAuthenticationChallenge
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Public-client PKCE needs no ambient HTTP/keychain/client-certificate
        // credential. Keep the platform's normal TLS trust validation intact.
        completionHandler(Self.authenticationDisposition(challenge.protectionSpace.authenticationMethod), nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Server-trust, client-certificate and connection-oriented challenges
        // may be delivered at session scope rather than task scope.
        completionHandler(Self.authenticationDisposition(challenge.protectionSpace.authenticationMethod), nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard current(), let response = response as? HTTPURLResponse, response.statusCode == 200,
              response.url?.absoluteString == oauth.token_endpoint,
              response.expectedContentLength <= 32768,
              response.mimeType?.lowercased() == "application/json" else { completionHandler(.cancel); finish(); return }
        responseAccepted = true; completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard current(), responseAccepted, responseBytes.count <= 32768 - data.count else { finish(); return }
        responseBytes.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard current(), responseAccepted, error == nil else { finish(); return }
        do {
            // Genuine token signature/principal/nonce/time is verified by UID703.
            // JSONDecoder rejects duplicate known claims in neither every SDK nor
            // every mode; exact duplicate-safe public response parsing is below.
            var token = try TokenResponse.idToken(responseBytes)
            defer { token.resetBytes(in: token.startIndex..<token.endIndex) }
            var reply = [UInt8]()
            defer { _ = reply.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
            try request.appendReply(token: token, to: &reply)
            guard current() else { throw BrokerFailure.refused }
            let (handoffDeadline, overflow) = HelperWire.nowNs().addingReportingOverflow(2_000_000_000)
            guard !overflow else { throw BrokerFailure.refused }
            try HelperWire.writeFrame(fd, reply, deadline: min(request.deadline, handoffDeadline))
        } catch { /* A failed or partial reply is never retried. */ }
        finish()
    }

    func finish() {
        guard !done else { return }; done = true
        timer?.invalidate(); timer = nil
        authentication?.cancel(); authentication = nil
        task?.cancel(); task = nil; network?.invalidateAndCancel(); network = nil
        responseBytes.resetBytes(in: responseBytes.startIndex..<responseBytes.endIndex); responseBytes.removeAll(keepingCapacity: false)
        verifier = ""; state = ""; anchor.orderOut(nil); anchor.close()
        if fd >= 0 { shutdown(fd, SHUT_RDWR); close(fd); fd = -1 }
        let completion = complete; complete = nil; completion?()
    }
}

enum TokenResponse {
    static func idToken(_ data: Data) throws -> Data {
        guard !data.isEmpty, data.count <= 32768,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = root["id_token"] as? String, !token.isEmpty, token.utf8.count <= 16384,
              token.utf8.allSatisfy({ (33...126).contains($0) }) else { throw BrokerFailure.refused }
        // Reject ambiguous duplicate keys by scanning the complete JSON grammar
        // before using JSONSerialization's materialized value.
        try StrictJSONMembers.check(data)
        return Data(token.utf8)
    }
}
