#if depot_OIDC_NATIVE_TESTING
import CryptoKit
import Foundation

enum BrokerProtocolSelfTest {
    static func check(_ condition: @autoclosure () -> Bool) throws {
        guard condition() else { throw BrokerFailure.refused }
    }
    static func refuses(_ operation: () throws -> Void) throws {
        do { try operation() } catch { return }
        throw BrokerFailure.refused
    }
    static func fields() -> [(String, [UInt8])] {
        [ ("protocol", CBOREncoder.encodeText("enclave.oidc-step-up.v1")),
          ("nonce", CBOREncoder.encodeText(String(repeating: "a", count: 43))),
          ("d_jcs", CBOREncoder.encodeText(String(repeating: "b", count: 64))),
          ("boot_epoch_id", CBOREncoder.encodeText("synthetic-boot")),
          ("t_start_ns", CBOREncoder.encodeUInt(100)), ("deadline_ns", CBOREncoder.encodeUInt(10_000_000_100)),
          ("console_uid", CBOREncoder.encodeUInt(501)), ("audit_session_id", CBOREncoder.encodeUInt(42)),
          ("max_age_s", CBOREncoder.encodeUInt(0)), ("issuer", CBOREncoder.encodeText("https://idp.invalid")),
          ("audience", CBOREncoder.encodeText("synthetic-client")) ]
    }
    static func encode(_ fields: [(String, [UInt8])]) -> [UInt8] {
        fields.reduce([0xa0 | UInt8(fields.count)]) { $0 + CBOREncoder.encodeText($1.0) + $1.1 }
    }
    static func run() throws {
        let request = try BrokerRequest.decode(encode(fields()))
        try check(request.uid == 501 && request.audit == 42 && request.nonce.count == 43)
        var reply = [UInt8]()
        try request.appendReply(token: Data("synthetic.a.b".utf8), to: &reply)
        var reader = CBORReader(data: reply)
        guard case .map(let envelope) = try reader.readValue(), envelope.count == 1,
              case .textString("Ok") = envelope[0].0,
              case .map(let body) = envelope[0].1, body.count == 3,
              reader.offset == reply.count else { throw BrokerFailure.refused }
        for mutation in 0..<5 {
            var changed = fields()
            if mutation == 0 { changed[10] = changed[9] }
            if mutation == 1 { changed[0] = ("protocol", CBOREncoder.encodeText("enclave.oidc-step-up.v0")) }
            if mutation == 2 { changed[8] = ("max_age_s", CBOREncoder.encodeUInt(300)) }
            if mutation == 3 { changed[7] = ("audit_session_id", CBOREncoder.encodeUInt(UInt64.max)) }
            if mutation == 4 { changed[1] = ("untrusted_override", CBOREncoder.encodeText("synthetic")) }
            try refuses { _ = try BrokerRequest.decode(encode(changed)) }
        }
        try refuses { _ = try BrokerRequest.decode(encode(fields()) + [0]) }
        try refuses { _ = try BrokerRequest.decode([0xbf]) }
        var simple = fields(); simple[8] = ("max_age_s", [0xe0])
        try refuses { _ = try BrokerRequest.decode(encode(simple)) }
        simple[8] = ("max_age_s", [0x18, 0x00])
        try refuses { _ = try BrokerRequest.decode(encode(simple)) }

        let redirect = "com.enterprise.enclave.oidc://callback"
        let code = try BrowserStepUp.authorizationCode(URL(string: redirect + "?code=synthetic&state=nonce")!, redirect: redirect, state: "nonce")
        try check(code == "synthetic")
        for text in [redirect + "?code=synthetic&state=wrong", redirect + "?code=a&code=b&state=nonce",
            redirect + "?code=a&state=nonce&state=nonce", redirect + "?code=a&state=nonce#hidden",
            "com.enterprise.enclave.oidc://other?code=a&state=nonce", redirect + "?error=denied&state=nonce"] {
            try refuses { _ = try BrowserStepUp.authorizationCode(URL(string: text)!, redirect: redirect, state: "nonce") }
        }
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        try check(BrowserStepUp.base64URL(Data(SHA256.hash(data: Data(verifier.utf8)))) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        let first = try BrowserStepUp.randomURLToken(); let second = try BrowserStepUp.randomURLToken()
        try check(first.count == 43 && second.count == 43 && first != second)

        let token = try TokenResponse.idToken(Data(#"{"id_token":"synthetic.a.b","token_type":"Bearer"}"#.utf8))
        try check(token == Data("synthetic.a.b".utf8))
        for text in [#"{"id_token":"a","id_token":"b"}"#, #"{"id_token":"a","\u0069d_token":"b"}"#,
            #"{"id_token":"a","extra":{"k":1,"k":2}}"#, #"{"id_token":"a","extra":[{"k":1,"k":2}]}"#,
            #"{"id_token":123}"#, #"{"id_token":""}"#, #"{"id_token":"a"}false"#] {
            try refuses { _ = try TokenResponse.idToken(Data(text.utf8)) }
        }
        try refuses { _ = try TokenResponse.idToken(Data(repeating: 65, count: 32769)) }
        try refuses { _ = try ProtectedBrokerFile.load("relative/untrusted") }
        try refuses { _ = try ProtectedBrokerFile.decode(BrokerIdentityConfig.self,
            Data(#"{"v":1,"v":1}"#.utf8), keys: ["v"]) }
        try check(BrokerOAuthConfig.https("https://idp.invalid/token") != nil)
        for endpoint in ["http://idp.invalid/token", "https://user@idp.invalid/token", "https://idp.invalid/token#x", "https://idp.invalid/token?override=x"] {
            try check(BrokerOAuthConfig.https(endpoint) == nil)
        }
        try check(BrowserStepUp.authenticationDisposition(NSURLAuthenticationMethodServerTrust) == .performDefaultHandling)
        for method in [NSURLAuthenticationMethodHTTPBasic, NSURLAuthenticationMethodHTTPDigest,
            NSURLAuthenticationMethodClientCertificate, NSURLAuthenticationMethodNTLM,
            NSURLAuthenticationMethodNegotiate, "unrecognized-authentication-method"] {
            try check(BrowserStepUp.authenticationDisposition(method) == .cancelAuthenticationChallenge)
        }
        print("OIDC private protocol probes PASS: typed request/reply, callback binding, RFC7636 PKCE, duplicate JSON, bounds, ambient-auth refusal and protected-path refusal; no browser, IdP or credential operation")
    }
}
#endif
