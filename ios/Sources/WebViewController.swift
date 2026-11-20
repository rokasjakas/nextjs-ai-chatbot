import UIKit
import WebKit
import UserNotifications

/// The whole app: the site in a WKWebView. Links to other sites open in Safari,
/// alert / confirm / prompt become native dialogs, files are saved or shared
/// through the share sheet, the camera and microphone work in video calls.
final class WebViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler, WKDownloadDelegate {
    static let home = URL(string: "https://app.eventsolutions.lt/")!
    /// bump together with IOS_LATEST in site/index.html
    static let version = 1

    private var web: WKWebView!
    private var token: String?
    private var pushAllowed = false
    private var loaded = false
    private var downloadTo: URL?
    /// a place to open once the page has loaded (from a notification)
    var pendingUrl: String?

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }

    override func loadView() {
        let cfg = WKWebViewConfiguration()
        cfg.allowsInlineMediaPlayback = true
        cfg.mediaTypesRequiringUserActionForPlayback = []
        cfg.websiteDataStore = .default()
        let bridge = "window.esIOS = { platform: 'ios', version: \(Self.version), token: '', push: false, " +
            "post: function (m) { try { window.webkit.messageHandlers.es.postMessage(m); } catch (e) {} } };"
        cfg.userContentController.addUserScript(WKUserScript(source: bridge, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        cfg.userContentController.add(self, name: "es")

        web = WKWebView(frame: .zero, configuration: cfg)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.allowsBackForwardNavigationGestures = true
        web.scrollView.contentInsetAdjustmentBehavior = .never   // the page uses env(safe-area-inset-*)
        web.isOpaque = false
        web.backgroundColor = UIColor(red: 0.067, green: 0.067, blue: 0.067, alpha: 1)
        web.scrollView.backgroundColor = web.backgroundColor
        if #available(iOS 16.4, *) { web.isInspectable = true }
        view = web
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        var start = Self.home
        if let p = pendingUrl, let u = inApp(p) { start = u; pendingUrl = nil }
        web.load(URLRequest(url: start))
    }

    // MARK: - the page and the app

    private func inApp(_ s: String) -> URL? {
        guard let u = URL(string: s, relativeTo: Self.home)?.absoluteURL, u.host == Self.home.host else { return nil }
        return u
    }
    private func js(_ s: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: [s])
        let arr = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[\"\"]"
        return String(arr.dropFirst().dropLast())
    }

    func open(_ url: String) {
        guard let u = inApp(url) else { return }
        guard loaded else { pendingUrl = url; return }
        let s = js(u.absoluteString)
        web.evaluateJavaScript("window.esOpenUrl ? esOpenUrl(\(s)) : (location.href = \(s))")
    }

    func setPushToken(_ t: String) { token = t; tellPage() }
    func setPushAllowed(_ ok: Bool) { pushAllowed = ok; tellPage() }
    private func tellPage() {
        guard loaded else { return }
        web.evaluateJavaScript("window.esIOS && (esIOS.token = \(js(token ?? "")), esIOS.push = \(pushAllowed), window.dispatchEvent(new Event('es-ios-token')))")
    }

    func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let d = message.body as? [String: Any], let type = d["type"] as? String else { return }
        switch type {
        case "badge":
            let n = (d["n"] as? Int) ?? 0
            if #available(iOS 16.0, *) { UNUserNotificationCenter.current().setBadgeCount(n) }
            else { UIApplication.shared.applicationIconBadgeNumber = n }
        case "settings":
            if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
        case "askPush":
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { ok, _ in
                DispatchQueue.main.async {
                    self.setPushAllowed(ok)
                    if ok { UIApplication.shared.registerForRemoteNotifications() }
                    else if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                }
            }
        default: break
        }
    }

    // MARK: - navigation

    func webView(_ w: WKWebView, didFinish n: WKNavigation!) {
        loaded = true
        tellPage()
        if let p = pendingUrl { pendingUrl = nil; open(p) }
    }

    func webView(_ w: WKWebView, decidePolicyFor a: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let u = a.request.url else { return decisionHandler(.cancel) }
        if a.shouldPerformDownload { return decisionHandler(.download) }
        // frames inside the page (video calls, maps …) load normally
        if let f = a.targetFrame, !f.isMainFrame { return decisionHandler(.allow) }
        if u.host == Self.home.host || ["about", "blob", "data"].contains(u.scheme ?? "") { return decisionHandler(.allow) }
        if ["http", "https", "tel", "mailto", "sms", "maps"].contains(u.scheme ?? "") { UIApplication.shared.open(u) }
        decisionHandler(.cancel)
    }

    func webView(_ w: WKWebView, decidePolicyFor r: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        let attachment = ((r.response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Disposition") ?? "").lowercased().hasPrefix("attachment")
        decisionHandler(r.canShowMIMEType && !attachment ? .allow : .download)
    }

    // window.open: pages of the app open here, other sites in Safari
    func webView(_ w: WKWebView, createWebViewWith c: WKWebViewConfiguration, for a: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let u = a.request.url, ["http", "https"].contains(u.scheme ?? "") {
            if u.host == Self.home.host { w.load(a.request) } else { UIApplication.shared.open(u) }
        }
        return nil
    }

    func webViewWebContentProcessDidTerminate(_ w: WKWebView) { w.reload() }

    // MARK: - camera and microphone (video calls)

    func webView(_ w: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo,
                 type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        let h = origin.host
        decisionHandler(h == Self.home.host || h == "daily.co" || h.hasSuffix(".daily.co") ? .grant : .deny)
    }

    // MARK: - alert / confirm / prompt

    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler done: @escaping () -> Void) {
        let a = UIAlertController(title: nil, message: m, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Gerai", style: .default) { _ in done() })
        present(a, animated: true)
    }

    func webView(_ w: WKWebView, runJavaScriptConfirmPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler done: @escaping (Bool) -> Void) {
        let a = UIAlertController(title: nil, message: m, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Atšaukti", style: .cancel) { _ in done(false) })
        a.addAction(UIAlertAction(title: "Gerai", style: .default) { _ in done(true) })
        present(a, animated: true)
    }

    func webView(_ w: WKWebView, runJavaScriptTextInputPanelWithPrompt p: String, defaultText: String?, initiatedByFrame f: WKFrameInfo,
                 completionHandler done: @escaping (String?) -> Void) {
        let a = UIAlertController(title: nil, message: p, preferredStyle: .alert)
        a.addTextField { $0.text = defaultText }
        a.addAction(UIAlertAction(title: "Atšaukti", style: .cancel) { _ in done(nil) })
        a.addAction(UIAlertAction(title: "Gerai", style: .default) { _ in done(a.textFields?.first?.text) })
        present(a, animated: true)
    }

    // MARK: - downloads (Excel, PDF …): saved, then the share sheet ("Išsaugoti failuose", AirDrop …)

    func webView(_ w: WKWebView, navigationAction a: WKNavigationAction, didBecome d: WKDownload) { d.delegate = self }
    func webView(_ w: WKWebView, navigationResponse r: WKNavigationResponse, didBecome d: WKDownload) { d.delegate = self }

    func download(_ d: WKDownload, decideDestinationUsing r: URLResponse, suggestedFilename name: String, completionHandler done: @escaping (URL?) -> Void) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let to = dir.appendingPathComponent(name.isEmpty ? "failas" : name)
        downloadTo = to
        done(to)
    }

    func downloadDidFinish(_ d: WKDownload) {
        guard let to = downloadTo else { return }
        let share = UIActivityViewController(activityItems: [to], applicationActivities: nil)
        share.popoverPresentationController?.sourceView = view
        share.popoverPresentationController?.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1)
        present(share, animated: true)
    }

    func download(_ d: WKDownload, didFailWithError e: Error, resumeData: Data?) {
        let a = UIAlertController(title: nil, message: "Nepavyko atsisiųsti: \(e.localizedDescription)", preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Gerai", style: .default))
        present(a, animated: true)
    }
}
