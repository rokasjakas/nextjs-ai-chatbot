// Event Solutions for iPhone / iPad: app.eventsolutions.lt in a full-screen web view
// with real (Apple, APNs) push notifications. The device token is handed to the
// page (window.esIOS.token), the page registers it (rpc ios_register) and
// push-notify sends notifications to it. Distributed through TestFlight,
// built and uploaded by .github/workflows/ios.yml.
import UIKit
import UserNotifications

@main
final class AppDelegate: UIResponder, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    var window: UIWindow?
    let web = WebViewController()

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // opened by tapping a notification while the app was closed
        if let note = options?[.remoteNotification] as? [AnyHashable: Any], let url = note["url"] as? String {
            web.pendingUrl = url
        }
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = web
        window?.makeKeyAndVisible()

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            DispatchQueue.main.async {
                self.web.setPushAllowed(granted)
                if granted { application.registerForRemoteNotifications() }
            }
        }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
        web.setPushToken(token.map { String(format: "%02x", $0) }.joined())
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        NSLog("push registration failed: \(error.localizedDescription)")
    }

    // the app is open: the page shows its own notices (as on Android), so nothing here
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([])
    }

    // a notification was tapped: open that place in the app
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        if let url = response.notification.request.content.userInfo["url"] as? String { web.open(url) }
        done()
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        UNUserNotificationCenter.current().getNotificationSettings { s in
            DispatchQueue.main.async { self.web.setPushAllowed(s.authorizationStatus == .authorized) }
        }
    }
}
