import AppKit
import Combine
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private var statusItem: NSStatusItem!
    private let model = VPNModel()
    private var cancellable: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        model.start()
        buildStatusItem()
        buildWindow()

        // keep the menu bar glyph in sync with tunnel state
        cancellable = model.$status.sink { [weak self] _ in
            Task { @MainActor in self?.refreshGlyph() }
        }

        showWindow()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    private func buildWindow() {
        // Fixed content height, measured from the layout: preferredContentSize
        // left the window un-ordered (zero-size frame), and a flexible
        // ScrollView silently absorbed any shortfall and clipped the log.
        let hosting = NSHostingView(rootView: ContentView(model: model))
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 372, height: 640),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        hosting.frame = NSRect(x: 0, y: 0, width: 372, height: 640)
        window.contentView = hosting
        window.setContentSize(NSSize(width: 372, height: 640))   // authoritative
        window.titlebarAppearsTransparent = true
        window.title = "Triple B VPN"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        // Never depend on a live display: with the lid closed NSScreen.screens
        // can be empty and center() would leave the panel nowhere.
        if let vf = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame {
            window.setFrameOrigin(NSPoint(x: vf.midX - window.frame.width / 2,
                                          y: vf.midY - window.frame.height / 2))
        } else {
            window.setFrameOrigin(NSPoint(x: 240, y: 240))
        }
        // A menu-bar utility must be reachable from every Space, including on
        // top of full-screen apps, otherwise clicking the status item looks
        // broken because the panel opens somewhere you cannot see.
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
    }

    private func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = glyph(named: "shield.slash")
            button.image?.isTemplate = false
            button.target = self
            button.action = #selector(statusClicked)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        refreshGlyph()
    }

    @objc private func statusClicked() {
        guard let button = statusItem.button else { return }
        if NSApp.currentEvent?.type == .rightMouseUp {
            let menu = buildMenu()
            menu.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.height + 4), in: button)
        } else {
            toggleWindow()
        }
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu()
        let state = model.clientRunning ? "Disconnect" : "Connect"
        menu.addItem(NSMenuItem(title: state, action: #selector(menuToggleConnect), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: model.nodeRunning ? "Stop exit node" : "Start exit node",
                                action: #selector(menuToggleNode), keyEquivalent: ""))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Open Triple B VPN", action: #selector(showWindow), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Copy pre-shared key", action: #selector(menuCopyKey), keyEquivalent: ""))
        menu.addItem(.separator())
        let stats = NSMenuItem(title: "\(model.headline) · ↓\(model.rxText) ↑\(model.txText)", action: nil, keyEquivalent: "")
        stats.isEnabled = false
        menu.addItem(stats)
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))
        for item in menu.items { item.target = self }
        return menu
    }

    @objc private func menuToggleConnect() { model.connect(); statusItem.menu = nil }
    @objc private func menuToggleNode() { model.toggleNode(); statusItem.menu = nil }
    @objc private func menuCopyKey() { model.copyKey(); statusItem.menu = nil }
    @objc private func quit() { NSApp.terminate(nil) }

    @objc func showWindow() {
        if !NSScreen.screens.contains(where: { $0.frame.intersects(window.frame) }) {
            if let vf = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame {
                var f = window.frame
                f.origin = NSPoint(x: vf.midX - f.width / 2, y: vf.midY - f.height / 2)
                window.setFrame(f, display: true)
            }
        }
        window.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)
    }

    private func toggleWindow() {
        if window.isVisible && window.isKeyWindow {
            window.orderOut(nil)
        } else {
            showWindow()
        }
    }

    private func glyph(named: String) -> NSImage? {
        let cfg = NSImage.SymbolConfiguration(pointSize: 13, weight: .semibold)
        let img = NSImage(systemSymbolName: named, accessibilityDescription: "Triple B VPN")?
            .withSymbolConfiguration(cfg)
        img?.isTemplate = true      // template = correct colour in light and dark bars
        return img
    }

    private func refreshGlyph() {
        let name: String
        if model.clientRunning {
            name = "lock.shield.fill"
        } else if model.nodeRunning {
            name = "lock.shield"
        } else if model.probed && !model.helperInstalled {
            name = "shield.slash"
        } else {
            name = "shield"
        }
        statusItem.button?.image = glyph(named: name)
        statusItem.button?.toolTip = "Triple B VPN — \(model.headline)"
    }
}

// NSApplication.delegate is a weak reference: this must stay alive at file
// scope or ARC frees it and applicationDidFinishLaunching never fires (the app
// then runs with no window and no menu-bar item).
var appDelegate: AppDelegate?

MainActor.assumeIsolated {
    let app = NSApplication.shared
    appDelegate = AppDelegate()
    app.delegate = appDelegate
    app.setActivationPolicy(.accessory)
    app.run()
}
