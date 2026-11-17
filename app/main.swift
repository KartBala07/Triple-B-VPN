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
        let hosting = NSHostingView(rootView: ContentView(model: model))
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 372, height: 560),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Triple B VPN"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.contentView = hosting
        window.isReleasedWhenClosed = false
        window.center()
        window.level = .floating
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
        window.makeKeyAndOrderFront(nil)
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

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
}
