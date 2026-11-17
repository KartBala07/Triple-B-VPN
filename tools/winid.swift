// Print window ids/bounds for a given owner process name.
import CoreGraphics
import Foundation

let needle = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "TripleB"
let opts: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
guard let list = CGWindowListCopyWindowInfo(opts, kCGNullWindowID) as? [[String: Any]] else {
    exit(1)
}
for w in list {
    let owner = (w[kCGWindowOwnerName as String] as? String) ?? ""
    guard owner.contains(needle) else { continue }
    let num = w[kCGWindowNumber as String] ?? "?"
    let b = w[kCGWindowBounds as String] ?? "?"
    print("\(num)\t\(owner)\t\(b)")
}
