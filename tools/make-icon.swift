// Draws the Triple B VPN app icon (1024×1024 PNG) with CoreGraphics.
// Mark: a single geometric "B" echoed three times along a diagonal (the triple),
// with the front copy in white and the two behind in blue — reads at 16px and
// has no reliance on a font.
import AppKit
import Foundation

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "/tmp/icon-1024.png"
let S: CGFloat = 1024

/// Bold geometric B as a stroked path: stem + two bowls.
func bStrokes(offset: CGPoint, scale: CGFloat = 1) -> NSBezierPath {
    let p = NSBezierPath()
    p.lineCapStyle = .round
    p.lineJoinStyle = .round

    let cx: CGFloat = 372 + offset.x
    let top: CGFloat = 268 + offset.y
    let mid: CGFloat = 512 + offset.y
    let bot: CGFloat = 756 + offset.y
    // stem
    p.move(to: CGPoint(x: cx, y: top))
    p.line(to: CGPoint(x: cx, y: bot))
    // upper bowl
    p.move(to: CGPoint(x: cx, y: top))
    p.curve(to: CGPoint(x: cx, y: mid),
            controlPoint1: CGPoint(x: cx + 268, y: top),
            controlPoint2: CGPoint(x: cx + 268, y: mid))
    // lower bowl (slightly wider, like real type)
    p.move(to: CGPoint(x: cx, y: mid))
    p.curve(to: CGPoint(x: cx, y: bot),
            controlPoint1: CGPoint(x: cx + 300, y: mid),
            controlPoint2: CGPoint(x: cx + 300, y: bot))
    return p
}

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(S), pixelsHigh: Int(S),
                           bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                           colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext
ctx.setAllowsAntialiasing(true)
ctx.interpolationQuality = .high
ctx.setShouldSmoothFonts(true)

// ---- plate: near-black navy → electric blue, diagonal
let plate = NSBezierPath(roundedRect: CGRect(x: 0, y: 0, width: S, height: S),
                         xRadius: S * 0.235, yRadius: S * 0.235)
plate.addClip()
let grad = NSGradient(colors: [
    NSColor(srgbRed: 0.031, green: 0.043, blue: 0.130, alpha: 1),   // #080B21
    NSColor(srgbRed: 0.063, green: 0.157, blue: 0.560, alpha: 1),   // #102890
    NSColor(srgbRed: 0.031, green: 0.470, blue: 0.980, alpha: 1),   // #0878FA
])!
grad.draw(in: plate, angle: -66)

// subtle radial lift bottom-right so the mark sits in light
let lift = NSGradient(colors: [
    NSColor(srgbRed: 0.28, green: 0.85, blue: 1.0, alpha: 0.30),
    NSColor(srgbRed: 0.28, green: 0.85, blue: 1.0, alpha: 0.0),
])!
lift.draw(fromCenter: CGPoint(x: S * 0.80, y: S * 0.16), radius: 0,
          toCenter: CGPoint(x: S * 0.80, y: S * 0.16), radius: S * 0.72, options: [])

// ---- three echoed B strokes, back to front
let layers: [(CGPoint, CGFloat, NSColor)] = [
    (CGPoint(x: 104, y: 92), 0.80, NSColor(srgbRed: 0.22, green: 0.80, blue: 1.0, alpha: 0.42)),
    (CGPoint(x: 52, y: 46), 0.90, NSColor(srgbRed: 0.55, green: 0.90, blue: 1.0, alpha: 0.62)),
    (CGPoint(x: 0, y: 0), 1.0, .white),
]
for (off, w, color) in layers {
    let path = bStrokes(offset: off)
    color.setStroke()
    path.lineWidth = S * 0.082 * w
    path.stroke()
}

NSGraphicsContext.restoreGraphicsState()

let png = rep.representation(using: .png, properties: [:])!
try! png.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
