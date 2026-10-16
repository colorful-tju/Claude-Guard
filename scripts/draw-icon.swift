import AppKit

// Original vector artwork. No remote assets, fonts or application screenshots.
let output=CommandLine.arguments[1]
try FileManager.default.createDirectory(atPath:output,withIntermediateDirectories:true)
func color(_ r:CGFloat,_ g:CGFloat,_ b:CGFloat,_ a:CGFloat=1)->NSColor {NSColor(srgbRed:r,green:g,blue:b,alpha:a)}
func render(_ pixels:Int)->NSBitmapImageRep {
    let bitmap=NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:pixels,pixelsHigh:pixels,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0)!
    let context=NSGraphicsContext(bitmapImageRep:bitmap)!
    NSGraphicsContext.saveGraphicsState();NSGraphicsContext.current=context
    context.cgContext.scaleBy(x:CGFloat(pixels)/1024,y:CGFloat(pixels)/1024)
    let tile=NSBezierPath(roundedRect:NSRect(x:60,y:60,width:904,height:904),xRadius:212,yRadius:212)
    let shadow=NSShadow();shadow.shadowColor=color(0.02,0.13,0.25,0.24);shadow.shadowBlurRadius=24;shadow.shadowOffset=NSSize(width:0,height:-14)
    NSGraphicsContext.saveGraphicsState();shadow.set();color(0.04,0.31,0.68).setFill();tile.fill();NSGraphicsContext.restoreGraphicsState()
    NSGradient(colors:[color(0.035,0.22,0.56),color(0.035,0.52,0.81),color(0.18,0.83,0.78)])!.draw(in:tile,angle:62)
    NSGraphicsContext.saveGraphicsState();tile.addClip()
    let glow=NSBezierPath(ovalIn:NSRect(x:450,y:550,width:750,height:550))
    NSGradient(starting:color(0.76,1,0.96,0.44),ending:color(0.7,1,1,0))!.draw(in:glow,relativeCenterPosition:NSPoint(x:0,y:0))
    let ribbon=NSBezierPath();ribbon.move(to:NSPoint(x:35,y:340));ribbon.curve(to:NSPoint(x:1040,y:730),controlPoint1:NSPoint(x:270,y:830),controlPoint2:NSPoint(x:740,y:120));ribbon.lineWidth=2;color(1,1,1,0.17).setStroke();ribbon.stroke()
    NSGraphicsContext.restoreGraphicsState()
    tile.lineWidth=2;color(1,1,1,0.3).setStroke();tile.stroke()
    // Soft glass shield; deliberately simple enough for a 16 px menu/Finder image.
    let shield=NSBezierPath()
    shield.move(to:NSPoint(x:512,y:817))
    shield.curve(to:NSPoint(x:756,y:716),controlPoint1:NSPoint(x:602,y:765),controlPoint2:NSPoint(x:683,y:731))
    shield.line(to:NSPoint(x:756,y:518))
    shield.curve(to:NSPoint(x:512,y:211),controlPoint1:NSPoint(x:755,y:367),controlPoint2:NSPoint(x:641,y:266))
    shield.curve(to:NSPoint(x:268,y:518),controlPoint1:NSPoint(x:383,y:266),controlPoint2:NSPoint(x:269,y:367))
    shield.line(to:NSPoint(x:268,y:716))
    shield.curve(to:NSPoint(x:512,y:817),controlPoint1:NSPoint(x:341,y:731),controlPoint2:NSPoint(x:422,y:765));shield.close()
    NSGraphicsContext.saveGraphicsState()
    let innerShadow=NSShadow();innerShadow.shadowColor=color(0,0.12,0.35,0.32);innerShadow.shadowBlurRadius=28;innerShadow.shadowOffset=NSSize(width:0,height:-12);innerShadow.set()
    color(0.76,0.97,1,0.19).setFill();shield.fill();NSGraphicsContext.restoreGraphicsState()
    NSGradient(starting:color(1,1,1,0.45),ending:color(0.76,0.94,1,0.11))!.draw(in:shield,angle:-90)
    shield.lineWidth=13;shield.lineJoinStyle = .round;color(0.93,1,1,0.94).setStroke();shield.stroke()
    // A connected checkmark: verified path rather than an imitation of Claude branding.
    let route=NSBezierPath();route.move(to:NSPoint(x:386,y:523));route.line(to:NSPoint(x:476,y:432));route.line(to:NSPoint(x:642,y:615));route.lineWidth=42;route.lineCapStyle = .round;route.lineJoinStyle = .round
    color(1,1,1).setStroke();route.stroke()
    for point in [NSPoint(x:386,y:523),NSPoint(x:642,y:615)] {
        let dot=NSBezierPath(ovalIn:NSRect(x:point.x-32,y:point.y-32,width:64,height:64));color(0.82,1,0.94).setFill();dot.fill()
    }
    NSGraphicsContext.restoreGraphicsState();return bitmap
}
for size in [16,32,128,256,512] {
    for scale in [1,2] {
        let name="icon_\(size)x\(size)"+(scale==2 ? "@2x":"")+".png"
        try render(size*scale).representation(using:.png,properties:[:])!.write(to:URL(fileURLWithPath:output).appendingPathComponent(name))
    }
}
