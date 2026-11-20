import AppKit
import CoreGraphics
import Foundation

/// 60 Hz window occlusion detector (FS-703 §5.1, GAP-14).
///
/// Any on-screen window that overlaps the intent sheet, is in front of it in
/// z-order, and is owned by another process causes an immediate occlusion abort.
/// The system CoreAuthUI Touch ID prompt itself is permitted.
public final class OcclusionDetector {

    /// Convert Cocoa window frame (bottom-left origin) to Quartz screen coordinates (top-left origin).
    public static func cocoaToQuartz(_ rect: CGRect) -> CGRect {
        guard let mainScreen = NSScreen.screens.first else { return rect }
        let screenHeight = mainScreen.frame.height
        return CGRect(
            x: rect.origin.x,
            y: screenHeight - rect.origin.y - rect.height,
            width: rect.width,
            height: rect.height
        )
    }

    /// Check whether any other process's window occludes `sheetWindowNumber`.
    public static func isOccluded(sheetWindowNumber: Int, sheetFrame: CGRect, simulatedTestWindowNumber: Int? = nil) -> Bool {
        let quartzSheetFrame = cocoaToQuartz(sheetFrame)
        let myPid = getpid()

        // In test mode: allow a designated simulated test window from our own process to count as occluding
        if let testWinNum = simulatedTestWindowNumber {
            let testList = CGWindowListCopyWindowInfo([.optionIncludingWindow], CGWindowID(testWinNum)) as? [[String: Any]] ?? []
            for win in testList {
                guard let boundsDict = win[kCGWindowBounds as String] as? [String: Any],
                      let winBounds = CGRect(dictionaryRepresentation: boundsDict as CFDictionary) else {
                    continue
                }
                if winBounds.intersects(quartzSheetFrame) {
                    return true
                }
            }
        }

        // Verify sheet has been composited on-screen by WindowServer (FS-703 §5.1.3 dwell gate)
        guard let onScreenList = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]],
              onScreenList.contains(where: { ($0[kCGWindowNumber as String] as? Int) == sheetWindowNumber }) else {
            // Fail closed: if WindowServer list is unavailable or sheet is not composited, treat as occluded
            return true
        }

        // Query only windows strictly above the sheet in z-order (FS-703 §5.1.2)
        guard let list = CGWindowListCopyWindowInfo([.optionOnScreenAboveWindow, .excludeDesktopElements], CGWindowID(sheetWindowNumber)) as? [[String: Any]] else {
            // Fail closed: cannot verify z-order
            return true
        }

        for win in list {
            guard let ownerPid = win[kCGWindowOwnerPID as String] as? Int,
                  ownerPid != myPid else {
                continue
            }

            // Only exact Apple Touch ID system prompts and WindowServer compositor/cursor are exempt
            if let ownerName = win[kCGWindowOwnerName as String] as? String {
                let lower = ownerName.lowercased()
                if lower == "coreauthui" || lower == "coreautha" || lower == "window server" || lower == "windowserver" {
                    continue
                }
            }

            guard let layer = win[kCGWindowLayer as String] as? Int, layer >= 0 else {
                continue
            }

            guard let boundsDict = win[kCGWindowBounds as String] as? [String: Any],
                  let winBounds = CGRect(dictionaryRepresentation: boundsDict as CFDictionary) else {
                // If bounds are unparseable, fail closed
                return true
            }

            if winBounds.width > 2 && winBounds.height > 2 && winBounds.intersects(quartzSheetFrame) {
                return true
            }
        }
        return false
    }
}
