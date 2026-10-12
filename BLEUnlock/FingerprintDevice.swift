//
//  FingerprintDevice.swift
//  BLEUnlock
//
//  Track a BLE device whose address rotates (e.g. a phone using LE Privacy)
//  by matching the stable parts of its advertisement payload — its
//  "fingerprint":
//
//    - manufacturer data prefix (hex, e.g. "750002" for a Samsung beacon)
//    - service data prefix       (e.g. "fd5a" or "fd5a:0201")
//    - service UUID              (e.g. "fd6f")
//
//  A user-defined profile carries a custom name and a stable synthetic UUID,
//  so a fingerprint-matched device becomes a first-class entry in the device
//  list and can be monitored (unlock/lock) exactly like a paired device.
//

import Foundation
import CoreBluetooth

struct DeviceFingerprint: Codable, Equatable {
    /// Stable synthetic UUID string used to key this device in the list.
    var id: String
    /// User-defined display name.
    var name: String
    /// Lowercased hex prefix of the manufacturer data (e.g. "750002").
    var manufacturerPrefix: String? = nil
    /// Lowercased prefix of a service data entry in "uuid:hex" form (e.g. "fd5a:0201").
    var serviceDataPrefix: String? = nil
    /// Service UUID (short or full form) that must be advertised.
    var serviceUUID: String? = nil
    /// Creation timestamp (informational).
    var createdAt: TimeInterval? = nil

    /// Stable UUID that represents this profile in `BLE.devices` / UserDefaults.
    var syntheticUUID: UUID {
        UUID(uuidString: id) ?? DeviceFingerprint.deterministicUUID(from: id)
    }

    /// Short human readable summary of the criteria (for menus / detail mode).
    var criteriaSummary: String {
        var parts: [String] = []
        if let mf = manufacturerPrefix, !mf.isEmpty { parts.append("MF:" + mf) }
        if let sd = serviceDataPrefix, !sd.isEmpty { parts.append("SD:" + sd) }
        if let u = serviceUUID, !u.isEmpty { parts.append("UUID:" + u) }
        return parts.isEmpty ? "-" : parts.joined(separator: " ")
    }

    /// Deterministic UUID fallback for hand-edited / corrupted profile ids,
    /// so a profile always maps to the same synthetic device key.
    static func deterministicUUID(from string: String) -> UUID {
        var h1: UInt64 = 0xcbf29ce484222325
        var h2: UInt64 = 0x84222325cbf29ce4
        for byte in string.utf8 {
            h1 = (h1 ^ UInt64(byte)) &* 0x100000001b3
            h2 = (h2 &+ UInt64(byte)) &* 0x100000001b3
        }
        func b(_ value: UInt64, _ index: Int) -> UInt8 {
            UInt8(truncatingIfNeeded: value >> (UInt64(index) * 8))
        }
        return UUID(uuid: (b(h1, 0), b(h1, 1), b(h1, 2), b(h1, 3),
                           b(h1, 4), b(h1, 5), b(h1, 6), b(h1, 7),
                           b(h2, 0), b(h2, 1), b(h2, 2), b(h2, 3),
                           b(h2, 4), b(h2, 5), b(h2, 6), b(h2, 7)))
    }

    // MARK: - Normalization

    /// "75 00 02", "0x750002" → "750002"
    static func normalizeManufacturerPrefix(_ raw: String) -> String? {
        var s = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("0x") { s = String(s.dropFirst(2)) }
        let hex = s.filter { $0.isHexDigit }
        return hex.isEmpty ? nil : hex
    }

    /// "FD5A:0201", "fd5a" → "fd5a:0201" / "fd5a"
    static func normalizeServiceDataPrefix(_ raw: String) -> String? {
        let s = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let cleaned = s.filter { $0.isHexDigit || $0 == ":" || $0 == "-" }
        return cleaned.isEmpty ? nil : cleaned
    }

    /// "FD6F", "0000fd6f-0000-1000-8000-00805f9b34fb" → lowercased, dashes preserved
    static func normalizeServiceUUID(_ raw: String) -> String? {
        var s = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("0x") { s = String(s.dropFirst(2)) }
        let cleaned = s.filter { $0.isHexDigit || $0 == "-" }
        return cleaned.isEmpty ? nil : cleaned
    }

    // MARK: - Matching

    /// Score > 0 when the advertisement matches this profile. Higher scores
    /// mean more specific matches; the best matching profile wins.
    func matchScore(_ signature: AdvertisementSignature) -> Int {
        var score = 0
        if let prefix = manufacturerPrefix, !prefix.isEmpty,
           let manufacturer = signature.manufacturerHex, manufacturer.hasPrefix(prefix) {
            score += 1000 + prefix.count
        }
        if let prefix = serviceDataPrefix, !prefix.isEmpty {
            for entry in signature.serviceDataEntries where entry.hasPrefix(prefix) {
                score += 500 + prefix.count
                break
            }
        }
        if let uuid = serviceUUID, !uuid.isEmpty {
            for advertised in signature.serviceUUIDs where DeviceFingerprint.uuidMatches(uuid, advertised) {
                score += 250 + uuid.count
                break
            }
        }
        return score
    }

    /// Compare UUIDs, accepting a 16/32-bit short form against its 128-bit expansion.
    static func uuidMatches(_ a: String, _ b: String) -> Bool {
        let x = a.lowercased().replacingOccurrences(of: "-", with: "")
        let y = b.lowercased().replacingOccurrences(of: "-", with: "")
        if x == y { return true }
        if x.count == 4 && y.count == 32 { return y.hasPrefix("0000" + x) }
        if y.count == 4 && x.count == 32 { return x.hasPrefix("0000" + y) }
        if x.count == 8 && y.count == 32 { return y.hasPrefix(x) }
        if y.count == 8 && x.count == 32 { return x.hasPrefix(y) }
        return false
    }
}

/// Parsed, normalized facts of one advertisement payload.
struct AdvertisementSignature {
    let manufacturerHex: String?
    let serviceDataEntries: [String]   // "uuid:hex", lowercased
    let serviceUUIDs: [String]         // lowercased

    init(advertisementData: [String: Any]) {
        if let data = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data {
            manufacturerHex = data.map { String(format: "%02x", $0) }.joined()
        } else {
            manufacturerHex = nil
        }

        var entries: [String] = []
        if let serviceData = advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] {
            for (key, value) in serviceData {
                entries.append(key.uuidString.lowercased() + ":" + value.map { String(format: "%02x", $0) }.joined())
            }
        }
        serviceDataEntries = entries.sorted()

        var uuids: [String] = []
        if let list = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
            uuids.append(contentsOf: list.map { $0.uuidString.lowercased() })
        }
        if let list = advertisementData[CBAdvertisementDataOverflowServiceUUIDsKey] as? [CBUUID] {
            uuids.append(contentsOf: list.map { $0.uuidString.lowercased() })
        }
        serviceUUIDs = uuids
    }

    /// Build a signature from already-parsed advertisement facts.
    init(manufacturerHex: String?, serviceDataEntries: [String], serviceUUIDs: [String]) {
        self.manufacturerHex = manufacturerHex
        self.serviceDataEntries = serviceDataEntries
        self.serviceUUIDs = serviceUUIDs
    }

    /// Fingerprint defaults suggested when the user picks a discovered device.
    var suggestedManufacturerPrefix: String? {
        guard let hex = manufacturerHex, !hex.isEmpty else { return nil }
        return String(hex.prefix(6))
    }

    var suggestedServiceDataPrefix: String? {
        guard let first = serviceDataEntries.first, !first.isEmpty else { return nil }
        return String(first.prefix(8))
    }
}

/// Persistence for fingerprint profiles (UserDefaults, JSON encoded).
enum FingerprintProfileStore {
    static let defaultsKey = "fingerprintDevices"

    static func load(from defaults: UserDefaults = .standard) -> [DeviceFingerprint] {
        guard let data = defaults.data(forKey: defaultsKey) else { return [] }
        return (try? JSONDecoder().decode([DeviceFingerprint].self, from: data)) ?? []
    }

    static func save(_ profiles: [DeviceFingerprint], to defaults: UserDefaults = .standard) {
        guard let data = try? JSONEncoder().encode(profiles) else { return }
        defaults.set(data, forKey: defaultsKey)
    }
}
