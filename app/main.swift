// VPN Guard.app — значок в строке меню для демона vpn-guard.
//
// Состояние берёт из /usr/local/var/vpn-guard/status.json (демон пишет его каждые
// INTERVAL секунд, читается без sudo). Список приложений записывает в
// /usr/local/etc/vpn-guard.apps через запрос пароля администратора — файл
// принадлежит root, иначе любая программа пользователя могла бы его переписать.
//
// Сборка: ./build.sh

import AppKit
import SwiftUI

let statusPath = "/usr/local/var/vpn-guard/status.json"
let appsFilePath = "/usr/local/etc/vpn-guard.apps"

struct AppState: Decodable {
    let path: String
    let locked: Bool
    let procs: Int
    let frozen: Int
}

struct GuardStatus: Decodable {
    let time: Double
    let vpn: Bool
    let iface: String
    let country: String
    let on_down: String
    let apps: [AppState]
}

func readStatus() -> GuardStatus? {
    guard let data = FileManager.default.contents(atPath: statusPath) else { return nil }
    return try? JSONDecoder().decode(GuardStatus.self, from: data)
}

func appName(_ path: String) -> String {
    ((path as NSString).lastPathComponent as NSString).deletingPathExtension
}

// MARK: - выбор приложений

final class PickerModel: ObservableObject {
    struct Item: Identifiable { let id: String; let name: String; let icon: NSImage }
    @Published var items: [Item] = []
    @Published var selected: Set<String> = []
    @Published var filter = ""
    @Published var error: String?

    func load(current: [String]) {
        let fm = FileManager.default
        var paths = Set<String>()
        let dirs = ["/Applications", "/Applications/Utilities", NSHomeDirectory() + "/Applications"]
        for d in dirs {
            for f in (try? fm.contentsOfDirectory(atPath: d)) ?? [] where f.hasSuffix(".app") {
                paths.insert(d + "/" + f)
            }
        }
        paths.formUnion(current)   // уже выбранное показывать, даже если его нет на месте
        items = paths.map { Item(id: $0, name: appName($0), icon: NSWorkspace.shared.icon(forFile: $0)) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        selected = Set(current)
        error = nil
    }

    var visible: [Item] {
        filter.isEmpty ? items : items.filter { $0.name.localizedCaseInsensitiveContains(filter) }
    }

    // true — записано. Пароль спрашивает macOS, приложение его не видит.
    func save() -> Bool {
        let body = "# Пишет VPN Guard.app. Одна строка — один путь к .app.\n"
            + selected.sorted().joined(separator: "\n") + "\n"
        let tmp = NSTemporaryDirectory() + "vpn-guard.apps.\(getpid())"
        do { try body.write(toFile: tmp, atomically: true, encoding: .utf8) } catch {
            self.error = "Не смог записать временный файл: \(error.localizedDescription)"; return false
        }
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let q = { (s: String) in "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let cmd = "/usr/bin/install -m 644 -o root -g wheel \(q(tmp)) \(q(appsFilePath))"
        let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"
        var err: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&err)
        if let err = err {
            if (err[NSAppleScript.errorNumber] as? Int) == -128 { return false }   // нажали «Отменить»
            self.error = (err[NSAppleScript.errorMessage] as? String) ?? "ошибка записи"
            return false
        }
        return true
    }
}

struct PickerView: View {
    @ObservedObject var model: PickerModel
    var onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Приложения, которые блокируются без VPN").font(.headline)
            TextField("Поиск", text: $model.filter).textFieldStyle(.roundedBorder)
            List(model.visible) { item in
                Toggle(isOn: Binding(
                    get: { model.selected.contains(item.id) },
                    set: { on in if on { model.selected.insert(item.id) } else { model.selected.remove(item.id) } }
                )) {
                    HStack {
                        Image(nsImage: item.icon).resizable().frame(width: 20, height: 20)
                        Text(item.name)
                        if !FileManager.default.fileExists(atPath: item.id) {
                            Text("(не найдено)").foregroundColor(.secondary)
                        }
                    }
                }
            }
            if let e = model.error { Text(e).foregroundColor(.red).font(.caption) }
            HStack {
                Text("Выбрано: \(model.selected.count)").foregroundColor(.secondary)
                Spacer()
                Button("Отмена", action: onClose).keyboardShortcut(.cancelAction)
                Button("Сохранить") { if model.save() { onClose() } }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(minWidth: 420, minHeight: 480)
    }
}

// MARK: - строка меню

final class Controller: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    let picker = PickerModel()
    var window: NSWindow?
    var last: GuardStatus?

    func applicationDidFinishLaunching(_ n: Notification) {
        menu.delegate = self
        item.menu = menu
        refresh()
        Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func isStale(_ s: GuardStatus) -> Bool { Date().timeIntervalSince1970 - s.time > 20 }

    func refresh() {
        last = readStatus()
        let symbol: String, tint: NSColor
        switch last {
        case nil: symbol = "exclamationmark.shield"; tint = .systemOrange
        case let s? where isStale(s): symbol = "exclamationmark.shield"; tint = .systemOrange
        case let s? where s.vpn: symbol = "checkmark.shield.fill"; tint = .systemGreen
        default: symbol = "xmark.shield.fill"; tint = .systemRed
        }
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "VPN Guard")?
            .withSymbolConfiguration(.init(paletteColors: [tint]))
        item.button?.image = img
        if menu.numberOfItems > 0 { rebuild() }   // меню открыто — обновить на лету
    }

    func menuWillOpen(_ m: NSMenu) { last = readStatus(); rebuild() }
    func menuDidClose(_ m: NSMenu) { menu.removeAllItems() }

    func info(_ title: String, bold: Bool = false, color: NSColor? = nil) {
        let mi = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        var attrs: [NSAttributedString.Key: Any] = [.font: bold ? NSFont.boldSystemFont(ofSize: 13) : NSFont.menuFont(ofSize: 13)]
        if let c = color { attrs[.foregroundColor] = c }
        mi.attributedTitle = NSAttributedString(string: title, attributes: attrs)
        menu.addItem(mi)
    }

    func rebuild() {
        menu.removeAllItems()
        if let s = last {
            if isStale(s) {
                info("Демон не отвечает", bold: true, color: .systemOrange)
                info("последнее обновление: \(Int(Date().timeIntervalSince1970 - s.time)) с назад")
            } else {
                info(s.vpn ? "VPN: поднят" : "VPN: ВЫКЛЮЧЕН — блокировка", bold: true,
                     color: s.vpn ? .systemGreen : .systemRed)
            }
            info("маршрут: \(s.iface.isEmpty ? "—" : s.iface), страна: \(s.country.isEmpty ? "нет ответа" : s.country)")
            menu.addItem(.separator())
            if s.apps.isEmpty { info("Приложения не выбраны") }
            for a in s.apps {
                info(appName(a.path), bold: true)
                var line = "   запуск: \(a.locked ? "ЗАБЛОКИРОВАНО" : "разблокировано"), процессов: \(a.procs)"
                if a.frozen > 0 { line += ", заморожено: \(a.frozen)" }
                info(line, color: a.frozen > 0 ? .systemRed : nil)
            }
        } else {
            info("Нет данных от демона", bold: true, color: .systemOrange)
            info("не найден \(statusPath)")
            info("обнови демон: sudo ~/vpn-guard/install.sh")
        }
        menu.addItem(.separator())
        let pick = NSMenuItem(title: "Выбрать приложения…", action: #selector(openPicker), keyEquivalent: ",")
        pick.target = self
        menu.addItem(pick)
        let log = NSMenuItem(title: "Открыть журнал", action: #selector(openLog), keyEquivalent: "")
        log.target = self
        menu.addItem(log)
        menu.addItem(NSMenuItem(title: "Выйти", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    @objc func openLog() {
        NSWorkspace.shared.open(URL(fileURLWithPath: "/usr/local/var/log/vpn-guard.log"))
    }

    @objc func openPicker() {
        picker.load(current: last?.apps.map(\.path) ?? [])
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 520),
                             styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            w.title = "VPN Guard"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: PickerView(model: picker) { [weak self] in
                self?.window?.close()
                self?.refresh()
            })
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

let app = NSApplication.shared
let controller = Controller()
app.delegate = controller
app.setActivationPolicy(.accessory)
app.run()
