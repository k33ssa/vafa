// Vafa.app — значок в строке меню для демона vpn-guard.
//
// Состояние берёт из /usr/local/var/vpn-guard/status.json (демон пишет его каждые
// INTERVAL секунд, читается без sudo). Список приложений записывает в
// /usr/local/etc/vpn-guard.apps через запрос пароля администратора — файл
// принадлежит root, иначе любая программа пользователя могла бы его переписать.
//
// Сборка: ./build.sh

import AppKit
import SwiftUI
import ServiceManagement

let statusPath = "/usr/local/var/vpn-guard/status.json"
let appsFilePath = "/usr/local/etc/vpn-guard.apps"
let countriesFilePath = "/usr/local/etc/vpn-guard.countries"
let defaultCountries = ["RU", "CN", "BY", "IR"]

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
    // nil — старый демон, который о странах ещё не знает
    let countries: [String]?
    let geo: Bool?
}

func readStatus() -> GuardStatus? {
    guard let data = FileManager.default.contents(atPath: statusPath) else { return nil }
    return try? JSONDecoder().decode(GuardStatus.self, from: data)
}

func appName(_ path: String) -> String {
    ((path as NSString).lastPathComponent as NSString).deletingPathExtension
}

// Записать файл в /usr/local/etc от root. Пароль спрашивает macOS, приложение его
// не видит. nil — записано; "" — нажали «Отменить»; иначе текст ошибки.
func installAsRoot(_ body: String, to dest: String) -> String? {
    let tmp = NSTemporaryDirectory() + "vafa.\(getpid()).\((dest as NSString).lastPathComponent)"
    do { try body.write(toFile: tmp, atomically: true, encoding: .utf8) } catch {
        return "Не смог записать временный файл: \(error.localizedDescription)"
    }
    defer { try? FileManager.default.removeItem(atPath: tmp) }
    let q = { (s: String) in "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    let cmd = "/usr/bin/install -m 644 -o root -g wheel \(q(tmp)) \(q(dest))"
    let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"
    var err: NSDictionary?
    NSAppleScript(source: script)?.executeAndReturnError(&err)
    if let err = err {
        if (err[NSAppleScript.errorNumber] as? Int) == -128 { return "" }   // нажали «Отменить»
        return (err[NSAppleScript.errorMessage] as? String) ?? "ошибка записи"
    }
    return nil
}

func flag(_ code: String) -> String {
    String(String.UnicodeScalarView(code.unicodeScalars.compactMap { Unicode.Scalar(127397 + $0.value) }))
}

let ruLocale = Locale(identifier: "ru_RU")
func countryName(_ code: String) -> String {
    ruLocale.localizedString(forRegionCode: code) ?? code
}

// MARK: - выбор приложений

final class PickerModel: ObservableObject {
    struct Item: Identifiable { let id: String; let name: String; let icon: NSImage }
    @Published var items: [Item] = []
    @Published var selected: Set<String> = []
    @Published var filter = ""
    @Published var error: String?
    @Published var status: GuardStatus?

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
        let body = "# Пишет Vafa.app. Одна строка — один путь к .app.\n"
            + selected.sorted().joined(separator: "\n") + "\n"
        guard let e = installAsRoot(body, to: appsFilePath) else { return true }
        if !e.isEmpty { error = e }
        return false
    }
}

// MARK: - выбор стран

final class CountryModel: ObservableObject {
    struct Item: Identifiable { let id: String; let name: String }
    @Published var items: [Item] = []
    @Published var selected: Set<String> = []
    @Published var filter = ""
    @Published var error: String?
    var geoOn = true

    func load(current: [String], geoOn: Bool) {
        self.geoOn = geoOn
        let codes = Set(Locale.isoRegionCodes.filter { $0.count == 2 && Int($0) == nil }).union(current)
        items = codes.map { Item(id: $0, name: countryName($0)) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        selected = Set(current)
        filter = ""
        error = nil
    }

    // выбранные — сверху, чтобы было видно, что сейчас блокируется
    var visible: [Item] {
        let f = filter.trimmingCharacters(in: .whitespaces)
        let list = f.isEmpty ? items : items.filter {
            $0.name.localizedCaseInsensitiveContains(f) || $0.id.caseInsensitiveCompare(f) == .orderedSame
        }
        return list.filter { selected.contains($0.id) } + list.filter { !selected.contains($0.id) }
    }

    func save() -> Bool {
        let body = "# Пишет Vafa.app. Одна строка — один код страны (ISO, две буквы).\n"
            + selected.sorted().joined(separator: "\n") + "\n"
        guard let e = installAsRoot(body, to: countriesFilePath) else { return true }
        if !e.isEmpty { error = e }
        return false
    }
}

struct CountryView: View {
    @ObservedObject var model: CountryModel
    var onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Страны, из которых VPN считается выключенным").font(.headline)
            Text("Если интернет видит тебя из отмеченной страны — приложения блокируются, даже когда туннель поднят.")
                .font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            if !model.geoOn {
                Text("Проверка страны выключена в /usr/local/etc/vpn-guard.conf: добавь geo в VPN_CHECK.")
                    .font(.caption).foregroundColor(.orange).fixedSize(horizontal: false, vertical: true)
            }
            TextField("Поиск: название или код (CN)", text: $model.filter).textFieldStyle(.roundedBorder)
            List(model.visible) { item in
                Toggle(isOn: Binding(
                    get: { model.selected.contains(item.id) },
                    set: { on in if on { model.selected.insert(item.id) } else { model.selected.remove(item.id) } }
                )) {
                    HStack {
                        Text(flag(item.id))
                        Text(item.name)
                        Text(item.id).foregroundColor(.secondary)
                    }
                }
            }
            if model.selected.isEmpty {
                Text("Ничего не выбрано — страна проверяться не будет, только туннель.")
                    .font(.caption).foregroundColor(.orange)
            }
            if let e = model.error { Text(e).foregroundColor(.red).font(.caption) }
            HStack {
                Button("По умолчанию") { model.selected = Set(defaultCountries) }
                Text("Выбрано: \(model.selected.count)").foregroundColor(.secondary)
                Spacer()
                Button("Сохранить") { if model.save() { onClose() } }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(minWidth: 420, minHeight: 560)
    }
}

struct PickerView: View {
    @ObservedObject var model: PickerModel
    var onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            StatusView(status: model.status)
            Divider()
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
                Button("Сохранить") { if model.save() { onClose() } }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(minWidth: 460, minHeight: 600)
    }
}

struct StatusView: View {
    let status: GuardStatus?
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let s = status {
                let stale = Date().timeIntervalSince1970 - s.time > 20
                Text(stale ? "Демон не отвечает" : (s.vpn ? "VPN: поднят" : "VPN: ВЫКЛЮЧЕН — блокировка"))
                    .font(.title2.bold())
                    .foregroundColor(stale ? .orange : (s.vpn ? .green : .red))
                Text("маршрут: \(s.iface.isEmpty ? "—" : s.iface), страна: \(s.country.isEmpty ? "нет ответа" : s.country)")
                    .foregroundColor(.secondary)
                ForEach(s.apps, id: \.path) { a in
                    Text("\(appName(a.path)) — запуск: \(a.locked ? "ЗАБЛОКИРОВАНО" : "разблокировано"), процессов: \(a.procs)"
                         + (a.frozen > 0 ? ", заморожено: \(a.frozen)" : ""))
                        .foregroundColor(a.frozen > 0 ? .red : .primary)
                }
            } else {
                Text("Нет данных от демона").font(.title2.bold()).foregroundColor(.orange)
            }
        }
    }
}

// MARK: - строка меню

// Новый значок macOS ставит левее всех — при забитой строке меню он уходит под вырез
// камеры и его не видно. Поэтому при первом запуске просим место ближе к часам
// (расстояние от правого края). Если пользователь потом перетащит щит с ⌘, macOS
// запишет своё значение и мы его не трогаем.
let positionKey = "NSStatusItem Preferred Position Item-0"
func placeStatusItemNearClock() {
    if UserDefaults.standard.object(forKey: positionKey) == nil {
        UserDefaults.standard.set(260.0, forKey: positionKey)
    }
}

final class Controller: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item: NSStatusItem = {
        placeStatusItemNearClock()
        return NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    }()
    let menu = NSMenu()
    let picker = PickerModel()
    let countries = CountryModel()
    var window: NSWindow?
    var countryWindow: NSWindow?
    var logWindow: NSWindow?
    var logView: NSTextView?
    var last: GuardStatus?

    func applicationDidFinishLaunching(_ n: Notification) {
        menu.delegate = self
        item.menu = menu
        refresh()
        Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
        // первый запуск — сразу включить автозапуск при входе; дальше решает пользователь
        let d = UserDefaults.standard
        if !d.bool(forKey: "loginItemAsked") {
            d.set(true, forKey: "loginItemAsked")
            setLoginItem(true)
        }
    }

    func applicationShouldHandleReopen(_ s: NSApplication, hasVisibleWindows: Bool) -> Bool {
        openPicker(); return true
    }

    func isStale(_ s: GuardStatus) -> Bool { Date().timeIntervalSince1970 - s.time > 20 }

    func refresh() {
        last = readStatus()
        picker.status = last
        // охрана выключена — сразу пустой контур, не ждать, пока status.json устареет
        let on = guardOn()
        let symbol: String, tint: NSColor
        switch last {
        case _ where !on: symbol = "shield"; tint = .systemGreen
        // охрана выключена (демон не работает) или сторожить нечего — пустой контур
        case nil: symbol = "shield"; tint = .systemGreen
        case let s? where isStale(s) || s.apps.isEmpty: symbol = "shield"; tint = .systemGreen
        case let s? where s.vpn: symbol = "checkmark.shield.fill"; tint = .systemGreen
        default: symbol = "xmark.shield.fill"; tint = .systemRed
        }
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "Vafa")?
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
            if !guardOn() {
                info("Охрана выключена", bold: true, color: .secondaryLabelColor)
            } else if isStale(s) {
                info("Демон не отвечает", bold: true, color: .systemOrange)
                info("последнее обновление: \(Int(Date().timeIntervalSince1970 - s.time)) с назад")
            } else {
                info(s.vpn ? "VPN: поднят" : "VPN: ВЫКЛЮЧЕН — блокировка", bold: true,
                     color: s.vpn ? .systemGreen : .systemRed)
            }
            info("маршрут: \(s.iface.isEmpty ? "—" : s.iface), страна: \(s.country.isEmpty ? "нет ответа" : s.country)")
            if let cc = s.countries {
                let on = s.geo ?? true
                info(!on ? "проверка страны выключена в конфиге"
                     : cc.isEmpty ? "страны блокировки не выбраны"
                     : "блокировать из: " + cc.map { "\(flag($0)) \($0)" }.joined(separator: "  "))
            }
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
        let cc = NSMenuItem(title: "Выбрать страны…", action: #selector(openCountries), keyEquivalent: "")
        cc.target = self
        menu.addItem(cc)
        let log = NSMenuItem(title: "Открыть журнал", action: #selector(openLog), keyEquivalent: "")
        log.target = self
        menu.addItem(log)
        menu.addItem(.separator())
        let on = guardOn()
        let g = NSMenuItem(title: "Охрана включена", action: #selector(toggleGuard), keyEquivalent: "")
        g.state = on ? .on : .off
        g.target = self
        menu.addItem(g)
        let li = NSMenuItem(title: "Запускать при входе в систему", action: #selector(toggleLogin), keyEquivalent: "")
        li.state = loginItemOn() ? .on : .off
        li.target = self
        menu.addItem(li)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Выйти", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    // Демон загружен? launchctl print system/... без root работает.
    func guardOn() -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["print", "system/local.vpnguard"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    // Выключение = выгрузить демон, запретить ему стартовать и снять всю блокировку.
    // Включение — наоборот. Оба через пароль администратора.
    @objc func toggleGuard() {
        let plist = "/Library/LaunchDaemons/local.vpnguard.plist"
        let cmd = guardOn()
            ? "launchctl bootout system \(plist); launchctl disable system/local.vpnguard; /usr/local/bin/vpn-guard unlock"
            : "launchctl enable system/local.vpnguard; launchctl bootstrap system \(plist)"
        var err: NSDictionary?
        NSAppleScript(source: "do shell script \"\(cmd)\" with administrator privileges")?.executeAndReturnError(&err)
        refresh()
    }

    func loginItemOn() -> Bool {
        if #available(macOS 13.0, *) { return SMAppService.mainApp.status == .enabled }
        return false
    }

    func setLoginItem(_ on: Bool) {
        guard #available(macOS 13.0, *) else { return }
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            NSLog("Vafa: автозапуск: \(error)")
        }
    }

    @objc func toggleLogin() {
        guard #available(macOS 13.0, *) else {
            let a = NSAlert()
            a.messageText = "На macOS 12 автозапуск включается вручную: Системные настройки → Пользователи → Объекты входа."
            a.runModal()
            return
        }
        setLoginItem(!loginItemOn())
    }

    // Журнал в своём окне: новые записи сверху. Сам файл пишется по порядку (дописывание
    // в конец), здесь только показываем последние 2000 строк в обратном порядке.
    func reversedLog() -> String {
        guard let data = FileManager.default.contents(atPath: "/usr/local/var/log/vpn-guard.log"),
              let text = String(data: data, encoding: .utf8) else { return "Журнал пуст или недоступен" }
        return text.split(separator: "\n").suffix(2000).reversed().joined(separator: "\n")
    }

    @objc func openLog() {
        if logWindow == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
                             styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
            w.title = "Vafa — журнал (новые сверху)"
            w.isReleasedWhenClosed = false
            let scroll = NSTextView.scrollableTextView()
            let tv = scroll.documentView as! NSTextView
            tv.isEditable = false
            tv.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            w.contentView = scroll
            w.center()
            logWindow = w; logView = tv
            Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
                guard let self = self, self.logWindow?.isVisible == true else { return }
                self.logView?.string = self.reversedLog()
            }
        }
        logView?.string = reversedLog()
        logView?.scrollToBeginningOfDocument(nil)
        NSApp.activate(ignoringOtherApps: true)
        logWindow?.makeKeyAndOrderFront(nil)
    }

    @objc func openCountries() {
        // старый демон не пишет страны в status.json — тогда показать список по умолчанию
        countries.load(current: last?.countries ?? defaultCountries, geoOn: last?.geo ?? true)
        if countryWindow == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 560),
                             styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            w.title = "Vafa — страны"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: CountryView(model: countries) { [weak self] in
                self?.countryWindow?.close()
                self?.refresh()
            })
            w.center()
            countryWindow = w
        }
        NSApp.activate(ignoringOtherApps: true)
        countryWindow?.makeKeyAndOrderFront(nil)
    }

    @objc func openPicker() {
        picker.load(current: last?.apps.map(\.path) ?? [])
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 520),
                             styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            w.title = "Vafa"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: PickerView(model: picker) { [weak self] in
                self?.refresh()   // выбор остаётся как сохранили; демон подхватит за ~2 с
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
app.setActivationPolicy(.accessory)   // только значок в строке меню, без Dock
app.run()
