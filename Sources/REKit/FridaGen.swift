import Foundation

/// Generates Frida agent scripts from verified class/selector pairs.
/// Guards mirror frida-ios-hooks discipline: check bridge, check class, check method,
/// bounded event budget, optional argument reads only when requested.
public enum FridaGen {
    public struct HookRequest {
        public var className: String
        public var selector: String
        public var logBacktrace: Bool
        public var logObject: Bool

        public init(className: String, selector: String, logBacktrace: Bool = false, logObject: Bool = false) {
            self.className = className
            self.selector = selector
            self.logBacktrace = logBacktrace
            self.logObject = logObject
        }
    }

    public static func script(bundleID: String, requests: [HookRequest]) -> String {
        var js = """
        // REKit agent — generated \(ISO8601DateFormatter().string(from: Date()))
        // target: \(bundleID)
        if (typeof ObjC === 'undefined' || !ObjC.available) {
            console.log('[-] ObjC bridge unavailable; abort');
        } else {
            let hookCount = 0;
            let armed = 0;

        """
        for req in requests {
            let sel = req.selector
            let isClassMethod = sel.hasPrefix("+")
            let cleanSel = sel.replacingOccurrences(of: "+", with: "").replacingOccurrences(of: "-", with: "")
            let key = "\(isClassMethod ? "+" : "-") "
            let objectLog = req.logObject
                ? "try { console.log('    self=' + new ObjC.Object(args[0])); } catch (e) {}"
                : ""
            let backtraceLog = req.logBacktrace
                ? "console.log('    bt=' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));"
                : ""
            js += """

                (function () {
                    var CLS = '\(req.className)';
                    var SEL = '\(cleanSel)';
                    var cls = ObjC.classes[CLS];
                    if (!cls) { console.log('[-] class missing: ' + CLS); return; }
                    var method = cls['\(key)' + SEL];
                    if (!method) { console.log('[-] selector missing: ' + CLS + ' \(key)' + SEL); return; }
                    console.log('[+] hooking ' + CLS + ' \(key)' + SEL);
                    armed++;
                    Interceptor.attach(method.implementation, {
                        onEnter: function (args) {
                            hookCount++;
                            if (hookCount > 1000) { return; }
                            this._t = Date.now();
                            \(objectLog)
                            \(backtraceLog)
                        },
                        onLeave: function (retval) {
                            console.log('[<] ' + CLS + ' \(key)' + SEL + ' ' + (Date.now() - this._t) + 'ms');
                        }
                    });
                })();

                """
        }
        js += """
            console.log('[+] REKit agent ready, armed=' + armed);
        }
        """
        return js
    }

    /// Minimal spawn-and-attach recipe for the CLI.
    public static func command(bundleID: String, scriptPath: String) -> String {
        "frida -U -f \(bundleID) -l \(scriptPath)"
    }
}
