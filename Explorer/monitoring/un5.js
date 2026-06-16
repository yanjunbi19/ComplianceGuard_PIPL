(function () {
    console.log("[*] Mode: Anti-Detection V10 - Enhanced");

    if (global._frida_script_loaded_v10) {
        console.log("[!] Script already loaded, skipping...");
        return;
    }
    global._frida_script_loaded_v10 = true;
function diag_install() {
    function now() { return (new Date()).toISOString(); }

    function safeStr(p) {
        try { return p.isNull() ? "NULL" : p.readUtf8String(); } catch (e) { return "<?>"; }
    }

    function addrInfo(a) {
        try {
            var m = Process.findModuleByAddress(a);
            if (m) return a + " (" + m.name + "+" + ptr(a).sub(m.base) + ")";
        } catch (e) {}
        return String(a);
    }

    // 1) 捕获 native 崩溃信号（不改行为，只记录）
    Process.setExceptionHandler(function (details) {
        try {
            send({
                diag: "exception",
                ts: now(),
                type: details.type,
                address: String(details.address),
                memory: details.memory ? String(details.memory.address) : null
            });
        } catch (e) {}
        return false; // 继续走系统默认处理
    });

    // 2) 记录 kill/abort/exit 的调用来源（返回地址、模块）
    function traceNative(name, retType, argTypes, fmt) {
        var p = Module.findExportByName("libc.so", name);
        if (!p) return;

        Interceptor.attach(p, {
            onEnter: function (args) {
                this.bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 8)
                    .map(addrInfo)
                    .join(" <- ");

                var msg = "";
                try { msg = fmt(args); } catch (e) { msg = "<fmt err>"; }

                send({
                    diag: "native-call",
                    ts: now(),
                    fn: name,
                    msg: msg,
                    bt: this.bt
                });
            }
        });
    }

    traceNative("kill", "int", ["int", "int"], function (args) {
        return "pid=" + args[0].toInt32() + " sig=" + args[1].toInt32();
    });

    traceNative("tgkill", "int", ["int", "int", "int"], function (args) {
        return "tgid=" + args[0].toInt32() + " tid=" + args[1].toInt32() + " sig=" + args[2].toInt32();
    });

    traceNative("raise", "int", ["int"], function (args) {
        return "sig=" + args[0].toInt32();
    });

    traceNative("abort", "void", [], function () { return ""; });
    traceNative("exit", "void", ["int"], function (args) { return "code=" + args[0].toInt32(); });
    traceNative("_exit", "void", ["int"], function (args) { return "code=" + args[0].toInt32(); });

    // 3) Java 层崩溃线索：UncaughtExceptionHandler（只记录）
    if (Java.available) {
        Java.perform(function () {
            try {
                var ThreadClz = Java.use("java.lang.Thread");
                var Handler = Java.registerClass({
                    name: "com.opencode.DiagUEH",
                    implements: [Java.use("java.lang.Thread$UncaughtExceptionHandler")],
                    methods: {
                        uncaughtException: function (t, e) {
                            try {
                                send({
                                    diag: "java-uncaught",
                                    ts: now(),
                                    thread: t ? String(t.getName()) : "<?>",
                                    ex: e ? String(e.toString()) : "<?>"
                                });
                            } catch (x) {}
                        }
                    }
                });

                var orig = ThreadClz.getDefaultUncaughtExceptionHandler();
                ThreadClz.setDefaultUncaughtExceptionHandler(Handler.$new());
                // 不覆盖链式调用，先只记录；需要的话你可以再把 orig 保存并转发
            } catch (e) {}
        });
    }
}

diag_install();

    var Files = new Map();
    var libc = "libc.so";

    var getpid = new NativeFunction(Module.findExportByName(libc, "getpid"), 'int', []);
    var gettid = new NativeFunction(Module.findExportByName(libc, "gettid"), 'int', []);
    var usleep = new NativeFunction(Module.findExportByName(libc, "usleep"), 'int', ['uint']);

    var myPid = getpid();

    var importantThreads = {};
    importantThreads[gettid()] = "init";

    var frozenCount = 0;
    var MAX_FROZEN = 10;

    console.log("[*] Anti-Detection V10 | pid=" + myPid);

    function shouldFreeze() {
        var tid = gettid();
        if (importantThreads[tid]) {
            console.log("[*] Thread " + tid + " is important (" + importantThreads[tid] + "), not freezing");
            return false;
        }
        if (frozenCount >= MAX_FROZEN) {
            console.log("[*] Too many frozen threads (" + frozenCount + "), not freezing " + tid);
            return false;
        }
        return true;
    }

    function freezeThread() {
        var tid = gettid();
        frozenCount++;
        console.log("[*] Freezing thread " + tid + " (total frozen: " + frozenCount + ")");
        while (true) {
            usleep(10000000);
        }
    }

    // =========================================================
    // 1. 反检测 Hooks - 增强版
    // =========================================================
    function universal_anti_detection() {
        if (global._anti_detection_v10_done) return;
        global._anti_detection_v10_done = true;

        if (!global._hooked_addrs_v10) global._hooked_addrs_v10 = {};

        function safeReplace(name, callback, retType, argTypes) {
            try {
                var ptr = Module.findExportByName(libc, name);
                if (!ptr) {
                    console.log("[-] " + name + " not found");
                    return null;
                }
                var key = ptr.toString();
                if (global._hooked_addrs_v10[key]) {
                    console.log("[*] " + name + " already hooked");
                    return null;
                }
                var original = new NativeFunction(ptr, retType, argTypes);
                Interceptor.replace(ptr, new NativeCallback(callback, retType, argTypes));
                global._hooked_addrs_v10[key] = true;
                console.log("[+] " + name);
                return original;
            } catch (e) {
                console.log("[-] " + name + ": " + e.message);
                return null;
            }
        }

        // ========== abort ==========
        safeReplace("abort", function() {
            var tid = gettid();
            console.log("[!] abort() | tid=" + tid);
            if (shouldFreeze()) {
                freezeThread();
            }
            // 重要线程：直接返回，不做任何事
        }, 'void', []);

        // ========== __stack_chk_fail ==========
        safeReplace("__stack_chk_fail", function() {
            var tid = gettid();
            console.log("[!] __stack_chk_fail | tid=" + tid);
            if (shouldFreeze()) {
                freezeThread();
            }
        }, 'void', []);

        // ========== __assert2 ==========
        safeReplace("__assert2", function(file, line, func, expr) {
            var tid = gettid();
            console.log("[!] __assert2 | tid=" + tid);
            if (shouldFreeze()) {
                freezeThread();
            }
        }, 'void', ['pointer', 'int', 'pointer', 'pointer']);

        // ========== __fortify_fatal ==========
        safeReplace("__fortify_fatal", function(fmt) {
            var tid = gettid();
            console.log("[!] __fortify_fatal | tid=" + tid);
            if (shouldFreeze()) {
                freezeThread();
            }
        }, 'void', ['pointer']);

        // ========== exit 系列 ==========
        safeReplace("exit", function(code) {
            console.log("[!] exit(" + code + ") | tid=" + gettid() + " -> NOP");
        }, 'void', ['int']);

        safeReplace("_exit", function(code) {
            console.log("[!] _exit(" + code + ") | tid=" + gettid() + " -> NOP");
        }, 'void', ['int']);

        safeReplace("_Exit", function(code) {
            console.log("[!] _Exit(" + code + ") | tid=" + gettid() + " -> NOP");
        }, 'void', ['int']);

        // ========== 信号相关 ==========
        var dangerSignals = {4:1, 5:1, 6:1, 7:1, 8:1, 9:1, 11:1, 15:1};

        var origKill = safeReplace("kill", function(pid, sig) {
            if (dangerSignals[sig]) {
                console.log("[!] BLOCKED: kill(" + pid + ", sig=" + sig + ")");
                return 0;
            }
            return origKill ? origKill(pid, sig) : 0;
        }, 'int', ['int', 'int']);

        var origTgkill = safeReplace("tgkill", function(tgid, tid, sig) {
            if (dangerSignals[sig]) {
                console.log("[!] BLOCKED: tgkill(sig=" + sig + ")");
                return 0;
            }
            return origTgkill ? origTgkill(tgid, tid, sig) : 0;
        }, 'int', ['int', 'int', 'int']);

        safeReplace("raise", function(sig) {
            console.log("[!] BLOCKED: raise(" + sig + ")");
            return 0;
        }, 'int', ['int']);

        var origSigaction = safeReplace("sigaction", function(sig, act, oldact) {
            if (dangerSignals[sig]) {
                return 0;
            }
            return origSigaction ? origSigaction(sig, act, oldact) : 0;
        }, 'int', ['int', 'pointer', 'pointer']);

        // ========== pthread_kill ==========
        var origPthreadKill = safeReplace("pthread_kill", function(thread, sig) {
            if (dangerSignals[sig]) {
                console.log("[!] BLOCKED: pthread_kill(sig=" + sig + ")");
                return 0;
            }
            return origPthreadKill ? origPthreadKill(thread, sig) : 0;
        }, 'int', ['pointer', 'int']);

        // ========== ptrace ==========
        safeReplace("ptrace", function(req, pid, addr, data) {
            console.log("[!] ptrace(" + req + ") -> " + (req === 0 ? "0" : "-1"));
            return req === 0 ? 0 : -1;
        }, 'long', ['int', 'int', 'pointer', 'pointer']);

        // ========== 文件检测 ==========
        var blockedPaths = ["frida", "xposed", "substrate", "magisk", "gadget",
                           "/proc/self/maps", "/proc/self/status", "/proc/self/task",
                           "/proc/self/mem", "/data/local/tmp", "re.frida", "linjector"];

        function isBlockedPath(pathStr) {
            if (!pathStr) return false;
            var lower = pathStr.toLowerCase();
            for (var i = 0; i < blockedPaths.length; i++) {
                if (lower.indexOf(blockedPaths[i]) !== -1) return true;
            }
            return false;
        }

        var origFopen = safeReplace("fopen", function(path, mode) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (isBlockedPath(pathStr)) {
                console.log("[!] BLOCKED: fopen(" + pathStr + ")");
                return ptr(0);
            }
            return origFopen ? origFopen(path, mode) : ptr(0);
        }, 'pointer', ['pointer', 'pointer']);

        var origOpen = safeReplace("open", function(path, flags, mode) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (isBlockedPath(pathStr)) {
                console.log("[!] BLOCKED: open(" + pathStr + ")");
                return -1;
            }
            return origOpen ? origOpen(path, flags, mode) : -1;
        }, 'int', ['pointer', 'int', 'int']);

        var origOpenat = safeReplace("openat", function(dirfd, path, flags, mode) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (isBlockedPath(pathStr)) {
                console.log("[!] BLOCKED: openat(" + pathStr + ")");
                return -1;
            }
            return origOpenat ? origOpenat(dirfd, path, flags, mode) : -1;
        }, 'int', ['int', 'pointer', 'int', 'int']);

        var origAccess = safeReplace("access", function(path, mode) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (isBlockedPath(pathStr)) {
                return -1;
            }
            return origAccess ? origAccess(path, mode) : -1;
        }, 'int', ['pointer', 'int']);

        var origStat = safeReplace("stat", function(path, buf) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (pathStr && pathStr.indexOf("/system/fonts") !== -1) {
                return origStat ? origStat(path, buf) : -1;
            }
            if (isBlockedPath(pathStr)) {
                return -1;
            }
            return origStat ? origStat(path, buf) : -1;
        }, 'int', ['pointer', 'pointer']);

        var origLstat = safeReplace("lstat", function(path, buf) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (isBlockedPath(pathStr)) {
                return -1;
            }
            return origLstat ? origLstat(path, buf) : -1;
        }, 'int', ['pointer', 'pointer']);

        // ========== readlink (检测 /proc/self/exe) ==========
        var origReadlink = safeReplace("readlink", function(path, buf, size) {
            var pathStr = "";
            try { pathStr = path.readCString(); } catch(e) {}
            if (isBlockedPath(pathStr)) {
                console.log("[!] BLOCKED: readlink(" + pathStr + ")");
                return -1;
            }
            return origReadlink ? origReadlink(path, buf, size) : -1;
        }, 'long', ['pointer', 'pointer', 'long']);

        // ========== strstr (字符串搜索检测) ==========
        var origStrstr = safeReplace("strstr", function(haystack, needle) {
            var needleStr = "";
            try { needleStr = needle.readCString(); } catch(e) {}
            if (needleStr) {
                var lower = needleStr.toLowerCase();
                if (lower.indexOf("frida") !== -1 || lower.indexOf("xposed") !== -1 ||
                    lower.indexOf("substrate") !== -1 || lower.indexOf("gadget") !== -1) {
                    return ptr(0);
                }
            }
            return origStrstr ? origStrstr(haystack, needle) : ptr(0);
        }, 'pointer', ['pointer', 'pointer']);

        // ========== strcmp/strncmp (字符串比较检测) ==========
        var origStrcmp = safeReplace("strcmp", function(s1, s2) {
            var str1 = "", str2 = "";
            try { str1 = s1.readCString(); str2 = s2.readCString(); } catch(e) {}
            if ((str1 && str1.toLowerCase().indexOf("frida") !== -1) ||
                (str2 && str2.toLowerCase().indexOf("frida") !== -1)) {
                return 1; // 不相等
            }
            return origStrcmp ? origStrcmp(s1, s2) : 0;
        }, 'int', ['pointer', 'pointer']);

        // ========== dlopen (动态库加载检测) ==========
        var origDlopen = safeReplace("dlopen", function(filename, flags) {
            var name = "";
            try { name = filename.readCString(); } catch(e) {}
            if (name && isBlockedPath(name)) {
                console.log("[!] BLOCKED: dlopen(" + name + ")");
                return ptr(0);
            }
            return origDlopen ? origDlopen(filename, flags) : ptr(0);
        }, 'pointer', ['pointer', 'int']);

        // ========== Java 层 ==========
        setTimeout(function() {
            if (!Java.available) return;
            Java.perform(function() {
                try {
                    var Process = Java.use("android.os.Process");
                    var mainTid = Process.myTid();
                    importantThreads[mainTid] = "main(Java)";
                    console.log("[*] Java main thread tid: " + mainTid);
                } catch(e) {}

                try {
                    var Looper = Java.use("android.os.Looper");
                    var Handler = Java.use("android.os.Handler");
                    var Process = Java.use("android.os.Process");
                    var mainLooper = Looper.getMainLooper();
                    var handler = Handler.$new(mainLooper);
                    var Runnable = Java.use("java.lang.Runnable");
                    var getTidRunnable = Java.registerClass({
                        name: "com.frida.GetTidRunnable",
                        implements: [Runnable],
                        methods: {
                            run: function() {
                                var tid = Process.myTid();
                                importantThreads[tid] = "UI";
                                console.log("[*] UI thread tid: " + tid);
                            }
                        }
                    });
                    handler.post(getTidRunnable.$new());
                } catch(e) {
                    console.log("[-] Failed to get UI thread: " + e);
                }

                try {
                    var System = Java.use("java.lang.System");
                    System.exit.implementation = function(code) {
                        console.log("[!] BLOCKED: System.exit(" + code + ")");
                    };
                } catch (e) {}

                try {
                    var Runtime = Java.use("java.lang.Runtime");
                    Runtime.exit.implementation = function(code) {
                        console.log("[!] BLOCKED: Runtime.exit(" + code + ")");
                    };
                } catch (e) {}

                try {
                    var Process = Java.use("android.os.Process");
                    Process.killProcess.implementation = function(pid) {
                        console.log("[!] BLOCKED: Process.killProcess(" + pid + ")");
                    };
                } catch (e) {}

                try {
                    var Debug = Java.use("android.os.Debug");
                    Debug.isDebuggerConnected.implementation = function() { return false; };
                } catch (e) {}

                // ========== 额外的 Java 层检测绕过 ==========
                try {
                    var ActivityThread = Java.use("android.app.ActivityThread");
                    // 防止通过 ActivityThread 检测
                } catch(e) {}

                // 阻止 UncaughtExceptionHandler
                try {
                    var Thread = Java.use("java.lang.Thread");
                    Thread.setDefaultUncaughtExceptionHandler.implementation = function(handler) {
                        console.log("[!] BLOCKED: setDefaultUncaughtExceptionHandler");
                    };
                } catch(e) {}

                // 伪装 Build 信息
                try {
                    var Build = Java.use("android.os.Build");
                    // 不修改，保持原样
                } catch(e) {}

                console.log("[+] Java hooks ready");
            });
        }, 100);

        console.log("[*] Anti-Detection V10 Ready!");
    }

    universal_anti_detection();

    // =========================================================
    // 2. 工具类
    // =========================================================
    var Utils = {
        processReturnValue: function (retval) {
            try { return (retval === null || retval === undefined) ? "null" : retval.toString(); }
            catch (e) { return "[Object]"; }
        },
        getTS: function () {
            var d = new Date();
            var pad = function (n) { return n < 10 ? "0" + n : n; };
            return d.getFullYear().toString() + pad(d.getMonth() + 1) + pad(d.getDate()) +
                pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
        },
        b64: function (arrayBuffer) {
            var uint8 = new Uint8Array(arrayBuffer);
            var b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var l = uint8.length, result = "";
            for (var i = 0; i < l; i += 3) {
                var a = uint8[i], b = uint8[i + 1], c = uint8[i + 2];
                result += b64chars[a >> 2];
                result += b64chars[((a & 3) << 4) | (b >> 4)];
                if (i + 1 < l) result += b64chars[((b & 15) << 2) | (c >> 6)]; else result += "=";
                if (i + 2 < l) result += b64chars[c & 63]; else result += "=";
            }
            return result;
        },
        getTopCaller: function () {
            if (!Java.available) return "Unknown";
            try {
                var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                for (var i = 3; i < stackTrace.length; i++) {
                    var cn = stackTrace[i].getClassName();
                    if (!cn.startsWith("java.") && !cn.startsWith("android.") &&
                        !cn.startsWith("dalvik.") && !cn.startsWith("com.android.")) {
                        return cn + "." + stackTrace[i].getMethodName();
                    }
                }
            } catch (e) {}
            return "Unknown";
        },
        getStackTraceString: function (maxLen) {
            if (!Java.available) return "Unknown";
            maxLen = maxLen || 4000;
            try {
                var Exception = Java.use("java.lang.Exception");
                var Log = Java.use("android.util.Log");
                var st = Log.getStackTraceString(Exception.$new());
                return st && st.length > maxLen ? st.substring(0, maxLen) + "..." : (st || "Unknown");
            } catch (e) { return "Unknown"; }
        },
        shouldSendFullStack: function (key, windowMs) {
            windowMs = windowMs || 1500;
            if (!global._stackSeen) global._stackSeen = {};
            var now = Date.now();
            if (now - (global._stackSeen[key] || 0) < windowMs) return false;
            global._stackSeen[key] = now;
            return true;
        }
    };

    // =========================================================
    // 3. 业务监控
    // =========================================================
    function start_business_logic() {
        if (global._business_v10) return;
        global._business_v10 = true;
        console.log("[*] Starting business monitoring...");

        Java.perform(function () {
            try {
                var ArrayList = Java.use("java.util.ArrayList");
                var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                TrustManagerImpl.checkServerTrusted
                    .overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String")
                    .implementation = function (a, b, c) { return ArrayList.$new(); };
            } catch (e) {}

            try {
                var InetSocketAddress = Java.use("java.net.InetSocketAddress");
                var ProxyClass = Java.use("java.net.Proxy");
                var ProxyType = Java.use("java.net.Proxy$Type");
                var myProxy = ProxyClass.$new(ProxyType.valueOf("HTTP"), InetSocketAddress.$new("127.0.0.1", 8080));
                var URL = Java.use("java.net.URL");
                URL.openConnection.overload().implementation = function () { return this.openConnection(myProxy); };
                URL.openConnection.overload("java.net.Proxy").implementation = function (p) { return this.openConnection(myProxy); };
            } catch (e) {}
        });

        console.log("[+] Business monitoring ready");
    }

    setTimeout(start_business_logic, 5000);

    // =========================================================
    // 4. RPC
    // =========================================================
    rpc.exports = {
        apimonitor: function (api_to_monitor) {
            console.log("[*] RPC apimonitor called");
            var api_list = Array.isArray(api_to_monitor) ? api_to_monitor : [api_to_monitor];

            setTimeout(function () {
                Java.perform(function () {
                    var tid = gettid();
                    importantThreads[tid] = "apimonitor";

                    api_list.forEach(function (category_obj) {
                        var category = category_obj["Category"];
                        var hooks = category_obj["hooks"];
                        if (!hooks) return;

                        hooks.forEach(function (hook) {
                            try {
                                var targetClass = Java.use(hook.clazz);
                                var methodName = hook.method;
                                if (!targetClass[methodName]) return;

                                targetClass[methodName].overloads.forEach(function (overload) {
                                    overload.implementation = function () {
                                        var currentTid = gettid();
                                        if (!importantThreads[currentTid]) {
                                            importantThreads[currentTid] = "hook_exec";
                                        }

                                        var args = Array.prototype.slice.call(arguments);
                                        var retval = overload.apply(this, arguments);

                                        var top = Utils.getTopCaller();
                                        var stackKey = category + "|" + hook.clazz + "|" + methodName + "|" + top;
                                        var fullStack = Utils.shouldSendFullStack(stackKey, 1500)
                                            ? Utils.getStackTraceString(4000) : "Deduped";

                                        send({
                                            ts: Utils.getTS(),
                                            category: category,
                                            "class": hook.clazz,
                                            method: methodName,
                                            args: args.map(function (a) { return String(a); }),
                                            returnValue: Utils.processReturnValue(retval),
                                            calledFrom: top,
                                            stack: fullStack
                                        });

                                        return retval;
                                    };
                                });
                            } catch (err) {}
                        });
                    });
                    console.log("[+] API hooks deployed");
                });
            }, 2000);

            return "Deployed.";
        },

        ping: function() { return "pong"; },

        addImportantThread: function(tid, name) {
            importantThreads[tid] = name || "manual";
            return "Added";
        },

        getImportantThreads: function() {
            return JSON.stringify(importantThreads);
        }
    };

    console.log("[*] Frida V10 loaded!");
})();
