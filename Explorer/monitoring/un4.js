(function () {
    console.log("[*] Mode: Port-Forwarding (adb reverse) Traffic Capture & Deep Anti-Detection (V5)");

    var Files = new Map();

    // =========================================================
    // 1. 深度环境伪装 (强制拦截自杀指令)
    // =========================================================
    function deep_stealth() {
        var libc = "libc.so";
        // --- A. 彻底屏蔽 ptrace ---
        var ptracePtr = Module.findExportByName(libc, "ptrace");
        if (ptracePtr) {
            Interceptor.replace(ptracePtr, new NativeCallback(function () {
                return 0;
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
        }
        // --- B. 拦截 kill (优化：防止 CPU 100%) ---
        var killPtr = Module.findExportByName(libc, "kill");
        if (killPtr) {
            var nativeKill = new NativeFunction(killPtr, 'int', ['int', 'int']);
            Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
                if (sig === 9 || sig === 6 || sig === 15) {
                    console.log("[!] 拦截到自杀信号: kill(" + pid + ", " + sig + ") - 已静默处理");
                    // 稍微睡眠一小会儿，防止 App 立即触发下一次尝试导致卡死
                    Thread.sleep(0.1);
                    return 0;
                }
                return nativeKill(pid, sig);
            }, 'int', ['int', 'int']));
        }
        // --- C. 拦截退出 (exit, _exit, abort) ---
        var exitSymbols = ["exit", "_exit", "abort", "__stack_chk_fail"];
        exitSymbols.forEach(function (name) {
            var ptr = Module.findExportByName(libc, name);
            if (ptr) {
                Interceptor.replace(ptr, new NativeCallback(function () {
                    console.log("[!] 拦截到 Native 退出请求: " + name + " (已挂起该请求)");
                    // 让请求退出的线程进入无限睡眠，而不是返回，防止它反复调用
                    while (true) { Thread.sleep(1); }
                }, 'void', ['int']));
            }
        });
        function safeReadUtf8(ptr) {
            if (ptr.isNull()) return null;
            try {
                // 不指定长度！让 Frida 自动读到 \0 为止
                return ptr.readUtf8String();
            } catch (e) {
                // 可选：降级尝试读原始字节（调试用）
                // console.warn("Fallback to readByteArray at " + ptr);
                return null;
            }
        }
        // --- D. 绕过文件检测 (access, stat) ---
        // 很多 App 会检查 /data/local/tmp/re.frida.server
        var accessPtr = Module.findExportByName(libc, "access");
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function (args) {
                    var path = safeReadUtf8(args[0]);
                    this.fake = false;
                    if (path && (path.indexOf("frida") > -1 || path.indexOf("magisk") > -1)) {
                        this.fake = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.fake) retval.replace(ptr(-1)); // 假装文件不存在
                }
            });
        }
        // --- E. 字符串搜索过滤 (strstr, strcmp) ---
        var strstrPtr = Module.findExportByName(libc, 'strstr');
        if (strstrPtr) {
            Interceptor.attach(strstrPtr, {
                onEnter: function (args) {
                    try { this.needle = args[1].readUtf8String(); } catch (e) { this.needle = null; }
                },
                onLeave: function (retval) {
                    if (this.needle && (this.needle.indexOf("frida") > -1 || this.needle.indexOf("gum-js") > -1)) {
                        retval.replace(ptr(0));
                    }
                }
            });
        }
        // --- F. Java 层退出拦截 ---
         Java.perform(function() {
            // 拦截 System.exit
            try {
                var System = Java.use("java.lang.System");
                System.exit.implementation = function(code) {
                    console.log("[!] 拦截到 Java System.exit(" + code + ")");
                };
            } catch (e) {}
            // 拦截 Runtime.halt (比 exit 更底层)
            try {
                var Runtime = Java.use("java.lang.Runtime");
                Runtime.halt.implementation = function(code) {
                    console.log("[!] 拦截到 Java Runtime.halt(" + code + ")");
                };
            } catch (e) {}
        });
    }

    deep_stealth();

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

        // 轻量 top caller（给 calledFrom 用）
        getTopCaller: function () {
            if (!Java.available) return "Unknown";
            try {
                var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                for (var i = 3; i < stackTrace.length; i++) {
                    var cn = stackTrace[i].getClassName();
                    if (!cn.startsWith("java.") &&
                        !cn.startsWith("android.") &&
                        !cn.startsWith("dalvik.") &&
                        !cn.startsWith("com.android.") &&
                        !cn.startsWith("sun.") &&
                        !cn.startsWith("frida.")) {
                        return cn + "." + stackTrace[i].getMethodName();
                    }
                }
            } catch (e) {}
            return "Unknown";
        },

        // 完整 Java 栈字符串（截断避免超大 payload）
        getStackTraceString: function (maxLen) {
            if (!Java.available) return "Unknown";
            maxLen = maxLen || 4000;
            try {
                var Exception = Java.use("java.lang.Exception");
                var Log = Java.use("android.util.Log");
                var st = Log.getStackTraceString(Exception.$new());
                if (!st) return "Unknown";
                if (st.length > maxLen) return st.substring(0, maxLen) + "...(truncated)";
                return st;
            } catch (e) {
                return "Unknown";
            }
        },

        // 去重：同一个调用点短时间内只发一次完整栈，其余发 Deduped
        shouldSendFullStack: function (key, windowMs) {
            windowMs = windowMs || 1500;
            try {
                if (!this._stackSeen) this._stackSeen = {};
                var now = Date.now();
                var last = this._stackSeen[key] || 0;
                if (now - last < windowMs) return false;
                this._stackSeen[key] = now;
                return true;
            } catch (e) {
                return true;
            }
        }
    };

    // =========================================================
    // 3. 业务监控逻辑 (延迟 5 秒执行)
    // =========================================================
    function start_business_logic() {
        console.log("[*] 延迟时间到，部署业务逻辑监控...");
        Java.perform(function () {
            try {
                var ArrayList = Java.use("java.util.ArrayList");
                var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                TrustManagerImpl.checkServerTrusted
                    .overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String")
                    .implementation = function (a, b, c) {
                        return ArrayList.$new();
                    };
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

        function hookFileAPI(name) {
            var ptr = Module.findExportByName("libc.so", name);
            if (!ptr) return;
            Interceptor.attach(ptr, {
                onEnter: function (args) {
                    var pathPtr = (name === "open") ? args[0] : (name === "openat" ? args[1] : args[0]);
                    try { this.path = pathPtr.readUtf8String(); } catch (e) { this.path = null; }
                },
                onLeave: function (retval) {
                    var fd = retval.toInt32();
                    if (fd > 0 && this.path && (this.path.indexOf("/storage") > -1 || this.path.indexOf("/sdcard") > -1)) {
                        Files.set(fd, this.path);
                        send(JSON.stringify({ "fs": { "function": name, "fd": fd, "path": this.path, "ts": Utils.getTS() } }));
                    }
                }
            });
        }

        hookFileAPI("open");
        hookFileAPI("openat");

        var writePtr = Module.findExportByName("libc.so", "write");
        if (writePtr) {
            Interceptor.attach(writePtr, {
                onEnter: function (args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
                onLeave: function (retval) {
                    var len = retval.toInt32();
                    if (len > 0 && Files.has(this.fd)) {
                        var data = Memory.readByteArray(this.buf, Math.min(len, 8192));
                        send(JSON.stringify({ "fs": { "function": "write", "fd": this.fd, "path": Files.get(this.fd), "data": Utils.b64(data), "ts": Utils.getTS() } }));
                    }
                }
            });
        }

        // 媒体监控
        try {
            var Log = Java.use("android.util.Log");
            var Exception = Java.use("java.lang.Exception");
            function sendMediaEvent(clazz, method, argsArr) {
                send({
                    "media": {
                        "ts": Utils.getTS(),
                        "class": clazz,
                        "method": method,
                        "args": (argsArr || []).map(function (a) { return String(a); }),
                        "stack": Log.getStackTraceString(Exception.$new())
                    }
                });
            }

            try {
                var Camera = Java.use("android.hardware.Camera");
                if (Camera && Camera.open) {
                    Camera.open.overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            sendMediaEvent("android.hardware.Camera", "open", args);
                            return ov.apply(this, arguments);
                        };
                    });
                }
            } catch (e) {}

            try {
                var AudioRecord = Java.use("android.media.AudioRecord");
                if (AudioRecord && AudioRecord.startRecording) {
                    AudioRecord.startRecording.overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            sendMediaEvent("android.media.AudioRecord", "startRecording", []);
                            return ov.apply(this, arguments);
                        };
                    });
                }
            } catch (e) {}

            console.log("[+] Media hooks installed (Camera/AudioRecord).");
        } catch (e) {
            console.log("[-] Media Hook Err (non-fatal): " + e);
        }

        console.log("[*] 业务监控全面就绪。");
    }

    setTimeout(start_business_logic, 3000);

    // =========================================================
    // 4. RPC 监控
    // =========================================================
    rpc.exports = {
        apimonitor: function (api_to_monitor) {
            var api_list = Array.isArray(api_to_monitor) ? api_to_monitor : [api_to_monitor];

            setTimeout(function () {
                Java.perform(function () {
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
                                        var args = Array.prototype.slice.call(arguments);

                                        // 用 overload.apply 调原实现，避免 this[method].apply 导致递归
                                        var retval = overload.apply(this, arguments);

                                        var top = Utils.getTopCaller();
                                        var stackKey = category + "|" + hook.clazz + "|" + methodName + "|" + top;
                                        var fullStack = Utils.shouldSendFullStack(stackKey, 1500)
                                            ? Utils.getStackTraceString(4000)
                                            : "Deduped";

                                        send({
                                            ts: Utils.getTS(),
                                            category: category,
                                            "class": hook.clazz,
                                            method: methodName,
                                            args: args.map(function (a) { return String(a); }),
                                            returnValue: Utils.processReturnValue(retval),

                                            // 每次都有轻量 caller
                                            calledFrom: top,

                                            // 每个调用点首次/间隔窗口发一次完整栈（稳定）
                                            stack: fullStack
                                        });

                                        return retval;
                                    };
                                });
                            } catch (err) {
                                // 保持静默，避免影响稳定性
                            }
                        });
                    });
                });
            }, 3000);

            return "Deployed.";
        }
    };

    console.log("[*] Start Moninting with login state load end!");
})();