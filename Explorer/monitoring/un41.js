(function () {
    console.log("[*] Mode: Stable Monitoring Build + Verbose Failure Diagnostics");

    var Files = new Map();

    // =========================================================
    // 0. 通用诊断发送
    // =========================================================
    function reportDiag(type, data) {
        try {
            send({
                diag: Object.assign({
                    type: type,
                    ts: Utils ? Utils.getTS() : (new Date().toISOString())
                }, data || {})
            });
        } catch (e) {
            try {
                send({
                    diag: {
                        type: "diag_send_error",
                        error: String(e),
                        rawType: type
                    }
                });
            } catch (_) {}
        }
    }

    function reportHookError(stage, data) {
        try {
            send({
                hookerror: Object.assign({
                    stage: stage,
                    ts: Utils ? Utils.getTS() : (new Date().toISOString())
                }, data || {})
            });
        } catch (e) {
            try {
                send({
                    diag: {
                        type: "hookerror_send_error",
                        error: String(e),
                        stage: stage
                    }
                });
            } catch (_) {}
        }
    }

    function getNativeBacktrace(context) {
        try {
            return Thread.backtrace(context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .map(function (s) { return s.toString(); })
                .join("\n");
        } catch (e) {
            return "Backtrace unavailable: " + String(e);
        }
    }

    // =========================================================
    // 1. 工具类
    // =========================================================
    var Utils = {
        processReturnValue: function (retval) {
            try {
                return (retval === null || retval === undefined) ? "null" : retval.toString();
            } catch (e) {
                return "[Object]";
            }
        },

        getTS: function () {
            var d = new Date();
            var pad = function (n) { return n < 10 ? "0" + n : n; };
            return d.getFullYear().toString() +
                pad(d.getMonth() + 1) +
                pad(d.getDate()) +
                pad(d.getHours()) +
                pad(d.getMinutes()) +
                pad(d.getSeconds());
        },

        b64: function (arrayBuffer) {
            var uint8 = new Uint8Array(arrayBuffer);
            var b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var l = uint8.length, result = "";
            for (var i = 0; i < l; i += 3) {
                var a = uint8[i], b = uint8[i + 1], c = uint8[i + 2];
                result += b64chars[a >> 2];
                result += b64chars[((a & 3) << 4) | ((b || 0) >> 4)];
                if (i + 1 < l) result += b64chars[((b & 15) << 2) | ((c || 0) >> 6)];
                else result += "=";
                if (i + 2 < l) result += b64chars[c & 63];
                else result += "=";
            }
            return result;
        },

        getTopCaller: function () {
            if (!Java.available) return "Unknown";
            try {
                var ThreadCls = Java.use("java.lang.Thread");
                var stackTrace = ThreadCls.currentThread().getStackTrace();
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

        getStackTraceString: function (maxLen) {
            if (!Java.available) return "Unknown";
            maxLen = maxLen || 2000;
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

        shouldSendFullStack: function (key, windowMs) {
            windowMs = windowMs || 3000;
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
        },

        shouldSample: function (key, mod) {
            try {
                if (!this._sampleCount) this._sampleCount = {};
                if (!this._sampleCount[key]) this._sampleCount[key] = 0;
                this._sampleCount[key]++;
                return (this._sampleCount[key] % mod) === 1;
            } catch (e) {
                return true;
            }
        },

        safeToString: function (v) {
            try {
                if (v === null || v === undefined) return "null";
                return String(v);
            } catch (e) {
                return "[Unstringifiable]";
            }
        }
    };

    // =========================================================
    // 2. 轻量环境诊断（不阻断、不保活，只记录）
    // =========================================================
    function light_diagnostics() {
        var libc = "libc.so";

        function safeReadUtf8(p) {
            if (!p || p.isNull()) return null;
            try {
                return p.readUtf8String();
            } catch (e) {
                return null;
            }
        }

        // --- A. kill ---
        try {
            var killPtr = Module.findExportByName(libc, "kill");
            if (killPtr) {
                Interceptor.attach(killPtr, {
                    onEnter: function (args) {
                        try {
                            this._bt = getNativeBacktrace(this.context);
                            var pid = args[0].toInt32();
                            var sig = args[1].toInt32();
                            reportDiag("kill", {
                                pid: pid,
                                sig: sig,
                                backtrace: this._bt
                            });
                        } catch (e) {
                            reportHookError("light_diagnostics.kill.onEnter", { error: String(e) });
                        }
                    }
                });
            } else {
                reportHookError("light_diagnostics.kill", { error: "kill export not found" });
            }
        } catch (e) {
            reportHookError("light_diagnostics.kill.attach", { error: String(e) });
        }

        // --- B. exit / _exit / abort ---
        ["exit", "_exit", "abort"].forEach(function (name) {
            try {
                var p = Module.findExportByName(libc, name);
                if (!p) {
                    reportHookError("light_diagnostics." + name, { error: "export not found" });
                    return;
                }

                Interceptor.attach(p, {
                    onEnter: function (args) {
                        try {
                            var code = null;
                            if (name === "exit" || name === "_exit") {
                                code = args[0].toInt32();
                            }
                            reportDiag(name, {
                                code: code,
                                backtrace: getNativeBacktrace(this.context)
                            });
                        } catch (e) {
                            reportHookError("light_diagnostics." + name + ".onEnter", { error: String(e) });
                        }
                    }
                });
            } catch (e) {
                reportHookError("light_diagnostics." + name + ".attach", { error: String(e) });
            }
        });

        // --- C. access ---
        try {
            var accessPtr = Module.findExportByName(libc, "access");
            if (accessPtr) {
                Interceptor.attach(accessPtr, {
                    onEnter: function (args) {
                        this.fake = false;
                        this.path = null;
                        try {
                            var path = safeReadUtf8(args[0]);
                            this.path = path;
                            if (path && (path.indexOf("frida") > -1 || path.indexOf("magisk") > -1)) {
                                this.fake = true;
                            }
                        } catch (e) {
                            reportHookError("light_diagnostics.access.onEnter", { error: String(e) });
                        }
                    },
                    onLeave: function (retval) {
                        try {
                            if (this.fake) {
                                reportDiag("access_filtered", {
                                    path: this.path,
                                    originalRet: retval.toInt32()
                                });
                                retval.replace(ptr(-1));
                            }
                        } catch (e) {
                            reportHookError("light_diagnostics.access.onLeave", { error: String(e) });
                        }
                    }
                });
            } else {
                reportHookError("light_diagnostics.access", { error: "access export not found" });
            }
        } catch (e) {
            reportHookError("light_diagnostics.access.attach", { error: String(e) });
        }

        // --- D. Java exit/halt ---
        if (Java.available) {
            Java.perform(function () {
                try {
                    var System = Java.use("java.lang.System");
                    var System_exit = System.exit.overload("int");
                    System_exit.implementation = function (code) {
                        reportDiag("System.exit", {
                            code: code,
                            stack: Utils.getStackTraceString(4000)
                        });
                        return System_exit.call(this, code);
                    };
                } catch (e) {
                    reportHookError("light_diagnostics.System.exit", { error: String(e) });
                }

                try {
                    var Runtime = Java.use("java.lang.Runtime");
                    var Runtime_halt = Runtime.halt.overload("int");
                    Runtime_halt.implementation = function (code) {
                        reportDiag("Runtime.halt", {
                            code: code,
                            stack: Utils.getStackTraceString(4000)
                        });
                        return Runtime_halt.call(this, code);
                    };
                } catch (e) {
                    reportHookError("light_diagnostics.Runtime.halt", { error: String(e) });
                }
            });
        } else {
            reportHookError("light_diagnostics.Java", { error: "Java not available" });
        }
    }

    light_diagnostics();

    // =========================================================
    // 3. 业务监控逻辑
    // =========================================================
    function start_business_logic() {
        console.log("[*] 部署业务逻辑监控...");
        reportDiag("business_logic_start", {});

        // -------------------------
        // 3.1 可选网络改写（保留原功能，但显式上报失败）
        // -------------------------
        try {
            Java.perform(function () {
                try {
                    var ArrayList = Java.use("java.util.ArrayList");
                    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                    if (TrustManagerImpl.checkServerTrusted) {
                        var tmOv = TrustManagerImpl.checkServerTrusted
                            .overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String");

                        tmOv.implementation = function (a, b, c) {
                            try {
                                reportDiag("TrustManagerImpl.checkServerTrusted.bypassed", {
                                    authType: Utils.safeToString(b),
                                    host: Utils.safeToString(c)
                                });
                            } catch (e) {}
                            return ArrayList.$new();
                        };

                        reportDiag("hook_installed", {
                            target: "com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted"
                        });
                    } else {
                        reportHookError("business_logic.trustmanager", {
                            error: "checkServerTrusted not found"
                        });
                    }
                } catch (e) {
                    reportHookError("business_logic.trustmanager", { error: String(e) });
                }

                try {
                    var InetSocketAddress = Java.use("java.net.InetSocketAddress");
                    var ProxyClass = Java.use("java.net.Proxy");
                    var ProxyType = Java.use("java.net.Proxy$Type");
                    var URL = Java.use("java.net.URL");

                    var myProxy = ProxyClass.$new(
                        ProxyType.valueOf("HTTP"),
                        InetSocketAddress.$new("127.0.0.1", 8080)
                    );

                    var openConnectionNoArg = URL.openConnection.overload();
                    openConnectionNoArg.implementation = function () {
                        try {
                            reportDiag("URL.openConnection.redirect", {
                                overload: "noargs",
                                stack: Utils.shouldSendFullStack("url_noargs", 5000) ? Utils.getStackTraceString(2000) : "Deduped"
                            });
                            return this.openConnection(myProxy);
                        } catch (e) {
                            reportHookError("business_logic.URL.openConnection.noargs.call", { error: String(e) });
                            return openConnectionNoArg.call(this);
                        }
                    };

                    var openConnectionWithProxy = URL.openConnection.overload("java.net.Proxy");
                    openConnectionWithProxy.implementation = function (p) {
                        try {
                            reportDiag("URL.openConnection.redirect", {
                                overload: "proxy",
                                stack: Utils.shouldSendFullStack("url_proxy", 5000) ? Utils.getStackTraceString(2000) : "Deduped"
                            });
                            return openConnectionWithProxy.call(this, myProxy);
                        } catch (e) {
                            reportHookError("business_logic.URL.openConnection.proxy.call", { error: String(e) });
                            return openConnectionWithProxy.call(this, p);
                        }
                    };

                    reportDiag("hook_installed", {
                        target: "java.net.URL.openConnection"
                    });
                } catch (e) {
                    reportHookError("business_logic.URL.openConnection", { error: String(e) });
                }
            });
        } catch (e) {
            reportHookError("business_logic.network.Java.perform", { error: String(e) });
        }

        // -------------------------
        // 3.2 文件系统监控
        // -------------------------
        function hookFileAPI(name) {
            try {
                var p = Module.findExportByName("libc.so", name);
                if (!p) {
                    reportHookError("fs." + name, { error: "export not found" });
                    return;
                }

                Interceptor.attach(p, {
                    onEnter: function (args) {
                        this.path = null;
                        try {
                            var pathPtr = (name === "open") ? args[0] : (name === "openat" ? args[1] : args[0]);
                            if (pathPtr && !pathPtr.isNull()) {
                                this.path = pathPtr.readUtf8String();
                            }
                        } catch (e) {
                            reportHookError("fs." + name + ".onEnter", { error: String(e) });
                        }
                    },
                    onLeave: function (retval) {
                        try {
                            var fd = retval.toInt32();
                            if (fd > 0 && this.path &&
                                (this.path.indexOf("/storage") > -1 || this.path.indexOf("/sdcard") > -1)) {
                                Files.set(fd, this.path);
                                send({
                                    fs: {
                                        function: name,
                                        fd: fd,
                                        path: this.path,
                                        ts: Utils.getTS()
                                    }
                                });
                            }
                        } catch (e) {
                            reportHookError("fs." + name + ".onLeave", { error: String(e) });
                        }
                    }
                });

                reportDiag("hook_installed", { target: "libc." + name });
            } catch (e) {
                reportHookError("fs." + name + ".attach", { error: String(e) });
            }
        }

        hookFileAPI("open");
        hookFileAPI("openat");

        try {
            var closePtr = Module.findExportByName("libc.so", "close");
            if (closePtr) {
                Interceptor.attach(closePtr, {
                    onEnter: function (args) {
                        try {
                            this.fd = args[0].toInt32();
                        } catch (e) {
                            this.fd = -1;
                            reportHookError("fs.close.onEnter", { error: String(e) });
                        }
                    },
                    onLeave: function (retval) {
                        try {
                            if (this.fd >= 0 && Files.has(this.fd)) {
                                Files.delete(this.fd);
                            }
                        } catch (e) {
                            reportHookError("fs.close.onLeave", { error: String(e) });
                        }
                    }
                });
                reportDiag("hook_installed", { target: "libc.close" });
            } else {
                reportHookError("fs.close", { error: "export not found" });
            }
        } catch (e) {
            reportHookError("fs.close.attach", { error: String(e) });
        }

        try {
            var writePtr = Module.findExportByName("libc.so", "write");
            if (writePtr) {
                Interceptor.attach(writePtr, {
                    onEnter: function (args) {
                        try {
                            this.fd = args[0].toInt32();
                            this.buf = args[1];
                            this.reqLen = args[2].toInt32();
                        } catch (e) {
                            this.fd = -1;
                            this.buf = null;
                            this.reqLen = 0;
                            reportHookError("fs.write.onEnter", { error: String(e) });
                        }
                    },
                    onLeave: function (retval) {
                        try {
                            var len = retval.toInt32();
                            if (len > 0 && Files.has(this.fd)) {
                                var path = Files.get(this.fd);
                                var key = "write|" + path;
                                if (Utils.shouldSample(key, 10)) {
                                    send({
                                        fs: {
                                            function: "write",
                                            fd: this.fd,
                                            path: path,
                                            len: len,
                                            ts: Utils.getTS()
                                        }
                                    });
                                }
                            }
                        } catch (e) {
                            reportHookError("fs.write.onLeave", { error: String(e) });
                        }
                    }
                });
                reportDiag("hook_installed", { target: "libc.write" });
            } else {
                reportHookError("fs.write", { error: "export not found" });
            }
        } catch (e) {
            reportHookError("fs.write.attach", { error: String(e) });
        }

        // -------------------------
        // 3.3 媒体监控
        // -------------------------
        try {
            Java.perform(function () {
                var Log = Java.use("android.util.Log");
                var Exception = Java.use("java.lang.Exception");

                function sendMediaEvent(clazz, method, argsArr) {
                    var payload = {
                        media: {
                            ts: Utils.getTS(),
                            "class": clazz,
                            "method": method,
                            "args": (argsArr || []).map(function (a) { return Utils.safeToString(a); })
                        }
                    };

                    try {
                        payload.media.stack = Log.getStackTraceString(Exception.$new());
                    } catch (e) {
                        reportHookError("media.stack", { error: String(e), clazz: clazz, method: method });
                    }

                    send(payload);
                }

                try {
                    var Camera = Java.use("android.hardware.Camera");
                    if (Camera && Camera.open) {
                        Camera.open.overloads.forEach(function (ov, idx) {
                            try {
                                ov.implementation = function () {
                                    var args = Array.prototype.slice.call(arguments);
                                    sendMediaEvent("android.hardware.Camera", "open", args);
                                    return ov.apply(this, arguments);
                                };
                            } catch (e) {
                                reportHookError("media.Camera.open.overload", {
                                    overloadIndex: idx,
                                    error: String(e)
                                });
                            }
                        });
                        reportDiag("hook_installed", { target: "android.hardware.Camera.open" });
                    } else {
                        reportHookError("media.Camera.open", { error: "method not found" });
                    }
                } catch (e) {
                    reportHookError("media.Camera", { error: String(e) });
                }

                try {
                    var AudioRecord = Java.use("android.media.AudioRecord");
                    if (AudioRecord && AudioRecord.startRecording) {
                        AudioRecord.startRecording.overloads.forEach(function (ov, idx) {
                            try {
                                ov.implementation = function () {
                                    sendMediaEvent("android.media.AudioRecord", "startRecording", []);
                                    return ov.apply(this, arguments);
                                };
                            } catch (e) {
                                reportHookError("media.AudioRecord.startRecording.overload", {
                                    overloadIndex: idx,
                                    error: String(e)
                                });
                            }
                        });
                        reportDiag("hook_installed", { target: "android.media.AudioRecord.startRecording" });
                    } else {
                        reportHookError("media.AudioRecord.startRecording", { error: "method not found" });
                    }
                } catch (e) {
                    reportHookError("media.AudioRecord", { error: String(e) });
                }

                console.log("[+] Media hooks installed (Camera/AudioRecord).");
            });
        } catch (e) {
            console.log("[-] Media Hook Err (non-fatal): " + e);
            reportHookError("media.Java.perform", { error: String(e) });
        }

        console.log("[*] 业务监控全面就绪。");
        reportDiag("business_logic_ready", {});
    }

    setTimeout(function () {
        try {
            start_business_logic();
        } catch (e) {
            reportHookError("start_business_logic.fatal", {
                error: String(e),
                stack: String(e && e.stack ? e.stack : "no-js-stack")
            });
        }
    }, 3000);

    // =========================================================
    // 4. RPC 监控
    // =========================================================
    rpc.exports = {
        apimonitor: function (api_to_monitor) {
            var api_list = Array.isArray(api_to_monitor) ? api_to_monitor : [api_to_monitor];

            setTimeout(function () {
                try {
                    Java.perform(function () {
                        var stat = {
                            requestedCategories: 0,
                            requestedMethods: 0,
                            hookedMethods: 0,
                            hookedOverloads: 0,
                            failedCount: 0,
                            failed: []
                        };

                        api_list.forEach(function (category_obj, categoryIndex) {
                            try {
                                stat.requestedCategories += 1;

                                if (!category_obj) {
                                    stat.failedCount += 1;
                                    stat.failed.push({
                                        stage: "category_parse",
                                        categoryIndex: categoryIndex,
                                        reason: "category_obj is null/undefined"
                                    });
                                    return;
                                }

                                var category = category_obj["Category"];
                                var hooks = category_obj["hooks"];

                                if (!hooks || !Array.isArray(hooks)) {
                                    stat.failedCount += 1;
                                    stat.failed.push({
                                        stage: "category_parse",
                                        category: category,
                                        reason: "hooks missing or not array"
                                    });
                                    return;
                                }

                                hooks.forEach(function (hook, hookIndex) {
                                    stat.requestedMethods += 1;

                                    try {
                                        if (!hook || !hook.clazz || !hook.method) {
                                            stat.failedCount += 1;
                                            stat.failed.push({
                                                stage: "hook_parse",
                                                category: category,
                                                hookIndex: hookIndex,
                                                hook: hook,
                                                reason: "invalid hook item"
                                            });
                                            return;
                                        }

                                        var targetClass;
                                        try {
                                            targetClass = Java.use(hook.clazz);
                                        } catch (classErr) {
                                            stat.failedCount += 1;
                                            stat.failed.push({
                                                stage: "Java.use",
                                                category: category,
                                                clazz: hook.clazz,
                                                method: hook.method,
                                                reason: String(classErr)
                                            });
                                            return;
                                        }

                                        var methodName = hook.method;

                                        if (!targetClass[methodName]) {
                                            stat.failedCount += 1;
                                            stat.failed.push({
                                                stage: "method_lookup",
                                                category: category,
                                                clazz: hook.clazz,
                                                method: methodName,
                                                reason: "method not found on targetClass"
                                            });
                                            return;
                                        }

                                        var overloads;
                                        try {
                                            overloads = targetClass[methodName].overloads;
                                        } catch (ovErr) {
                                            stat.failedCount += 1;
                                            stat.failed.push({
                                                stage: "overloads_access",
                                                category: category,
                                                clazz: hook.clazz,
                                                method: methodName,
                                                reason: String(ovErr)
                                            });
                                            return;
                                        }

                                        if (!overloads || overloads.length === 0) {
                                            stat.failedCount += 1;
                                            stat.failed.push({
                                                stage: "overloads_empty",
                                                category: category,
                                                clazz: hook.clazz,
                                                method: methodName,
                                                reason: "no overloads"
                                            });
                                            return;
                                        }

                                        stat.hookedMethods += 1;

                                        overloads.forEach(function (overload, ovIndex) {
                                            try {
                                                var sig = "unknown";
                                                try {
                                                    sig = overload.argumentTypes.map(function (t) {
                                                        return t.className;
                                                    }).join(", ");
                                                } catch (e) {}

                                                overload.implementation = function () {
                                                    try {
                                                        var args = Array.prototype.slice.call(arguments);
                                                        var retval = overload.apply(this, arguments);

                                                        var key = category + "|" + hook.clazz + "|" + methodName;
                                                        var payload = {
                                                            ts: Utils.getTS(),
                                                            category: category,
                                                            "class": hook.clazz,
                                                            method: methodName,
                                                            overloadSignature: sig,
                                                            args: args.map(function (a) { return Utils.safeToString(a); }),
                                                            returnValue: Utils.processReturnValue(retval),
                                                            calledFrom: "Unknown",
                                                            stack: "Deduped"
                                                        };

                                                        if (Utils.shouldSample(key + "|caller", 5)) {
                                                            payload.calledFrom = Utils.getTopCaller();
                                                        }

                                                        if (Utils.shouldSendFullStack(key, 3000)) {
                                                            payload.stack = Utils.getStackTraceString(2000);
                                                        }

                                                        send(payload);
                                                        return retval;
                                                    } catch (invokeErr) {
                                                        reportHookError("apimonitor.invoke", {
                                                            category: category,
                                                            clazz: hook.clazz,
                                                            method: methodName,
                                                            overloadIndex: ovIndex,
                                                            error: String(invokeErr)
                                                        });
                                                        throw invokeErr;
                                                    }
                                                };

                                                stat.hookedOverloads += 1;
                                            } catch (implErr) {
                                                stat.failedCount += 1;
                                                stat.failed.push({
                                                    stage: "set_implementation",
                                                    category: category,
                                                    clazz: hook.clazz,
                                                    method: methodName,
                                                    overloadIndex: ovIndex,
                                                    reason: String(implErr)
                                                });
                                            }
                                        });
                                    } catch (err) {
                                        stat.failedCount += 1;
                                        stat.failed.push({
                                            stage: "hook_outer",
                                            category: category,
                                            clazz: hook ? hook.clazz : "unknown",
                                            method: hook ? hook.method : "unknown",
                                            reason: String(err)
                                        });
                                    }
                                });
                            } catch (catErr) {
                                stat.failedCount += 1;
                                stat.failed.push({
                                    stage: "category_outer",
                                    categoryIndex: categoryIndex,
                                    reason: String(catErr)
                                });
                            }
                        });

                        send({
                            hookstat: {
                                ts: Utils.getTS(),
                                requestedCategories: stat.requestedCategories,
                                requestedMethods: stat.requestedMethods,
                                hookedMethods: stat.hookedMethods,
                                hookedOverloads: stat.hookedOverloads,
                                failedCount: stat.failedCount,
                                failed: stat.failed.slice(0, 300)
                            }
                        });
                    });
                } catch (e) {
                    reportHookError("apimonitor.Java.perform.fatal", {
                        error: String(e),
                        stack: String(e && e.stack ? e.stack : "no-js-stack")
                    });
                }
            }, 3000);

            return "Deployed.";
        }
    };

    reportDiag("script_loaded", {});
    console.log("[*] Start Monitoring after login-state load end!");
})();