(function () {
    console.log("[*] Mode: Port-Forwarding (adb reverse) Traffic Capture & Privacy Monitoring");

    var Files = new Map();

    // =========================================================
    // 1. 立即执行：深度反检测层 (防止闪退)
    // =========================================================
    function stealth_init() {
        console.log("[*] 正在部署深度反检测层...");

        // A. 隐藏 TracerPid 和 状态伪装
        var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
        if (fgetsPtr) {
            Interceptor.attach(fgetsPtr, {
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    try {
                        var bufstr = retval.readUtf8String();
                        if (bufstr && (bufstr.indexOf('TracerPid:') > -1 || bufstr.indexOf('State:') > -1)) {
                            retval.writeUtf8String("TracerPid:\t0\nState:\tS (sleeping)");
                        }
                    } catch (e) {}
                }
            });
        }

        // B. 隐藏内存中的 Frida 特征 (strstr 过滤)
        var strstrPtr = Module.findExportByName('libc.so', 'strstr');
        if (strstrPtr) {
            Interceptor.attach(strstrPtr, {
                onEnter: function (args) {
                    try {
                        this.needle = args[1].readUtf8String();
                    } catch (e) { this.needle = null; }
                },
                onLeave: function (retval) {
                    if (this.needle && (this.needle.indexOf("frida") > -1 || this.needle.indexOf("gum-js") > -1)) {
                        retval.replace(ptr(0));
                    }
                }
            });
        }

        // C. 防止 App 调用 Java 层退出
        Java.perform(function() {
            try {
                var System = Java.use("java.lang.System");
                System.exit.implementation = function(code) {
                    console.log("[!] App 尝试调用 System.exit(" + code + ")，已拦截！");
                };
            } catch (e) {}
        });
    }

    stealth_init();

    // =========================================================
    // 2. 工具类 (保持并增强)
    // =========================================================
    var Utils = {
        processReturnValue: function (retval) {
            try {
                if (retval === null || retval === undefined) return "null";
                return retval.toString();
            } catch (e) { return '[Object]'; }
        },
        getTS: function () {
            var d = new Date();
            var pad = function(n) { return n < 10 ? '0' + n : n; };
            return d.getFullYear().toString() + pad(d.getMonth() + 1) + pad(d.getDate()) +
                   pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
        },
        b64: function (arrayBuffer) {
            var uint8 = new Uint8Array(arrayBuffer);
            var b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
            var l = uint8.length;
            var result = '';
            for (var i = 0; i < l; i += 3) {
                var a = uint8[i], b = uint8[i + 1], c = uint8[i + 2];
                result += b64chars[a >> 2];
                result += b64chars[((a & 3) << 4) | (b >> 4)];
                if (i + 1 < l) result += b64chars[((b & 15) << 2) | (c >> 6)];
                else result += '=';
                if (i + 2 < l) result += b64chars[c & 63];
                else result += '=';
            }
            return result;
        },
        getCallerInfo: function() {
            if (Java.available) {
                try {
                    var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                    for (var i = 3; i < stackTrace.length; i++) {
                        var frame = stackTrace[i];
                        var className = frame.getClassName();
                        if (className.startsWith('frida') || className.startsWith('dalvik') ||
                            className.startsWith('java.lang.reflect') || className.startsWith('com.android.internal')) {
                            continue;
                        }
                        return className + "." + frame.getMethodName() + "(" + frame.getFileName() + ":" + frame.getLineNumber() + ")";
                    }
                } catch (e) { return "Stack_Error"; }
            }
            return "Unknown_Caller";
        }
    };

    function safeGetPath(ptr) {
        if (ptr.isNull()) return null;
        try { return ptr.readUtf8String(); }
        catch (e) { try { return ptr.readCString(); } catch (e2) { return null; } }
    }

    function isPrivacyPath(name) {
        if (!name) return false;
        return name.startsWith("/storage") &&
               !name.startsWith("/storage/emulated/0/Android/obb") &&
               !name.startsWith("/storage/emulated/0/Android/data");
    }

    // =========================================================
    // 3. 核心业务功能 (延迟 3 秒注入)
    // =========================================================
    setTimeout(function() {
        console.log("[*] 延迟时间到，开始注入业务监控...");

        Java.perform(function () {
            // --- SSL Unpinning ---
            try {
                var ArrayList = Java.use("java.util.ArrayList");
                var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function (a, b, c) {
                    return ArrayList.$new();
                };
                var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) { return; };
                HttpsURLConnection.setHostnameVerifier.implementation = function (v) { return; };
            } catch (e) { console.log("[-] SSL Unpinning 注入跳过"); }

            // --- 代理注入 ---
            try {
                var InetSocketAddress = Java.use("java.net.InetSocketAddress");
                var ProxyClass = Java.use("java.net.Proxy");
                var ProxyType = Java.use("java.net.Proxy$Type");
                var myProxy = ProxyClass.$new(ProxyType.valueOf("HTTP"), InetSocketAddress.$new("127.0.0.1", 8080));

                var ConnectivityManager = Java.use("android.net.ConnectivityManager");
                if (ConnectivityManager.getProxyService) ConnectivityManager.getProxyService.implementation = function () { return null; };

                var URL = Java.use("java.net.URL");
                URL.openConnection.overload().implementation = function () { return this.openConnection(myProxy); };
                URL.openConnection.overload('java.net.Proxy').implementation = function (p) { return this.openConnection(myProxy); };
                console.log("[*] Proxy Injection Deployed.");
            } catch (e) { console.log("[-] Proxy 注入失败"); }
        });

        // --- Native SSL 绕过 ---
        ["libssl.so", "libboringssl.so", "libcronet.so"].forEach(function(modName) {
            var m = Process.findModuleByName(modName);
            if (m) {
                var get_result_ptr = Module.findExportByName(m.name, "SSL_get_verify_result");
                if (get_result_ptr) {
                    Interceptor.attach(get_result_ptr, { onLeave: function (retval) { retval.replace(ptr(0)); } });
                }
            }
        });

        // =========================================================
        // 4. 增强的文件隐私监控 (保持你的格式)
        // =========================================================

        // A. open & openat
        function hookOpenFunc(name) {
            var p = Module.findExportByName("libc.so", name);
            if (!p) return;
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var pathPtr = (name === "open") ? args[0] : args[1];
                    this.name = safeGetPath(pathPtr);
                    this.flag = (name === "open") ? args[1].toInt32() : args[2].toInt32();
                },
                onLeave: function (retval) {
                    var fd = retval.toInt32();
                    if (fd > 0 && isPrivacyPath(this.name)) {
                        Files.set(fd, this.name);
                        send(JSON.stringify({"fs":{"function":"open","fd":fd,"path":this.name,"flag":this.flag}}));
                    }
                }
            });
        }
        hookOpenFunc("open");
        hookOpenFunc("openat");

        // B. remove
        var removePtr = Module.findExportByName("libc.so", "remove");
        if (removePtr) {
            Interceptor.attach(removePtr, {
                onEnter: function (args) { this.name = safeGetPath(args[0]); },
                onLeave: function (retval) {
                    if (isPrivacyPath(this.name)) {
                        send(JSON.stringify({"fs":{"function":"remove","status":retval.toInt32(),"path":this.name}}));
                    }
                }
            });
        }

        // C. rename
        var renamePtr = Module.findExportByName("libc.so", "rename");
        if (renamePtr) {
            Interceptor.attach(renamePtr, {
                onEnter: function (args) {
                    this.src = safeGetPath(args[0]);
                    this.dst = safeGetPath(args[1]);
                },
                onLeave: function (retval) {
                    if (retval.toInt32() == 0 && (isPrivacyPath(this.src) || isPrivacyPath(this.dst))) {
                        send(JSON.stringify({"fs":{"function":"rename","source":this.src,"destination":this.dst}}));
                    }
                }
            });
        }

        // D. read & write (带 FD 过滤，防止崩溃)
        function hookReadWrite(name) {
            var p = Module.findExportByName("libc.so", name);
            if (!p) return;
            Interceptor.attach(p, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                    this.addr = args[1];
                },
                onLeave: function (retval) {
                    var len = retval.toInt32();
                    if (len > 0 && len != 0xFFFFFFFF && Files.has(this.fd)) {
                        // 性能优化：限制读取前 16KB，防止大文件导致 ANR 闪退
                        var captureLen = Math.min(len, 16384);
                        var data = Memory.readByteArray(this.addr, captureLen);
                        send(JSON.stringify({
                            "fs": {
                                "function": name,
                                "fd": this.fd,
                                "path": Files.get(this.fd),
                                "data": Utils.b64(data)
                            }
                        }));
                    }
                }
            });
        }
        hookReadWrite("read");
        hookReadWrite("write");

        // E. close
        var closePtr = Module.findExportByName("libc.so", "close");
        if (closePtr) {
            Interceptor.attach(closePtr, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                },
                onLeave: function (retval) {
                    if (Files.has(this.fd)) {
                        send(JSON.stringify({"fs":{"function":"close","fd":this.fd}}));
                        Files.delete(this.fd);
                    }
                }
            });
        }

        console.log("[*] 文件隐私监控已就绪");
    }, 3000);

    // =========================================================
    // 5. RPC 监控部分 (保持)
    // =========================================================
    rpc.exports = {
        apimonitor: function (api_to_monitor) {
            var api_list = Array.isArray(api_to_monitor) ? api_to_monitor : [api_to_monitor];
            setTimeout(function() {
                Java.perform(function () {
                    api_list.forEach(function (category_obj) {
                        var category = category_obj["Category"];
                        var hooks = category_obj["hooks"];
                        if (!hooks) return;
                        hooks.forEach(function (hook) {
                            try {
                                var targetClass = Java.use(hook.clazz);
                                targetClass[hook.method].overloads.forEach(function (overload) {
                                    overload.implementation = function () {
                                        var args = Array.prototype.slice.call(arguments);
                                        var retval = this[hook.method].apply(this, arguments);
                                        var callerInfo = (category === "PrivacyAPI") ? Utils.getCallerInfo() : "Skipped";
                                        send({
                                            ts: Utils.getTS(),
                                            category: category,
                                            "class": hook.clazz,
                                            method: hook.method,
                                            args: args.map(function(a) { return String(a); }),
                                            returnValue: Utils.processReturnValue(retval),
                                            calledFrom: callerInfo
                                        });
                                        return retval;
                                    };
                                });
                            } catch (err) {}
                        });
                    });
                });
            }, 1000);
            return "Deployed.";
        }
    };
})();
