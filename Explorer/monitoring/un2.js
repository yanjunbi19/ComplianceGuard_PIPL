(function () {
    console.log("[*] Start Monitoring with login state - Stability Version");

    var ArrayList = null;
    var Files = new Map(); // 用于追踪 Native 文件路径

    var Utils = {
        processReturnValue: function (retval) {
            try {
                if (retval === null || retval === undefined) return undefined;
                return retval.toString();
            } catch (e) { return '[Object]'; }
        },
        getTS: function () {
            var d = new Date();
            var pad = function(n) { return n < 10 ? '0' + n : n; };
            return d.getFullYear().toString() + pad(d.getMonth() + 1) + pad(d.getDate()) +
                   pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
        },
        // 👈 修复：高效的 Base64 转换，避免 "expected an integer" 错误
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
        }
    };

    // ========== 1. 底层 Native 绕过 (证书固定) ==========
    function deployNativeUnpinning() {
        var modules = ["libssl.so", "libboringssl.so", "libcronet.so"];
        modules.forEach(function(modName) {
            var m = Process.findModuleByName(modName);
            if (m) {
                var get_result_ptr = Module.findExportByName(m.name, "SSL_get_verify_result");
                if (get_result_ptr) {
                    Interceptor.attach(get_result_ptr, { onLeave: function (retval) { retval.replace(ptr(0)); } });
                }
            }
        });
    }
    setTimeout(deployNativeUnpinning, 500);

    // =========================================================
    // ✅ 核心修复: 将反调试逻辑提升到全局作用域
    // =========================================================
    function deployAntiDetection() {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;

        // 1. Ptrace Bypass
        var ptracePtr = Module.findExportByName(libc.name, "ptrace");
        if (ptracePtr) {
            Interceptor.replace(ptracePtr, new NativeCallback(function (request, pid, addr, data) {
                if (request.toInt32() === 0 || request.toInt32() === 1) {
                    return -1; 
                }
                return new NativeFunction(ptracePtr, 'long', ['int', 'int', 'pointer', 'pointer'])(request, pid, addr, data);
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            console.log("[+] Anti-debug: Ptrace bypassed.");
        }

        // 2. Kill Syscall Bypass
        var killPtr = Module.findExportByName(libc.name, "kill");
        var SIGSTOP = 19; 
        var SIGTRAP = 5;
        
        // --- 核心修改：使用 FFI 调用 getpid() ---
        var getpidPtr = Module.findExportByName(libc.name, "getpid");
        if (!getpidPtr) {
            console.log("[-] getpid not found, Kill Hook skipped.");
            return;
        }
        var getpid = new NativeFunction(getpidPtr, 'int', []);
        var currentPid = getpid(); // <-- 绝对稳定的获取 PID 方式
        // ------------------------------------------

        if (killPtr) {
            Interceptor.attach(killPtr, {
                onEnter: function (args) {
                    this.pid = args[0].toInt32();
                    this.sig = args[1].toInt32();
                    if (this.pid === currentPid && (this.sig === SIGSTOP || this.sig === SIGTRAP)) {
                        args[1] = ptr(0); 
                        console.log("[+] Anti-debug: Blocked debug signal (SIG:" + this.sig + ").");
                    }
                }
            });
        }
    }
    // =========================================================


    // ========== 2. Java 层逻辑 (网络/媒体/隐私) ==========
    Java.perform(function () {
        ArrayList = Java.use("java.util.ArrayList");
        var Log = Java.use("android.util.Log");
        var Exception = Java.use("java.lang.Exception");

        // --- 2.1 深度隐藏代理与网络状态 ---
        try {
            var ConnectivityManager = Java.use("android.net.ConnectivityManager");
            if (ConnectivityManager.getProxyService) {
                ConnectivityManager.getProxyService.implementation = function () { return null; };
            }
            if (ConnectivityManager.getDefaultProxy) {
                ConnectivityManager.getDefaultProxy.implementation = function () { return null; };
            }

            var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");
            NetworkCapabilities.hasCapability.implementation = function (c) {
                if ([11, 12, 15, 16].indexOf(c) !== -1) return true;
                return this.hasCapability(c);
            };

            var NetworkInfo = Java.use("android.net.NetworkInfo");
            NetworkInfo.isConnectedOrConnecting.implementation = function () { return true; };
            NetworkInfo.isConnected.implementation = function () { return true; };
            NetworkInfo.isAvailable.implementation = function () { return true; };
        } catch (e) { console.log("[-] Network Spoof Err (Non-Fatal): " + e); }

        // --- 2.2 媒体监控模块 (Camera/Audio) ---
        try {
            var Camera = Java.use("android.hardware.Camera");
            var AudioRecord = Java.use("android.media.AudioRecord");

            function sendMediaEvent(clazz, method, args) {
                send({
                    "media": {
                        "ts": Utils.getTS(),
                        "class": clazz,
                        "method": method,
                        "args": args.map(function(a) { return String(a); }),
                        "stack": Log.getStackTraceString(Exception.$new())
                    }
                });
            }

            // 监控所有 Camera.open 重载
            Camera.open.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var args = Array.prototype.slice.call(arguments);
                    sendMediaEvent("android.hardware.Camera", "open", args);
                    return this.open.apply(this, arguments);
                };
            });

            // 监控 AudioRecord.startRecording (处理重载)
            var startRec = AudioRecord.startRecording;
            if (startRec) {
                startRec.overloads.forEach(function(ov) {
                    ov.implementation = function() {
                        sendMediaEvent("android.media.AudioRecord", "startRecording", []);
                        return ov.apply(this, arguments);
                    };
                });
            }
        } catch (e) { console.log("[-] Media Hook Err: " + e); }

        // --- 2.3 彻底解决 TrustManager 问题 ---
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function (chain, authType, host) {
                return ArrayList.$new(); 
            };
        } catch (e) {}

        // --- 2.4 绕过 HostnameVerifier ---
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) { return; };
            HttpsURLConnection.setHostnameVerifier.implementation = function (v) { return; };
        } catch (e) {}

        try {
            // ✅ 修复：正确引用 OkHttpClient.Builder 类
            var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
            
            var InetSocketAddress = Java.use("java.net.InetSocketAddress");
            var ProxyClass = Java.use("java.net.Proxy");
            var ProxyType = Java.use("java.net.Proxy$Type");
            
            // 使用 createUnresolved 避免 DNS 查找，提高稳定性
            var myProxy = ProxyClass.$new(ProxyType.valueOf("HTTP"), 
                                          InetSocketAddress.createUnresolved("127.0.0.1", 8080));
            
            OkHttpClientBuilder.build.implementation = function () {
                this.proxy(myProxy);
                return this.build();
            };
        } catch (e) {
            console.log("[-] OkHttp Proxy Hook Err (Non-Fatal): " + e); 
        }

        // --- 2.6 强制 java.net.URL 代理注入 (解决原生库绕过) ---
        try {
            var URL = Java.use("java.net.URL");
            var ProxyClass = Java.use("java.net.Proxy");
            var ProxyType = Java.use("java.net.Proxy$Type");
            var InetSocketAddress = Java.use("java.net.InetSocketAddress");
            
            var myProxy = ProxyClass.$new(ProxyType.valueOf("HTTP"), 
                                            InetSocketAddress.createUnresolved("127.0.0.1", 8080));

            // Hook openConnection()
            URL.openConnection.overload().implementation = function () {
                // 调用带代理参数的重载
                return this.openConnection.overload('java.net.Proxy').call(this, myProxy);
            };
            
        } catch (e) {
            console.log("[-] URL Proxy Hook Err: " + e); 
        }

    });

    // ========== 3. Native 文件/反检测逻辑 (仅 TracerPid 和文件监控) ==========
    (function () {
        // --- 3.1 修复后的 TracerPid 隐藏 (防崩溃版) ---
        var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
        if (fgetsPtr) {
            Interceptor.attach(fgetsPtr, {
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    try {
                        var bufstr = retval.readCString(); 
                        if (bufstr && bufstr.indexOf('TracerPid:') > -1) {
                            retval.writeUtf8String('TracerPid:\t0');
                        }
                    } catch (err) {}
                }
            });
        }

        // 👈 新增：Native 文件监控 (libc.so)
        try {
            var openPtr = Module.findExportByName("libc.so", "open");
            if (openPtr) {
                Interceptor.attach(openPtr, {
                    onEnter: function (args) { this.path = Memory.readUtf8String(args[0]); },
                    onLeave: function (retval) {
                        var fd = retval.toInt32();
                        if (this.path && (this.path.indexOf("/storage") > -1 || this.path.indexOf("/sdcard") > -1) && fd > 0) {
                            Files.set(fd, this.path);
                            send({ "fs": { "function": "open", "fd": fd, "path": this.path, "ts": Utils.getTS() } });
                        }
                    }
                });
            }

            var writePtr = Module.findExportByName("libc.so", "write");
            if (writePtr) {
                Interceptor.attach(writePtr, {
                    onEnter: function (args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
                    onLeave: function (retval) {
                        var len = retval.toInt32();
                        if (len > 0 && len < 1024 * 1024 && Files.has(this.fd)) { // 限制 1MB 避免性能崩溃
                            var data = Memory.readByteArray(this.buf, len);
                            send({ "fs": { "function": "write", "fd": this.fd, "path": Files.get(this.fd), "data_b64": Utils.b64(data), "ts": Utils.getTS() } });
                        }
                    }
                });
            }
        } catch (e) { console.log("[-] Native FS Hook Error: " + e); }
    })();

    // ========== 4. RPC 监控部分 (保持) ==========
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
                                        send({
                                            ts: Utils.getTS(),
                                            category: category,
                                            "class": hook.clazz,
                                            method: hook.method,
                                            args: args.map(function(a) { return String(a); }),
                                            returnValue: Utils.processReturnValue(retval)
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
    
    // ✅ 关键修复：在全局作用域中调用延迟后的函数
    setTimeout(deployAntiDetection, 1500); 
    
    console.log("[*] Start Moninting with login state load end!");
})();
