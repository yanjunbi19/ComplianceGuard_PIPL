(function () {
    console.log("[*] Start Moninting with login state ");

    var ArrayList = null;
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
        }
    };

       // ========== 1. 底层 Native 绕过 (保持) ==========
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

    // ========== 2. Java 层核心逻辑 ==========
    Java.perform(function () {
        ArrayList = Java.use("java.util.ArrayList");
        var ConnectivityManager = Java.use("android.net.ConnectivityManager");
        var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");
        var NetworkInfo = Java.use("android.net.NetworkInfo");

        // --- 2.1 深度隐藏代理：让 App 觉得自己在纯净 WIFI 下 ---
        // 屏蔽代理获取,44行错误也没关系，不能注释，注释就失败了
        ConnectivityManager.getProxyService.implementation = function () { return null; };
        ConnectivityManager.getDefaultProxy.implementation = function () { return null; };

        // 强行修改网络能力标志
        NetworkCapabilities.hasCapability.implementation = function (c) {
            // 12: INTERNET, 16: NOT_PROXY, 15: NOT_VPN, 11: NOT_METERED
            if ([11, 12, 15, 16].indexOf(c) !== -1) return true;
            return this.hasCapability(c);
        };

        // 屏蔽 VPN 传输类型
        NetworkCapabilities.hasTransport.implementation = function (t) {
            if (t === 4) return false; // 4 是 TRANSPORT_VPN
            if (t === 1) return true;  // 1 是 TRANSPORT_WIFI
            return this.hasTransport(t);
        };

        // 伪装 NetworkInfo 状态
        NetworkInfo.isConnectedOrConnecting.implementation = function () { return true; };
        NetworkInfo.isConnected.implementation = function () { return true; };
        NetworkInfo.isAvailable.implementation = function () { return true; };

        // --- 2.2 彻底解决 TrustManager: null 问题 ---
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        // Hook 3个参数的版本
        TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function (chain, authType, host) {
            // console.log('🚀 [SSL Bypass] TrustManager (3-arg): ' + host);
            return ArrayList.$new(); 
        };

        // Hook 2个参数的版本 (很多底层校验会走这里)
        TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (chain, authType) {
            // console.log('🚀 [SSL Bypass] TrustManager (2-arg) triggered');
            return ArrayList.$new();
        };

        // --- 2.3 绕过 HostnameVerifier (全量 Hook) ---
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
            // console.log("🚀 [SSL Bypass] Disabling DefaultHostnameVerifier");
            return; 
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
            // console.log("🚀 [SSL Bypass] Disabling InstanceHostnameVerifier");
            return;
        };

        // --- 2.4 OkHttp3 深度绕过 ---
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (h, c) {
                // console.log('🚀 [SSL Bypass] OkHttp3: ' + h);
                return; 
            };
        } catch (e) {}

        // --- 2.5 强制协议回退 ---
        try {
            var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
            var Protocol = Java.use("okhttp3.Protocol");
            OkHttpClientBuilder.protocols.implementation = function (p) {
                var list = ArrayList.$new();
                list.add(Protocol.HTTP_1_1.value);
                return this.protocols(list);
            };
        } catch (e) {}

        // --- 2.6 内存代理注入 ---
        try {
            var InetSocketAddress = Java.use("java.net.InetSocketAddress");
            var ProxyClass = Java.use("java.net.Proxy");
            var ProxyType = Java.use("java.net.Proxy$Type");
            var myProxy = ProxyClass.$new(ProxyType.valueOf("HTTP"), InetSocketAddress.$new("127.0.0.1", 8080));
            
            OkHttpClientBuilder.build.implementation = function () {
                this.proxy(myProxy);
                return this.build();
            };
        } catch (e) {}

        // --- 2.7 隐藏系统属性 (防止检测 adb reverse) ---
        var System = Java.use("java.lang.System");
        var originalGetProperty = System.getProperty.overload('java.lang.String');
        System.getProperty.overload('java.lang.String').implementation = function (key) {
            if (key.indexOf("proxy") !== -1) return null;
            return originalGetProperty.call(System, key);
        };
    });

    // ========== 3. 反检测模块 (防止 TracerPid) ==========
    (function antiDetection() {
        var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
        if (fgetsPtr) {
            Interceptor.attach(fgetsPtr, {
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    var bufstr = retval.readUtf8String();
                    if (bufstr && bufstr.indexOf('TracerPid:') > -1) {
                        retval.writeUtf8String('TracerPid:\t0');
                    }
                }
            });
        }
    })();
    
    // ========== 3. RPC 监控部分 (保持) ==========
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
    console.log("[*] Start Moninting with login state load end!");
})();
