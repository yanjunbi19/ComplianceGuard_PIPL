/**
 * force_proxy.js
 * 强制所有网络请求使用指定代理
 * 支持 OkHttp, HttpURLConnection, Apache HttpClient, Volley 等
 */

Java.perform(function() {
    console.log("========================================");
    console.log("[Force Proxy] Starting proxy enforcement");
    console.log("========================================");

    // ========== 配置代理地址 ==========
    var PROXY_HOST = "192.168.143.112";
    var PROXY_PORT = 8080;

    console.log("[Config] Proxy: " + PROXY_HOST + ":" + PROXY_PORT);

    // ========== 1. Hook OkHttp3 (最常用的网络库) ==========
    try {
        console.log("\n[1/6] Hooking OkHttp3...");

        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        var Proxy = Java.use('java.net.Proxy');
        var ProxyType = Java.use('java.net.Proxy$Type');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');

        // Hook Builder.build()
        Builder.build.implementation = function() {
            console.log("   [OkHttp] Intercepting client build");

            try {
                // 创建代理对象
                var proxyAddr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
                var proxy = Proxy.$new(ProxyType.HTTP.value, proxyAddr);

                // 强制设置代理
                this.proxy(proxy);

                console.log("   [OkHttp] ✅ Proxy set successfully");
            } catch (e) {
                console.log("   [OkHttp] ⚠️ Error setting proxy: " + e);
            }

            return this.build();
        };

        // Hook proxy() 方法，防止被覆盖
        Builder.proxy.implementation = function(proxy) {
            if (proxy == null) {
                console.log("   [OkHttp] ⚠️ App trying to disable proxy, blocking!");

                var proxyAddr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
                var forcedProxy = Proxy.$new(ProxyType.HTTP.value, proxyAddr);
                return this.proxy(forcedProxy);
            }

            console.log("   [OkHttp] App setting custom proxy: " + proxy);
            return this.proxy(proxy);
        };

        console.log("   [OkHttp] ✅ Hooks installed");

    } catch (e) {
        console.log("   [OkHttp] ❌ Not found or error: " + e);
    }

    // ========== 2. Hook HttpURLConnection ==========
    try {
        console.log("\n[2/6] Hooking HttpURLConnection...");

        var URL = Java.use('java.net.URL');
        var Proxy = Java.use('java.net.Proxy');
        var ProxyType = Java.use('java.net.Proxy$Type');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');

        // Hook openConnection()
        URL.openConnection.overload().implementation = function() {
            var urlString = this.toString();
            console.log("   [HttpURLConnection] Request: " + urlString);

            try {
                var proxyAddr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
                var proxy = Proxy.$new(ProxyType.HTTP.value, proxyAddr);

                console.log("   [HttpURLConnection] ✅ Using proxy");
                return this.openConnection(proxy);
            } catch (e) {
                console.log("   [HttpURLConnection] ⚠️ Error: " + e);
                return this.openConnection();
            }
        };

        // Hook openConnection(Proxy)
        URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
            var urlString = this.toString();
            console.log("   [HttpURLConnection] Request with proxy: " + urlString);

            // 强制使用我们的代理
            var proxyAddr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
            var forcedProxy = Proxy.$new(ProxyType.HTTP.value, proxyAddr);

            console.log("   [HttpURLConnection] ✅ Forcing our proxy");
            return this.openConnection(forcedProxy);
        };

        console.log("   [HttpURLConnection] ✅ Hooks installed");

    } catch (e) {
        console.log("   [HttpURLConnection] ❌ Error: " + e);
    }

    // ========== 3. Hook Apache HttpClient ==========
    try {
        console.log("\n[3/6] Hooking Apache HttpClient...");

        var HttpHost = Java.use('org.apache.http.HttpHost');
        var DefaultHttpClient = Java.use('org.apache.http.impl.client.DefaultHttpClient');
        var HttpParams = Java.use('org.apache.http.params.HttpParams');
        var ConnRouteParams = Java.use('org.apache.http.conn.params.ConnRouteParams');

        // Hook execute 方法
        var executeOverloads = DefaultHttpClient.execute.overloads;

        executeOverloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("   [Apache HttpClient] Intercepting request");

                try {
                    var proxy = HttpHost.$new(PROXY_HOST, PROXY_PORT, "http");
                    var params = this.getParams();
                    ConnRouteParams.setDefaultProxy(params, proxy);

                    console.log("   [Apache HttpClient] ✅ Proxy set");
                } catch (e) {
                    console.log("   [Apache HttpClient] ⚠️ Error: " + e);
                }

                return overload.apply(this, arguments);
            };
        });

        console.log("   [Apache HttpClient] ✅ Hooks installed");

    } catch (e) {
        console.log("   [Apache HttpClient] ❌ Not found: " + e);
    }

    // ========== 4. Hook Volley (Google 网络库) ==========
    try {
        console.log("\n[4/6] Hooking Volley...");

        var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
        var Proxy = Java.use('java.net.Proxy');
        var ProxyType = Java.use('java.net.Proxy$Type');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');

        // Hook createConnection
        HurlStack.createConnection.implementation = function(url) {
            console.log("   [Volley] Request: " + url.toString());

            try {
                var proxyAddr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
                var proxy = Proxy.$new(ProxyType.HTTP.value, proxyAddr);

                var connection = url.openConnection(proxy);
                console.log("   [Volley] ✅ Using proxy");
                return connection;
            } catch (e) {
                console.log("   [Volley] ⚠️ Error: " + e);
                return this.createConnection(url);
            }
        };

        console.log("   [Volley] ✅ Hooks installed");

    } catch (e) {
        console.log("   [Volley] ❌ Not found: " + e);
    }

    // ========== 5. Hook Retrofit (基于 OkHttp) ==========
    try {
        console.log("\n[5/6] Hooking Retrofit...");

        var Retrofit = Java.use('retrofit2.Retrofit');
        var RetrofitBuilder = Java.use('retrofit2.Retrofit$Builder');

        RetrofitBuilder.build.implementation = function() {
            console.log("   [Retrofit] Intercepting builder");

            try {
                // Retrofit 使用 OkHttp，所以 OkHttp 的 hook 会生效
                console.log("   [Retrofit] ✅ Will use OkHttp proxy");
            } catch (e) {
                console.log("   [Retrofit] ⚠️ Error: " + e);
            }

            return this.build();
        };

        console.log("   [Retrofit] ✅ Hooks installed");

    } catch (e) {
        console.log("   [Retrofit] ❌ Not found: " + e);
    }

    // ========== 6. Hook DNS 解析（调试用） ==========
    try {
        console.log("\n[6/6] Hooking DNS resolution...");

        var InetAddress = Java.use('java.net.InetAddress');

        InetAddress.getAllByName.overload('java.lang.String').implementation = function(host) {
            console.log("   [DNS] Resolving: " + host);

            try {
                var result = this.getAllByName(host);

                if (result && result.length > 0) {
                    console.log("   [DNS] ✅ Resolved to: " + result[0].getHostAddress());
                } else {
                    console.log("   [DNS] ⚠️ No results");
                }

                return result;
            } catch (e) {
                console.log("   [DNS] ❌ Resolution failed: " + e);
                console.log("   [DNS] Stack trace:");
                console.log(Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Exception").$new()
                ));
                throw e;
            }
        };

        console.log("   [DNS] ✅ Hooks installed");

    } catch (e) {
        console.log("   [DNS] ❌ Error: " + e);
    }

    // ========== 7. Hook ProxySelector (系统代理选择器) ==========
    try {
        console.log("\n[7/7] Hooking ProxySelector...");

        var ProxySelector = Java.use('java.net.ProxySelector');
        var Proxy = Java.use('java.net.Proxy');
        var ProxyType = Java.use('java.net.Proxy$Type');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');
        var ArrayList = Java.use('java.util.ArrayList');

        ProxySelector.getDefault().select.implementation = function(uri) {
            console.log("   [ProxySelector] Request for: " + uri.toString());

            try {
                var proxyList = ArrayList.$new();
                var proxyAddr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
                var proxy = Proxy.$new(ProxyType.HTTP.value, proxyAddr);
                proxyList.add(proxy);

                console.log("   [ProxySelector] ✅ Returning forced proxy");
                return proxyList;
            } catch (e) {
                console.log("   [ProxySelector] ⚠️ Error: " + e);
                return this.select(uri);
            }
        };

        console.log("   [ProxySelector] ✅ Hooks installed");

    } catch (e) {
        console.log("   [ProxySelector] ❌ Error: " + e);
    }

    console.log("\n========================================");
    console.log("[Force Proxy] ✅ All hooks installed!");
    console.log("[Force Proxy] Monitoring network traffic...");
    console.log("========================================\n");
});
