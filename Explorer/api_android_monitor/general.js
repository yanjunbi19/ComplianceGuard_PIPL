// ========================================
// general.js - 通用工具和基础Hook
// 保留网络函数定义（供其他脚本引用），但不进行网络重定向
// ========================================

var JavaConnectionPool = {};
var Modules = {};
const Files = new Map();

// ========== 工具函数 ==========

function base64(input) {
    var _keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    var output = "";
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;
    while (i < input.length) {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;
        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }

        output = output + _keyStr.charAt(enc1) + _keyStr.charAt(enc2) + _keyStr.charAt(enc3) + _keyStr.charAt(enc4);
    }
    return output;
}

function btoa(p) {
    if (p == null) {
        return ''
    } else {
        if (typeof (p) === 'string') {
            var p = Java.use('java.lang.String').$new(p).getBytes();
        }
        try {
            if (p.$className == "java.nio.HeapByteBuffer") {
                p = p.array();
            }
            var Base64 = Java.use('android.util.Base64');
            var base64encode = Base64.encodeToString.overload('[B', 'int');
            return base64encode.call(Base64, p, 2);
        } catch (_e) {
            return arrayBufferToBase64(p);
        }
    }
}

function arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return base64(binary);
}

function ntohs(val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

function arrayBuffer(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return (binary);
}

// ========== 网络相关函数（保留定义，供其他脚本引用）==========

function inet_pton(a) {
    let m
    let i
    let j
    const f = String.fromCharCode

    m = a.match(/^(?:\d{1,3}(?:\.|$)){4}/)
    if (m) {
        m = m[0].split('.')
        m = f(m[0], m[1], m[2], m[3])
        if (m.length === 4) {
            var ret = new Uint8Array(4);
            for (var ii = 0; ii < m.length; ii++) {
                ret[ii] = m.charCodeAt(ii);
            }
            return ret;
        } else {
            return false;
        }
    }

    // IPv6
    if (a.length > 39) {
        return false
    }

    m = a.split('::')

    if (m.length > 2) {
        return false
    }

    const reHexDigits = /^[\da-f]{1,4}$/i

    for (j = 0; j < m.length; j++) {
        if (m[j].length === 0) {
            continue
        }
        m[j] = m[j].split(':')
        for (i = 0; i < m[j].length; i++) {
            let hextet = m[j][i]
            if (!reHexDigits.test(hextet)) {
                return false
            }

            hextet = parseInt(hextet, 16)
            if (isNaN(hextet)) {
                return false
            }
            m[j][i] = f(hextet >> 8, hextet & 0xFF)
        }
        m[j] = m[j].join('')
    }
    var final = m.join('\x00'.repeat(16 - m.reduce((tl, m) => tl + m.length, 0)));

    var ret = new Uint8Array(16);
    for (var ii = 0; ii < final.length; ii++) {
        ret[ii] = final.charCodeAt(ii);
    }
    return ret;
}

function inet_ntop(v) {
    var a = arrayBuffer(v);
    let i = 0
    let m = ''
    const c = []
    a += ''
    if (a.length === 4) {
        return [a.charCodeAt(0), a.charCodeAt(1), a.charCodeAt(2), a.charCodeAt(3)].join('.')
    } else if (a.length === 16) {
        for (i = 0; i < 16; i++) {
            c.push(((a.charCodeAt(i++) << 8) + a.charCodeAt(i)).toString(16))
        }
        return c.join(':').replace(/((^|:)0(?=:|$))+:?/g, function (t) {
            m = (t.length > m.length) ? t : m
            return t
        }).replace(m || ' ', '::')
    } else {
        return null
    }
}

function ipv4t6(a) {
    var z = inet_pton(a)
    if (z == false) {
        return false
    }
    var ar = new Uint8Array(16);
    for (var i = 0; i < 4; i++) {
        ar[12 + i] = z[i];
    }
    return inet_ntop(ar);
}

// ========== 🔹 关键修改：定义变量但不用于重定向 ==========
// 这些变量只是占位符，不会实际影响网络流量
var proxy_addr4 = "127.0.0.1"  // 🔹 改成127.0.0.1（无害）
var proxy_addr6 = ipv4t6(proxy_addr4)

console.log("[General] Network functions loaded (no redirection)");

// ========== 基础Hook ==========

Java.perform(function () {
    console.log("[General] Starting basic hooks...");

    // ========== 1. 阻止APP退出 ==========
    try {
        Java.use('java.lang.System').exit.implementation = function (v) {
            console.log("[Bypass] System.exit(" + v + ") - Blocked");
            // 不执行退出
            // return this.exit(v);
        }
        console.log("[✓] Hooked System.exit");
    } catch (_) {
        console.log("[✗] Failed to hook System.exit");
    }

    // ========== 2. 绕过设备安全检测 ==========
    try {
        Java.use('android.app.KeyguardManager').isDeviceSecure.overload().implementation = function (v) {
            console.log("[Bypass] isDeviceSecure -> true");
            return true;
        }
        console.log("[✓] Hooked isDeviceSecure");
    } catch (_) {
        console.log("[✗] Failed to hook isDeviceSecure");
    }

    // ========== 3. 绕过安装来源检测 ==========
    try {
        Java.use("android.app.ApplicationPackageManager").getInstallerPackageName.implementation = function (_packageName) {
            console.log("[Bypass] getInstallerPackageName: " + _packageName + " -> com.android.vending");
            return Java.use("java.lang.String").$new("com.android.vending").toString();
        }
        console.log("[✓] Hooked getInstallerPackageName");
    } catch (_) {
        console.log("[✗] Failed to hook getInstallerPackageName");
    }

    // ========== 4. 绕过安装来源检测（Android 11+）==========
    try {
        Java.use('android.content.pm.InstallSourceInfo').getInstallingPackageName.implementation = function () {
            console.log("[Bypass] getInstallingPackageName -> com.android.vending");
            return Java.use("java.lang.String").$new("com.android.vending").toString();
        }
        console.log("[✓] Hooked getInstallingPackageName");
    } catch (_) {
        console.log("[✗] Failed to hook getInstallingPackageName");
    }

    console.log("[General] Basic hooks completed");
});

// ========== 内存保护（可选，已注释）==========
/*
Process.enumerateModules()
   .forEach(function (m) {
       if (m.path.startsWith("/apex/") || m.path.startsWith("/data/app/")) {
           Memory.protect(m.base, m.size, 'rwx');
       }
   });
*/

console.log("[General] Loaded successfully");
