[built_in_crypto.js](built_in_crypto.js)

监控 Android 应用的所有加密操作，包括：

加密/解密数据（
Cipher.doFinal()
,
Cipher.update()
）
密钥初始化（
Cipher.init()
）
IV 和密钥生成（
IvParameterSpec
,
SecretKeySpec
）

generate_dynamic_hooks()

动态生成 JavaScript 代码来 Hook 自定义加密函数，监控应用中所有加密操作的参数和返回值。

[bypass_root_detection.js](bypass_root_detection.js)

过root

[debug.js](debug.js)

隐藏 ADB 调试状态，绕过反调试检测


[java.js](java.js)

监控 Java 层的所有网络连接（TCP/UDP），记录连接地址、本地地址、设备 ID，并将 HTTPS 连接重定向到代理。

[native.js](native.js)

监控和拦截应用的所有网络连接，包括：

记录所有 TCP/UDP 连接
重定向 HTTPS 连接到代理
阻止特定的本地连接
获取 libc.so 库
  ↓
枚举网络相关函数
  ↓
Hook 每个网络函数
  ├─ onEnter: 记录连接信息
  └─ onLeave: 发送数据、重定向、阻止

[fs.js](fs.js)

监控应用对存储卡文件的所有操作（打开、读、写、删除、重命名），记录文件路径和数据内容。


[media.js](media.js)

监控应用对摄像头、麦克风、屏幕录制的所有操作，记录调用时间、调用栈，追踪隐私数据采集行为。

