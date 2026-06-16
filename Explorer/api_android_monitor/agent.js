// agent.js - 终极强化版

console.log("--- [AGENT] 正在执行最终策略：强化排除列表 ---");

Java.perform(function() {
    try {
        // --- 强化版自定义排除列表 ---
        // 我们现在直接排除所有 'com.android.' 前缀的包，这是最可靠的方法
        const exclusionList = [
            "android",               // 排除 'android' 核心包
            "com.android.",          // <--- !! 关键变更 !! 排除所有标准安卓包和系统模块

            // 排除模拟器自带应用
            "com.mumu.",
            "com.netease.mumu.",
            "com.netease.nemu.",

            // 排除明确的工具类应用
            "io.github.huskydg.magisk", // Magisk Root
            "reaper.",                  // Reaper 分析工具
            "com.github.uiautomator",   // UIAutomator 测试框架
            "com.pcapdroid.mitm",       // PCAPdroid 抓包工具
            "com.emanuelef.remote_capture" // Remote Capture 抓包工具
        ];

        console.log("[AGENT] 强化版排除列表已加载，规则数量: " + exclusionList.length);

        var ActivityThread = Java.use('android.app.ActivityThread');
        var PackageInfo = Java.use('android.content.pm.PackageInfo');

        var currentApplication = ActivityThread.currentApplication();
        var packageManager = currentApplication.getPackageManager();
        var installedPackagesList = packageManager.getInstalledPackages(0);

        var userInstalledPackageNames = [];

        // --- 反射准备 ---
        var pkgInfoClass = Java.use('android.content.pm.PackageInfo').class;
        var packageNameField = pkgInfoClass.getField("packageName");
        packageNameField.setAccessible(true);

        console.log("[AGENT] 开始遍历和过滤...");

        for (var i = 0; i < installedPackagesList.size(); i++) {
            var pkgInfo = Java.cast(installedPackagesList.get(i), PackageInfo);

            var packageNameValue = packageNameField.get(pkgInfo);
            var finalPackageNameStr = packageNameValue.toString();

            // --- 核心过滤逻辑：只使用排除列表 ---
            // 检查当前包名是否以排除列表中的任何一个前缀开头
            var isExcluded = exclusionList.some(function(prefix) {
                return finalPackageNameStr.startsWith(prefix);
            });

            // 如果没有被排除，它就是我们想要的第三方应用
            if (!isExcluded) {
                userInstalledPackageNames.push(finalPackageNameStr);
            }
        }

        console.log("[AGENT] 遍历和过滤完成，准备发送数据...");

        var payload_data = {
            status: "success",
            count: userInstalledPackageNames.length,
            package_names_json_str: JSON.stringify(userInstalledPackageNames)
        };

        send(payload_data);

    } catch (e) {
        console.error("[AGENT ERROR] " + e.stack);
        send({ status: "error", message: e.message, stack: e.stack });
    }
});
