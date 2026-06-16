/******************************************************************************
 * Exported APIs
 ******************************************************************************/

rpc.exports = {
    loadclasses: function () {
      var loaded_classes = []

      Java.perform(function () {
        Java.enumerateLoadedClasses({
          onMatch: function (className) {
            if (className.length > 5)
              loaded_classes.push(className)
          },
          onComplete: function () {
            loaded_classes.sort()
          }
        });
      })
      return loaded_classes;
    },

    loadclasseswithfilter: function (filter) {
      var loaded_classes = []
      Java.perform(function () {
        Java.enumerateLoadedClasses({
          onMatch: function (className) {
            if (filter != null) {
              var filter_array = filter.split(",");
              filter_array.forEach(function (f) {
                if (className.startsWith(f.trim())) {
                  loaded_classes.push(className)
                }
              });
            }
          },
          onComplete: function () {
            loaded_classes.sort()
          }
        });
      })
      return loaded_classes;
    },

    loadcustomfridascript: function (frida_script) {
      Java.perform(function () {
        console.log("FRIDA script LOADED")
        eval(frida_script)
      })
    },

    loadmethods: function (loaded_classes) {
      var loaded_methods = {};
      Java.perform(function () {
        loaded_classes.forEach(function (className, index) {
          var jClass;
          var classMethods_dirty;

          try{
            jClass = Java.use(className);
            classMethods_dirty = jClass.class.getDeclaredMethods();
          }catch(err){
            send("Exception while loading methods for "+className);
            loaded_methods[className] = []
            return;
          }
          var classMethods = []

          classMethods_dirty.forEach(function (m) {
            var method_and_args = {};
            m = m.toString();
            method_and_args["ui_name"] = m.replace(className + ".", "")

            while (m.includes("<")) {
              m = m.replace(/<.*?>/g, "");
            }

            if (m.indexOf(" throws ") !== -1) {
              m = m.substring(0, m.indexOf(" throws "));
            }

            m = m.slice(m.lastIndexOf(" "));
            m = m.replace(className + ".", "");
            method_and_args["name"] = m.split("(")[0].trim()

            var args_dirty = ((/\((.*?)\)/.exec(m)[1]).trim())
            var args_array = args_dirty.split(",")
            var args_srt = ""
            for (var i = 0; i < args_array.length; i++) {
              args_srt = args_srt + ("\"" + args_array[i] + "\"")
              if (i + 1 < args_array.length) args_srt = args_srt + ",";
            }

            method_and_args["args"] = args_srt
            classMethods.push(method_and_args);
          });

          loaded_methods[className] = classMethods;
        });
      })
      return loaded_methods;
    },

    hookclassesandmethods: function (loaded_classes, loaded_methods, template) {
      Java.perform(function () {
        console.log("Hook Template setup")

        loaded_classes.forEach(function (clazz) {
          loaded_methods[clazz].forEach(function (dict) {
            var t = template
            t = t.replace("{className}", clazz);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{classMethod}", dict["name"]);

            if (dict["args"] != "\"\"") {
              t = t.replace("{overload}", "overload(" + dict["args"] + ").");
              var args_len = (dict["args"].split(",")).length
              var args = "";
              for (var i = 0; i < args_len; i++) {
                if (i + 1 == args_len) args = args + "v" + i;
                else args = args + "v" + i + ",";
              }
              t = t.replace("{args}", args);
              t = t.replace("{args}", args);
            } else {
              t = t.replace("{overload}", "overload().");
              t = t.replace("{args}", "");
              t = t.replace("{args}", "");
            }
            eval(t);
          });
        });
      })
    },

    generatehooktemplate: function (loaded_classes, loaded_methods, template) {
      var hto = ""
      Java.perform(function () {
        loaded_classes.forEach(function (clazz) {
          loaded_methods[clazz].forEach(function (dict) {
            var t = template
            t = t.replace("{className}", clazz);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{methodSignature}", dict["ui_name"]);

            if (dict["args"] != "\"\"") {
              t = t.replace("{overload}", "overload(" + dict["args"] + ").");
              var args_len = (dict["args"].split(",")).length
              var args = "";
              for (var i = 0; i < args_len; i++) {
                if (i + 1 == args_len) args = args + "v" + i;
                else args = args + "v" + i + ",";
              }
              t = t.replace("{args}", args);
              t = t.replace("{args}", args);
              t = t.replace("{args}", args);
            } else {
              t = t.replace("{overload}", "overload().");
              t = t.replace("{args}", "");
              t = t.replace("{args}", "");
              t = t.replace("{args}", "\"\"");
            }
            hto = hto + t;
          });
        });
      })
      return hto;
    },

    heapsearchtemplate: function (loaded_classes, loaded_methods, template) {
      var hto = ""
      Java.perform(function () {
        loaded_classes.forEach(function (clazz) {
          loaded_methods[clazz].forEach(function (dict) {
            var t = template
            t = t.replace("{className}", clazz);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{classMethod}", dict["name"]);
            t = t.replace("{methodSignature}", dict["ui_name"]);

            if (dict["args"] != "\"\"") {
              var args_len = (dict["args"].split(",")).length
              var args = "";
              for (var i = 0; i < args_len; i++) {
                if (i + 1 == args_len) args = args + "v" + i;
                else args = args + "v" + i + ",";
              }
              t = t.replace("{args}", args);
            } else {
              t = t.replace("{args}", "");
            }
            hto = hto + t;
          });
        });
      })
      return hto;
    },

apimonitor: function (api_to_monitor) {
      Java.perform(function () {
        api_to_monitor.forEach(function (e) {
          e["hooks"].forEach(function (hook) {
            // Native Hook
            if (e["HookType"] == "Native") {
              nativedynamichook(hook, e["Category"]);
            }
            // Java Hook
            else if (e["HookType"] == "Java") {
              javadynamichook(hook, e["Category"], function (realRetval, to_print) {
                to_print.returnValue = realRetval;

                // 处理返回值
                if (realRetval && typeof realRetval === 'object' && realRetval.length !== undefined) {
                  var retval_string = [];
                  for (var k = 0, l = realRetval.length; k < l; k++) {
                    retval_string.push(realRetval[k]);
                  }
                  to_print.returnValue = '' + retval_string.join('');
                } else if (realRetval && typeof realRetval === 'object') {
                  try {
                    to_print.returnValue = realRetval.toString();
                  } catch (e) {
                    to_print.returnValue = '[Object could not be stringified]';
                  }
                }

                if (!to_print.result) to_print.result = undefined;
                if (to_print.returnValue === null || to_print.returnValue === "") to_print.returnValue = undefined;

                // ========== 检测并格式化加密消息 ==========
                var cryptoMessage = formatCryptoMessage(hook, to_print, realRetval);
                if (cryptoMessage) {
                  send(cryptoMessage);
                } else {
                  send(to_print);
                }

                return realRetval;
              });
            }
          });
        });
      })
    }
};
function toBase64Safe(data) {
  try {
    if (!data) {
      return "";
    }

    // 在函数内部重新获取 Java 类
    var Base64 = Java.use('android.util.Base64');
    var String = Java.use('java.lang.String');

    // 如果是字节数组
    if (data.$className && data.$className.indexOf("[B") !== -1) {
      return Base64.encodeToString(data, 0);
    }

    // 如果是 Java 字符串
    if (data.$className && data.$className === "java.lang.String") {
      var bytes = data.getBytes();
      return Base64.encodeToString(bytes, 0);
    }

    // 如果是 JavaScript 字符串
    if (typeof data === 'string') {
      var bytes = String.$new(data).getBytes();
      return Base64.encodeToString(bytes, 0);
    }

    // 如果是数字
    if (typeof data === 'number') {
      return data.toString();
    }

    // 如果是布尔值
    if (typeof data === 'boolean') {
      return data.toString();
    }

    // 如果是对象，尝试 toString
    if (data && typeof data === 'object') {
      try {
        var str = data.toString();
        var bytes = String.$new(str).getBytes();
        return Base64.encodeToString(bytes, 0);
      } catch (e) {
        console.log("Error converting object to Base64: " + e);
        return "[Object]";
      }
    }

    // 默认转为字符串
    return data ? data.toString() : "";

  } catch (e) {
    console.log("Error in toBase64Safe: " + e);
    // 返回一个安全的默认值
    try {
      return data ? data.toString() : "";
    } catch (e2) {
      return "[Error]";
    }
  }
}

/**
 * 安全地转换参数数组
 */
function convertArgsToBase64(args) {
  var result = [];
  try {
    if (!args || args.length === 0) {
      return result;
    }

    for (var i = 0; i < args.length; i++) {
      try {
        var converted = toBase64Safe(args[i]);
        result.push(converted);
      } catch (e) {
        console.log("Error converting arg " + i + ": " + e);
        result.push("[Error]");
      }
    }
  } catch (e) {
    console.log("Error in convertArgsToBase64: " + e);
  }
  return result;
}

/**
 * 获取堆栈跟踪
 */
function getStackTraceSafe() {
  try {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackTrace = Log.getStackTraceString(Exception.$new());
    return toBase64Safe(stackTrace);
  } catch (e) {
    console.log("Error getting stack trace: " + e);
    return "";
  }
}

/**
 * 安全地转换参数数组
 */
function convertArgsToBase64(args) {
  var result = [];
  try {
    if (!args || args.length === 0) {
      return result;
    }

    for (var i = 0; i < args.length; i++) {
      try {
        result.push(toBase64Safe(args[i]));
      } catch (e) {
        console.log("Error converting arg " + i + ": " + e);
        result.push("");
      }
    }
  } catch (e) {
    console.log("Error in convertArgsToBase64: " + e);
  }
  return result;
}

/**
 * 格式化加密消息
 */
function formatCryptoMessage(hook, to_print, retval) {
  var clazz = hook.clazz;
  var method = hook.method;

  try {
    // ========== 1. javax.crypto.Cipher ==========
    if (clazz === "javax.crypto.Cipher") {

      // Cipher.init
      if (method === "init") {
        try {
          var mode = String(to_print.args[0]); // 1=encrypt, 2=decrypt
          var key = to_print.args[1];
          var keyBytes = "";

          // 提取密钥字节
          if (key && key.$className) {
            if (key.$className.indexOf("SecretKey") !== -1) {
              keyBytes = toBase64Safe(key.getEncoded());
            }
          }

          // 获取算法和 IV
          var algorithm = "";
          var iv = "";

          try {
            // 注意：这里的 retval 可能是 undefined，因为 init 返回 void
            // 我们需要从 this 获取信息
            var cipherInstance = to_print.args.callee; // 获取 Cipher 实例
            if (cipherInstance && cipherInstance.getAlgorithm) {
              algorithm = cipherInstance.getAlgorithm();
            }
          } catch (e) {
            console.log("Error getting algorithm: " + e);
          }

          try {
            if (cipherInstance && cipherInstance.getIV) {
              var ivParam = cipherInstance.getIV();
              if (ivParam) {
                iv = toBase64Safe(ivParam);
              }
            }
          } catch (e) {
            console.log("Error getting IV: " + e);
          }

          // 获取 hashCode
          var hashcode = "";
          try {
            if (cipherInstance && cipherInstance.hashCode) {
              hashcode = String(cipherInstance.hashCode());
            }
          } catch (e) {
            hashcode = "0";
          }

          return {
            "crypto": JSON.stringify({
              "class_name": clazz,
              "method_name": "init-key",
              "args": [mode, keyBytes, "java.security.SecureRandom"],
              "ret": "",
              "hashcode": hashcode,
              "algorithm": algorithm,
              "IV": iv,
              "stackTrace": getStackTraceSafe()
            })
          };
        } catch (e) {
          console.log("Error formatting Cipher.init: " + e);
          return null;
        }
      }

      // Cipher.doFinal
      else if (method === "doFinal") {
        try {
          var input = to_print.args[0];
          var output = retval;

          var inputBase64 = toBase64Safe(input);
          var outputBase64 = toBase64Safe(output);

          var hashcode = "0";
          try {
            if (to_print.args.callee && to_print.args.callee.hashCode) {
              hashcode = String(to_print.args.callee.hashCode());
            }
          } catch (e) {}

          return {
            "crypto": JSON.stringify({
              "class_name": clazz,
              "method_name": "doFinal",
              "args": [inputBase64],
              "ret": outputBase64,
              "hashcode": hashcode,
              "stackTrace": getStackTraceSafe()
            })
          };
        } catch (e) {
          console.log("Error formatting Cipher.doFinal: " + e);
          return null;
        }
      }

      // Cipher.update
      else if (method === "update") {
        try {
          var input = to_print.args[0];
          var output = retval;

          var inputBase64 = toBase64Safe(input);
          var outputBase64 = toBase64Safe(output);

          var hashcode = "0";
          try {
            if (to_print.args.callee && to_print.args.callee.hashCode) {
              hashcode = String(to_print.args.callee.hashCode());
            }
          } catch (e) {}

          return {
            "crypto": JSON.stringify({
              "class_name": clazz,
              "method_name": "update",
              "args": [inputBase64],
              "ret": outputBase64,
              "hashcode": hashcode,
              "stackTrace": getStackTraceSafe()
            })
          };
        } catch (e) {
          console.log("Error formatting Cipher.update: " + e);
          return null;
        }
      }
    }

    // ========== 2. javax.crypto.spec.SecretKeySpec ==========
    else if (clazz === "javax.crypto.spec.SecretKeySpec") {
      if (method === "$init" || method === "<init>") {
        try {
          var keyBytes = to_print.args[0];
          var algorithm = to_print.args[1];

          return {
            "key-iv": JSON.stringify({
              "class_name": clazz,
              "method_name": "$new",
              "args": [toBase64Safe(keyBytes), String(algorithm)],
              "ret": ""
            })
          };
        } catch (e) {
          console.log("Error formatting SecretKeySpec: " + e);
          return null;
        }
      }
    }

    // ========== 3. javax.crypto.spec.IvParameterSpec ==========
    else if (clazz === "javax.crypto.spec.IvParameterSpec") {
      if (method === "$init" || method === "<init>") {
        try {
          var ivBytes = to_print.args[0];

          return {
            "key-iv": JSON.stringify({
              "class_name": clazz,
              "method_name": "$new",
              "args": [toBase64Safe(ivBytes)],
              "ret": ""
            })
          };
        } catch (e) {
          console.log("Error formatting IvParameterSpec: " + e);
          return null;
        }
      }
    }

    // ========== 4. 第三方加密库 ==========
    else if (method.toLowerCase().indexOf("encrypt") !== -1 ||
             method.toLowerCase().indexOf("decrypt") !== -1) {
      try {
        var args = to_print.args;
        var argsBase64 = convertArgsToBase64(args);
        var retBase64 = toBase64Safe(retval);

        return {
          "crypto": JSON.stringify({
            "class_name": clazz,
            "method_name": method,
            "args": argsBase64,
            "ret": retBase64,
            "stackTrace": getStackTraceSafe()
          })
        };
      } catch (e) {
        console.log("Error formatting 3rd party crypto: " + e);
        return null;
      }
    }

  } catch (e) {
    console.log("Error in formatCryptoMessage: " + e);
  }

  // 不是加密相关的调用
  return null;
}

// ========== 原有函数保持不变 ==========

function nativedynamichook(hook, category) {
  Interceptor.attach(
    Module.findExportByName(hook["clazz"], hook["method"]), {
      onEnter: function (args) {
        var file = Memory.readCString(args[0]);
        if (hook["clazz"] == "libc.so" &&
          hook["method"] == "open" &&
          !file.includes("/dev/ashmem") &&
          !file.includes("/proc/"))
          send("API Monitor - " + category + " - " + hook["clazz"] + " - " + hook["method"] + " - " + file);
      }
    }
  );
}

function javadynamichook(hook, category, callback) {
  var Exception = Java.use('java.lang.Exception');
  var toHook;
  try {
    var clazz = hook.clazz;
    var method = hook.method;

    try {
      if (hook.target &&
        parseInt(Java.androidVersion, 10) < hook.target) {
        send('API Monitor - Android Version not supported - Cannot hook - ' + clazz + '.' + method)
        return
      }

      toHook = Java.use(clazz)[method];
      if (!toHook) {
        send('API Monitor - Cannot find ' + clazz + '.' + method);
        return
      }
    } catch (err) {
      send('API Monitor - Cannot find ' + clazz + '.' + method);
      return
    }

    for (var i = 0; i < toHook.overloads.length; i++) {
      toHook.overloads[i].implementation = function () {
        var args = [].slice.call(arguments);
        var retval = this[method].apply(this, arguments);

        if (callback) {
          var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
          var to_print = {
            category: category,
            class: clazz,
            method: method,
            args: args,
            calledFrom: calledFrom
          };
          retval = callback(retval, to_print);
        }
        return retval;
      }
    }
  } catch (err) {
    send('API Monitor - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
  }
}