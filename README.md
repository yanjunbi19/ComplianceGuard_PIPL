# 安卓隐私违规检测系统使用说明

本项目用于对安卓应用的隐私政策声明和实际运行行为进行联合分析，检测隐私政策内容缺失、同意前收集、第三方 SDK 未披露访问、模糊披露等问题。系统由三部分组成：隐私政策解析、动态探索与行为分析、合规规则检测。

## 1. 项目结构

```text
Explorer/                动态探索、敏感 API 监控、流量采集与 leak.json 生成
privacypolicy/           隐私政策分类、信息抽取、评估脚本
ui/                      图形界面、政策分析、行为分析、合规检测整合
ui/res/                  UI 运行所需的小型资源文件
README.md                使用说明
```

## 2. 检测规则

当前合规检测规则主要在 `ui/compliance_checker.py` 中实现，规则编号为 R1-R8：

| 规则 | 名称 | 含义 |
| --- | --- | --- |
| R1 | 结构完整性缺失 | 隐私政策缺少核心模块，如政策适用范围、收集使用规则、第三方共享、用户权利、存储、更新机制等。 |
| R2 | 信息来源缺失 | 政策声明了处理的个人信息类别，但没有说明个人信息来源。 |
| R3 | 存储生命周期缺失 | 政策存在数据存储相关声明，但缺少存储时长或存储地点。 |
| R4 | 用户核心权利缺失 | 政策涉及用户权利，但缺少查询、更正、删除、撤回同意、注销等核心权利说明。 |
| R5 | 政策更新机制缺失 | 隐私政策未包含政策更新机制。 |
| R6 | 未经同意收集 | 在用户点击同意前，动态行为证据中已经出现个人信息 API 访问。 |
| R7 | 违规扩散 | 实际参与个人信息处理的第三方 SDK 未在隐私政策中披露参与事实或接收方。 |
| R8 | 模糊披露 | 隐私政策仅披露信息大类，但动态分析发现访问了更细粒度的个人信息项。 |

R1-R5 主要基于隐私政策解析结果判断；R6-R8 需要结合动态探索生成的行为证据，尤其是 `Explorer/analysis/<algo>/<app>/leak.json`。

## 3. UI 使用方式

UI 是推荐入口，适合把隐私政策分析、APK 静态分析、动态沙箱和违规检测串起来执行。

启动图形界面：

```powershell
cd G:\iie\mylab\guitest\ui
python main.py
```

UI 默认读取：

```text
G:\iie\mylab\guitest\ui\config.json
```

`ui/config.json` 是本机运行配置，需要自行修改

界面中可上传 APK、隐私政策 HTML，或二者同时上传。三类分析相互独立：

1. 隐私政策分析读取 HTML，输出条款分类和 LLM 结构化抽取结果。
2. 静态分析读取 APK 或已有缓存。若 `Explorer/apps/ap1/apinfo/<apk文件名>.json`、`Explorer/hooks/<apk文件名>.json` 已存在，则直接复用缓存，也视为静态分析完成。
3. 动态沙箱调用 `Explorer/explore33.py` 采集原始行为证据，并在 `run_leak_analysis` 为 `true` 时自动调用 `Explorer/anal5.py` 生成 `leak.json`。

违规检测只在隐私政策、静态分析、动态沙箱三项都完成后执行；如果缺少任一项，UI 会显示缺少的分析步骤，不会强行生成违规结论。

### 3.1 `ui/config.json` 参数说明

```json
{
  "classifier": {
    "model_path": "G:\\iie\\mylab\\guitest\\Explorer\\basemodel\\checkpoint-25685",
    "csv_label_path": "G:\\iie\\mylab\\guitest\\ui\\res\\idlable.csv",
    "removed_ids": [6, 7, 8, 9, 10, 11],
    "thresholds_path": "G:\\iie\\mylab\\guitest\\ui\\res\\optimal_thresholds.npy",
    "batch_size": 64,
    "device": null,
    "reuse_predictions": true
  },
  "llm": {
    "enabled": true,
    "model_name": "glm-4-plus",
    "use_dynamic_rag": false,
    "kb_path": null,
    "reuse_cache": true,
    "api_keys": {
      "dashscope": null,
      "glm": null,
      "deepseek": null
    }
  },
  "dynamic_explorer": {
    "script_path": "G:\\iie\\mylab\\guitest\\Explorer\\explore33.py",
    "leak_analyzer_script": "G:\\iie\\mylab\\guitest\\Explorer\\anal5.py",
    "run_leak_analysis": true,
    "leak_analysis_timeout_sec": 300,
    "algo": "sac",
    "iterations": 50,
    "episods": 1,
    "stage": 2,
    "platform_version": "12",
    "udid": "a6a635a42b72c75b",
    "device_name": "Pixel5",
    "apps_explored": "G:\\iie\\mylab\\guitest\\Explorer\\apps\\testapp_end",
    "layout_model": null,
    "memory_capacity": 32,
    "num_actions": 200
  },
  "ui": {
    "analysis_order": ["policy", "static", "dynamic"]
  }
}
```

| 参数 | 说明 |
| --- | --- |
| `classifier.model_path` | 隐私政策条款分类模型目录。模型文件已放在项目目录中，保持该路径指向实际 checkpoint 目录即可。 |
| `classifier.csv_label_path` | 标签映射文件，默认使用 `ui/res/idlable.csv`。 |
| `classifier.removed_ids` | 分类时排除的标签 ID 列表。 |
| `classifier.thresholds_path` | 多标签分类阈值文件，默认使用 `ui/res/optimal_thresholds.npy`。 |
| `classifier.batch_size` | 分类推理批大小。显存不足时可调小。 |
| `classifier.device` | 推理设备。`null` 表示由代码自动选择；也可设置为 `cpu`、`cuda` 等。 |
| `classifier.reuse_predictions` | 若输出目录已有分类结果，是否复用缓存。 |
| `llm.enabled` | 是否启用大模型实体抽取。关闭后 R7/R8 可能因政策侧证据不足而无法完整判断。 |
| `llm.model_name` | 使用的大模型名称，如 `glm-4-plus`、`qwen-plus`、`deepseek` 相关模型名。 |
| `llm.use_dynamic_rag` | 是否启用动态 RAG。 |
| `llm.kb_path` | RAG 知识库路径，不使用时为 `null`。 |
| `llm.reuse_cache` | 是否复用已有 `llm_extraction_results.jsonl`。 |
| `llm.api_keys.dashscope` | 通义千问/DashScope API Key，使用 `qwen-plus` 等模型时填写。 |
| `llm.api_keys.glm` | 智谱 GLM API Key，使用 `glm-4-plus` 等模型时填写。 |
| `llm.api_keys.deepseek` | DeepSeek API Key，使用 DeepSeek 模型时填写。 |
| `dynamic_explorer.script_path` | UI 启动动态探索时调用的脚本，默认是 `Explorer/explore33.py`。 |
| `dynamic_explorer.leak_analyzer_script` | 动态探索结束后用于生成 `leak.json` 的汇总脚本，默认是 `Explorer/anal5.py`。 |
| `dynamic_explorer.run_leak_analysis` | 是否在动态探索结束后自动运行 `anal5.py` 生成 `leak.json`；违规检测需要该文件作为行为证据。 |
| `dynamic_explorer.leak_analysis_timeout_sec` | `anal5.py` 汇总分析的等待超时时间。超时后若 `leak.json` 已生成，UI 会继续加载该文件，不再无限等待。 |
| `dynamic_explorer.algo` | UI 启动探索时使用的算法，支持 `sac`、`dqn`、`random`、`Q`。 |
| `dynamic_explorer.iterations` | 单个应用探索轮数；原先 UI 中硬编码的 `50` 已移到这里。 |
| `dynamic_explorer.episods` | 探索 episode 数。 |
| `dynamic_explorer.stage` | 探索阶段，`1` 表示未登录/首次运行阶段，`2` 表示登录态或保留状态阶段。 |
| `dynamic_explorer.platform_version` | Appium/设备参数中的 Android 版本。 |
| `dynamic_explorer.udid` | 设备序列号或无线调试地址。 |
| `dynamic_explorer.device_name` | 设备名称。 |
| `dynamic_explorer.apps_explored` | 探索完成后的 APK 记录或移动目录。 |
| `dynamic_explorer.layout_model` | 布局编码模型路径，不使用时为 `null`。 |
| `dynamic_explorer.memory_capacity` | DQN 经验池容量配置。 |
| `dynamic_explorer.num_actions` | 动作空间大小，SAC/DQN 策略会使用。 |
| `ui.analysis_order` | UI 中各分析任务的执行顺序。默认 `["policy", "static", "dynamic"]`；如需先跑动态沙箱，可改为 `["dynamic", "static", "policy"]`。违规检测不受该顺序影响，只有隐私政策、静态分析、动态沙箱三项都完成后才执行。 |

如果启用 LLM，推荐在 `llm.api_keys` 中填写对应 API Key；也可以继续使用环境变量 `GLM_API_KEY`、`DASHSCOPE_API_KEY` 或 `DEEPSEEK_API_KEY`。

## 4. 命令行检测脚本

若已经有政策解析结果和动态分析结果，可直接运行检测脚本。常用入口有两个：

### 4.1 规则 R6-R8 手动测试

```powershell
cd G:\iie\mylab\guitest\ui
python manual_test_r678.py `
  --policy result\com.example.app\llm_extraction_results.jsonl `
  --behavior ..\Explorer\analysis\sac\com.example.app\leak.json `
  --package com.example.app `
  --output r678_test_result.json
```

该脚本主要用于快速检查 R6、R7、R8，便于调试政策抽取结果和 `leak.json` 行为证据是否能正确对齐。

### 4.2 完整政策-行为对比检测

`ui/rule.py` 提供命令行检测入口，输入政策声明、行为分析结果以及类别映射配置：

```powershell
cd G:\iie\mylab\guitest\ui
python rule.py `
  --declaration result\com.example.app\llm_extraction_results.jsonl `
  --behavior ..\Explorer\analysis\sac\com.example.app\leak.json `
  --it-info ..\Explorer\analysis\it_info.json `
  --device-info ..\Explorer\analysis\device_info.json `
  --sdk-list ..\Explorer\analysis\sdk_info.json `
  --output violation_report `
  --format json text csv
```

主要输入说明：

| 参数 | 说明 |
| --- | --- |
| `--declaration` | 隐私政策解析结果，通常是 `llm_extraction_results.jsonl`。 |
| `--behavior` | 动态行为分析结果，即 `leak.json`。 |
| `--it-info` | 个人信息类别定义文件。 |
| `--device-info` | 设备字段与个人信息类别映射文件。 |
| `--sdk-list` | SDK 列表或 SDK 识别结果，可选。 |
| `--output` | 输出报告文件名前缀。 |
| `--format` | 输出格式，支持 `json`、`text`、`csv`。 |

## 5. 动态探索与 `leak.json` 生成

`leak.json` 是后续 R6-R8 检测的重要行为证据，来源于动态探索、敏感 API 监控、网络流量解析和 SDK 归因。

### 5.1 动态探索入口

动态探索的主要入口为：

```text
Explorer/explore33.py
```

该脚本负责批量安装待测 APK、启动 UI 自动探索、接入敏感 API 监控和网络流量采集，并按探索阶段生成后续行为分析所需的原始证据。探索结果默认写入：

```text
Explorer/analysis/<algo>/<app_name>/
```

`--apps` 可以是 APK 目录，也可以是单个 APK 文件路径。UI 上传单个 APK 时就是按单文件路径调用该脚本。

示例：

```powershell
cd G:\iie\mylab\guitest\Explorer
python explore33.py `
  --apps apps\testapp `
  --apps_explored apps\testapp_end `
  --algo sac `
  --iterations 600 `
  --episods 1 `
  --stage 2 `
  --udid a6a635a42b72c75b `
  --device_name Pixel5 `
  --platform_version 12
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--apps` | 待检测 APK 目录或单个 APK 文件。 |
| `--apps_explored` | 探索完成后 APK 移动或记录目录。 |
| `--algo` | 探索策略，支持 `sac`、`dqn`、`random`、`Q`。 |
| `--iterations` | 单个应用探索轮数。 |
| `--episods` | 探索 episode 数。 |
| `--stage` | 探索阶段，`1` 表示未登录/首次运行阶段，`2` 表示登录态或保留状态阶段。 |
| `--layout_model` | 布局编码模型路径。 |
| `--num_actions` | 动作空间大小，SAC/DQN 策略会使用。 |

### 5.2 设备与代理配置

动态探索读取 `Explorer/config.py`：

```python
ADB_DEVICE = "192.168.101.11:5555"
DEFAULT_MITM_PORT = 8080
MITM_PORT_BY_DEVICE = {
    "192.168.1.105:5555": 8080,
    "192.168.1.109:5555": 8081,
}
```

需要根据本机环境修改：

| 参数 | 说明 |
| --- | --- |
| `ADB_DEVICE` | ADB 设备序列号，使用 `adb devices` 查看。无线调试通常形如 `ip:port`。 |
| `DEFAULT_MITM_PORT` | 默认 mitmproxy 监听端口，设计上用于单设备或未命中设备映射时的兜底端口。 |
| `MITM_PORT_BY_DEVICE` | 多设备并行时的端口映射，设计上用于按 `ADB_DEVICE` 为不同设备分配不同 mitmproxy 端口。 |
| `duration` | 动态监控持续时间相关配置。 |
| `Device_resolution_x/y` | 设备分辨率，用于 UI 坐标和截图逻辑。 |
| `MAX_EPISODE_STEPS` | 单个 episode 最大步数。 |

当前代码中需要特别注意端口的实际生效位置：`Explorer/explore33.py` 会读取 `config.ADB_DEVICE`，但网络监控由 `Explorer/utils/network.py` 启动；该文件目前将 `MITMPROXY_PORT` 固定为 `8080`，并未实际读取 `DEFAULT_MITM_PORT` 或 `MITM_PORT_BY_DEVICE`。因此，在现有实现下，mitmproxy、`adb reverse` 和代理连通性检查使用的是 `8080`。如果需要多设备并行，应先将 `Explorer/utils/network.py` 中的端口选择逻辑改为按设备读取 `MITM_PORT_BY_DEVICE`，未命中时再回退到 `DEFAULT_MITM_PORT`。

动态探索前通常需要准备：

1. 设备或模拟器可通过 ADB 连接。
2. 设备已配置代理和证书，便于 mitmproxy 捕获 HTTPS 流量。
3. frida-server、uiautomator/ATX 等运行组件可用。
4. APK 放入 `Explorer/apps/...` 或命令行 `--apps` 指定目录。

### 5.3 `leak.json` 分析脚本

探索阶段会在应用目录下产生 API 调用、抓包、文件系统监控等原始结果。`leak.json` 的汇总分析逻辑主要在：

```text
Explorer/anal5.py
```

单独运行示例：

```powershell
cd G:\iie\mylab\guitest\Explorer
python anal5.py `
  --path analysis\sac `
  --app com.example.app `
  --sdk-info analysis\sdk_info.json `
  --device-info analysis\device_info.json
```

主要参数：

| 参数 | 说明 |
| --- | --- |
| `--path` | 动态探索输出的算法目录，如 `Explorer/analysis/sac`。 |
| `--app` | 需要汇总的应用目录名，通常是包名。建议显式指定，避免使用脚本内置示例值。 |
| `--sdk-info` | SDK 识别信息文件，默认使用 `Explorer/analysis/sdk_info.json`。 |
| `--device-info` | 设备字段与个人信息类别映射文件，默认使用 `Explorer/analysis/device_info.json`。 |

该脚本会读取动态探索输出目录中的内容，例如：

```text
mitmdump-1.mitm / mitmdump-2.mitm
crypt-*.txt
fs-*.txt
permission-*.txt
api_privacy_full.json
api_privacy_summary.json
```

并输出：

```text
Explorer/analysis/<algo>/<app_name>/leak.json
Explorer/analysis/<algo>/<app_name>/analysis_report.txt
```

`leak.json` 中通常包含：

| 字段 | 说明 |
| --- | --- |
| `package` | 应用包名或分析目录名。 |
| `analysis_time` | 汇总分析时间。 |
| `summary` | 按信息类别、host、SDK、明文/加密、出入站方向等聚合的摘要。 |
| `leak_by_source` | 按 App 自身、第三方、未知来源、本地文件等来源归类的泄露记录。 |
| `records` | 标准化后的隐私泄露记录，是 R6-R8 的主要行为证据。 |
| `api_traffic_correlations` | API 调用和网络流量的时间窗口关联结果。 |

如果 API 隐私调用分析有结果，同一目录下还会生成：

```text
api_privacy_summary.json
api_privacy_full.json
```

完整流程可以理解为：

```text
APK
  -> Explorer/explore33.py 动态探索
  -> Monitor / Frida / UIAutomator 收集流量、API、文件系统和 UI 事件
  -> Explorer/analysis/<algo>/<app_name>/ 原始结果
  -> Explorer/anal5.py 汇总分析
  -> leak.json
  -> ui/compliance_checker.py 或 ui/rule.py 执行 R1-R8 检测
```

## 6. 典型使用流程

### 6.1 UI 流程

1. 检查 `ui/config.json`，确认模型路径、LLM Key、动态探索算法、探索轮数和 `analysis_order`。
2. 检查 `Explorer/config.py`，确认 `ADB_DEVICE`、设备分辨率和监控时长等运行环境参数。
3. 启动 UI，上传 APK 和隐私政策 HTML。
4. 点击开始检测。UI 会按 `ui.analysis_order` 执行隐私政策、静态、动态分析。
5. 动态沙箱完成后，UI 会自动调用 `Explorer/anal5.py` 生成或加载 `leak.json`。
6. 当隐私政策、静态分析、动态分析三项都完成后，UI 自动执行 R1-R8 违规检测。

### 6.2 命令行流程

1. 将待测 APK 放入 `Explorer/apps/testapp`，或在 `--apps` 中直接传入单个 APK 文件路径。
2. 运行 `Explorer/explore33.py` 进行动态探索。
3. 运行 `Explorer/anal5.py` 将探索结果汇总为 `leak.json`。
4. 使用 UI 生成隐私政策解析结果，或直接准备 `llm_extraction_results.jsonl`。
5. 使用 `ui/rule.py` 或 `ui/manual_test_r678.py` 进行合规检测。
