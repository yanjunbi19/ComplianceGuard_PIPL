thread_life = True
frida_ready = False
TIMER = None
api_trigged_list = set()
duration = 1200
Device_resolution_x = 1080
Device_resolution_y = 1920
MAX_EPISODE_STEPS=200
GLOBAL_APP_INSTANCE = None
MANUAL_MODE = False
app_first_run_done = {}   # 记录每个 App 的首次启动是否完成
ADB_DEVICE= "192.168.43.51:5555"
DEFAULT_MITM_PORT = 8080


frida_last_error = ""
frida_hard_failed = False
frida_last_ok_ts = 0.0
frida_current_package = ""
