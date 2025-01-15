# 配置会话过期时间
from datetime import timedelta
import basic
time = basic.select_session_time_lib(1)

# 出现前端传入非整数时，自动更新会话超时时间为60秒
try:
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(time))
except:
    basic.update_session_time_lib(60,1)