# 配置会话过期时间
from datetime import timedelta
import basic
time = basic.select_session_time_lib(1)
PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(time))