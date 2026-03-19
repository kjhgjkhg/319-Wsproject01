"""
HTTP 日志分析与告警系统 - 全局配置模块

该模块定义了系统的所有配置常量，包括路径、阈值、告警设置等。
所有配置项均可通过修改此文件进行调整，无需修改核心业务代码。
"""

import os
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent.parent


INPUT_DIR = SCRIPT_DIR / "http_logs"
OUTPUT_DIR = SCRIPT_DIR / "analysis_output"


STATS_REPORT_FILE = "stats_report.json"
ANALYSIS_SUMMARY_FILE = "analysis_summary.md"
HASH_RECORD_FILE = ".processed_files.json"


ALLOWED_EXTENSIONS = {".log", ".txt"}
IGNORE_PREFIX = "ignore_"


HIGH_FREQ_IP_THRESHOLD = 100
HIGH_FREQ_TIME_WINDOW = 600


ERROR_RATE_THRESHOLD = 0.10


SLOW_REQUEST_THRESHOLD = 5.0


STATS_TIME_WINDOW = 3600


ALERT_CONFIG = {
    "enabled": True,
    "wechat_webhook": "",
    "dingtalk_webhook": "",
    "alert_types": {
        "high_freq_ip": True,
        "error_spike": True,
        "slow_request": True,
    },
    "alert_cooldown": 300,
}


LOG_PATTERNS = {
    "nginx_combined": r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"(?:\s+(?P<response_time>[\d.]+))?',
    "nginx_with_time": r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s+(?P<response_time>[\d.]+)',
}


DATETIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
]


def ensure_directories() -> None:
    """
    确保输入和输出目录存在。
    
    如果目录不存在，将自动创建。
    """
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_output_path(filename: str) -> Path:
    """
    获取输出文件的完整路径。
    
    Args:
        filename: 输出文件名
        
    Returns:
        输出文件的完整路径
    """
    return OUTPUT_DIR / filename


def update_threshold(high_freq_ip: int = None, error_rate: float = None, 
                     slow_request: float = None) -> None:
    """
    动态更新阈值配置。
    
    Args:
        high_freq_ip: 高频 IP 阈值（次/时间窗口）
        error_rate: 错误率阈值（百分比，如 0.10 表示 10%）
        slow_request: 慢请求阈值（秒）
    """
    global HIGH_FREQ_IP_THRESHOLD, ERROR_RATE_THRESHOLD, SLOW_REQUEST_THRESHOLD
    
    if high_freq_ip is not None:
        HIGH_FREQ_IP_THRESHOLD = high_freq_ip
    if error_rate is not None:
        ERROR_RATE_THRESHOLD = error_rate
    if slow_request is not None:
        SLOW_REQUEST_THRESHOLD = slow_request


def update_alert_webhook(wechat: str = None, dingtalk: str = None) -> None:
    """
    动态更新告警 Webhook 地址。
    
    Args:
        wechat: 企业微信机器人 Webhook 地址
        dingtalk: 钉钉机器人 Webhook 地址
    """
    if wechat is not None:
        ALERT_CONFIG["wechat_webhook"] = wechat
    if dingtalk is not None:
        ALERT_CONFIG["dingtalk_webhook"] = dingtalk
