"""
配置文件 - 存放路径常量、阈值配置、告警地址等全局设置
"""

import os

# 获取脚本所在目录的绝对路径
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 路径约束
INPUT_DIR = os.path.join(BASE_DIR, 'http_logs')
OUTPUT_DIR = os.path.join(BASE_DIR, 'analysis_output')

# 输出文件名
STATS_REPORT_FILE = 'stats_report.json'
ANALYSIS_SUMMARY_FILE = 'analysis_summary.md'

# 增量处理记录文件
PROCESSED_FILES_RECORD = os.path.join(OUTPUT_DIR, '.processed_files.json')

# 文件过滤规则
ALLOWED_EXTENSIONS = ('.log', '.txt')
IGNORE_PATTERN = 'ignore_*.log'

# 异常检测阈值配置
THRESHOLDS = {
    # 高频IP检测: 10分钟内请求次数超过阈值
    'high_freq_ip': {
        'time_window_minutes': 10,
        'max_requests': 100,
    },
    # 5xx错误占比阈值
    'server_error_rate': {
        'time_window_minutes': 10,
        'max_error_rate': 0.10,  # 10%
    },
    # 慢速请求阈值(秒)
    'slow_request': {
        'max_response_time': 5.0,
    },
}

# 告警配置
ALERT_CONFIG = {
    # 企业微信机器人配置
    'wechat': {
        'enabled': False,
        'webhook_url': '',  # 企业微信机器人Webhook地址
    },
    # 钉钉机器人配置
    'dingtalk': {
        'enabled': False,
        'webhook_url': '',  # 钉钉机器人Webhook地址
        'secret': '',  # 钉钉机器人密钥(可选)
    },
    # 告警日志文件
    'log_file': os.path.join(OUTPUT_DIR, 'alert.log'),
}

# Nginx Combined Log Format 正则表达式
# 格式: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
NGINX_LOG_PATTERN = r'''
    ^(?P<ip>\S+)\s+                    # 客户端IP
    -\s+                                # 占位符
    (?P<user>\S+)\s+                    # 远程用户
    \[(?P<timestamp>[^\]]+)\]\s+        # 时间戳
    "(?P<method>\S+)\s+                 # 请求方法
    (?P<url>\S+)\s+                     # URL
    (?P<protocol>[^"]*)"\s+             # 协议
    (?P<status>\d+)\s+                  # 状态码
    (?P<bytes>\d+)\s+                   # 响应字节数
    "(?P<referer>[^"]*)"\s+             # Referer
    "(?P<user_agent>[^"]*)"             # User-Agent
    (?:\s+(?P<response_time>[\d.]+))?   # 响应时间(可选)
'''

# 时间格式
TIME_FORMAT = '%d/%b/%Y:%H:%M:%S %z'

# 统计配置
STATS_CONFIG = {
    'top_ips_limit': 20,           # Top IP数量
    'top_urls_limit': 20,          # Top URL数量
    'status_code_distribution': True,  # 状态码分布
    'response_time_percentiles': [50, 90, 95, 99],  # 响应时间分位数
}
