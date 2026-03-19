"""
告警推送工具模块

该模块封装告警推送功能，支持：
- 企业微信机器人
- 钉钉机器人
- 告警日志记录
"""

import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import ALERT_CONFIG, OUTPUT_DIR, get_output_path, ensure_directories


@dataclass
class AlertMessage:
    """
    告警消息数据类。
    
    Attributes:
        title: 告警标题
        content: 告警内容
        level: 告警级别（info/warning/error/critical）
        anomaly_type: 异常类型
        timestamp: 告警时间
    """
    title: str
    content: str
    level: str = "warning"
    anomaly_type: str = "unknown"
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式。
        
        Returns:
            包含所有字段的字典
        """
        return {
            'title': self.title,
            'content': self.content,
            'level': self.level,
            'anomaly_type': self.anomaly_type,
            'timestamp': self.timestamp.isoformat()
        }


class AlertLogger:
    """
    告警日志记录器。
    
    将告警信息记录到本地文件。
    """
    
    ALERT_LOG_FILE = "alert_history.log"
    
    def __init__(self, log_path: Optional[Path] = None):
        """
        初始化日志记录器。
        
        Args:
            log_path: 日志文件路径，默认使用输出目录
        """
        self.log_path = log_path or get_output_path(self.ALERT_LOG_FILE)
        ensure_directories()
    
    def log(self, message: AlertMessage, success: bool = True, 
            channel: str = "", error: str = "") -> None:
        """
        记录告警日志。
        
        Args:
            message: 告警消息对象
            success: 是否发送成功
            channel: 发送渠道
            error: 错误信息
        """
        log_entry = {
            'timestamp': message.timestamp.isoformat(),
            'level': message.level,
            'anomaly_type': message.anomaly_type,
            'title': message.title,
            'content': message.content,
            'channel': channel,
            'success': success,
            'error': error
        }
        
        log_line = json.dumps(log_entry, ensure_ascii=False)
        
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(log_line + '\n')
        except IOError as e:
            print(f"警告：无法写入告警日志: {e}")


class WeChatNotifier:
    """
    企业微信机器人通知器。
    
    通过企业微信机器人 Webhook 发送告警消息。
    """
    
    def __init__(self, webhook_url: Optional[str] = None):
        """
        初始化通知器。
        
        Args:
            webhook_url: 企业微信机器人 Webhook 地址
        """
        self.webhook_url = webhook_url or ALERT_CONFIG.get('wechat_webhook', '')
    
    def _build_markdown_message(self, message: AlertMessage) -> Dict[str, Any]:
        """
        构建 Markdown 格式消息。
        
        Args:
            message: 告警消息对象
            
        Returns:
            企业微信消息格式字典
        """
        level_emoji = {
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '❌',
            'critical': '🔴'
        }
        
        emoji = level_emoji.get(message.level, '⚠️')
        
        content = f"""{emoji} **{message.title}**

> 类型: {message.anomaly_type}
> 级别: {message.level}
> 时间: {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

{message.content}
"""
        
        return {
            "msgtype": "markdown",
            "markdown": {
                "content": content
            }
        }
    
    def send(self, message: AlertMessage) -> tuple:
        """
        发送告警消息到企业微信。
        
        Args:
            message: 告警消息对象
            
        Returns:
            (是否成功, 错误信息) 元组
        """
        if not self.webhook_url:
            return False, "企业微信 Webhook 未配置"
        
        payload = self._build_markdown_message(message)
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'HTTP-Log-Analyzer/1.0'
        }
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                if result.get('errcode', 0) == 0:
                    return True, ""
                else:
                    return False, result.get('errmsg', '未知错误')
                    
        except urllib.error.URLError as e:
            return False, f"网络错误: {e}"
        except urllib.error.HTTPError as e:
            return False, f"HTTP 错误: {e.code} {e.reason}"
        except json.JSONDecodeError as e:
            return False, f"响应解析错误: {e}"
        except Exception as e:
            return False, f"未知错误: {e}"


class DingTalkNotifier:
    """
    钉钉机器人通知器。
    
    通过钉钉机器人 Webhook 发送告警消息。
    """
    
    def __init__(self, webhook_url: Optional[str] = None):
        """
        初始化通知器。
        
        Args:
            webhook_url: 钉钉机器人 Webhook 地址
        """
        self.webhook_url = webhook_url or ALERT_CONFIG.get('dingtalk_webhook', '')
    
    def _build_markdown_message(self, message: AlertMessage) -> Dict[str, Any]:
        """
        构建 Markdown 格式消息。
        
        Args:
            message: 告警消息对象
            
        Returns:
            钉钉消息格式字典
        """
        level_emoji = {
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '❌',
            'critical': '🔴'
        }
        
        emoji = level_emoji.get(message.level, '⚠️')
        
        content = f"""{emoji} **{message.title}**

- 类型: {message.anomaly_type}
- 级别: {message.level}
- 时间: {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

{message.content}
"""
        
        return {
            "msgtype": "markdown",
            "markdown": {
                "title": message.title,
                "text": content
            }
        }
    
    def send(self, message: AlertMessage) -> tuple:
        """
        发送告警消息到钉钉。
        
        Args:
            message: 告警消息对象
            
        Returns:
            (是否成功, 错误信息) 元组
        """
        if not self.webhook_url:
            return False, "钉钉 Webhook 未配置"
        
        payload = self._build_markdown_message(message)
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'HTTP-Log-Analyzer/1.0'
        }
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                if result.get('errcode', 0) == 0:
                    return True, ""
                else:
                    return False, result.get('errmsg', '未知错误')
                    
        except urllib.error.URLError as e:
            return False, f"网络错误: {e}"
        except urllib.error.HTTPError as e:
            return False, f"HTTP 错误: {e.code} {e.reason}"
        except json.JSONDecodeError as e:
            return False, f"响应解析错误: {e}"
        except Exception as e:
            return False, f"未知错误: {e}"


class AlertManager:
    """
    告警管理器。
    
    整合多种通知渠道，提供统一的告警发送接口。
    """
    
    def __init__(self):
        """初始化告警管理器。"""
        self.logger = AlertLogger()
        self.wechat = WeChatNotifier()
        self.dingtalk = DingTalkNotifier()
        self._last_alert_time: Dict[str, datetime] = {}
    
    def _should_send_alert(self, anomaly_type: str) -> bool:
        """
        检查是否应该发送告警（基于冷却时间）。
        
        Args:
            anomaly_type: 异常类型
            
        Returns:
            是否应该发送告警
        """
        cooldown = ALERT_CONFIG.get('alert_cooldown', 300)
        
        if anomaly_type in self._last_alert_time:
            elapsed = (datetime.now() - self._last_alert_time[anomaly_type]).total_seconds()
            if elapsed < cooldown:
                return False
        
        return True
    
    def _update_alert_time(self, anomaly_type: str) -> None:
        """
        更新告警时间记录。
        
        Args:
            anomaly_type: 异常类型
        """
        self._last_alert_time[anomaly_type] = datetime.now()
    
    def send_alert(self, message: AlertMessage) -> Dict[str, Any]:
        """
        发送告警消息。
        
        Args:
            message: 告警消息对象
            
        Returns:
            发送结果字典
        """
        if not ALERT_CONFIG.get('enabled', False):
            return {'sent': False, 'reason': '告警功能已禁用'}
        
        alert_types = ALERT_CONFIG.get('alert_types', {})
        if not alert_types.get(message.anomaly_type, True):
            return {'sent': False, 'reason': f'{message.anomaly_type} 类型告警已禁用'}
        
        if not self._should_send_alert(message.anomaly_type):
            return {'sent': False, 'reason': '告警冷却中'}
        
        results = {
            'sent': False,
            'channels': {},
            'errors': []
        }
        
        success, error = self.wechat.send(message)
        results['channels']['wechat'] = {'success': success, 'error': error}
        self.logger.log(message, success, 'wechat', error)
        if success:
            results['sent'] = True
        elif error and "未配置" not in error:
            results['errors'].append(f"企业微信: {error}")
        
        success, error = self.dingtalk.send(message)
        results['channels']['dingtalk'] = {'success': success, 'error': error}
        self.logger.log(message, success, 'dingtalk', error)
        if success:
            results['sent'] = True
        elif error and "未配置" not in error:
            results['errors'].append(f"钉钉: {error}")
        
        if results['sent']:
            self._update_alert_time(message.anomaly_type)
        
        return results
    
    def send_batch_alerts(self, messages: List[AlertMessage]) -> List[Dict[str, Any]]:
        """
        批量发送告警消息。
        
        Args:
            messages: 告警消息列表
            
        Returns:
            发送结果列表
        """
        return [self.send_alert(msg) for msg in messages]


def create_alert_from_anomaly(anomaly: Dict[str, Any]) -> AlertMessage:
    """
    从异常检测结果创建告警消息。
    
    Args:
        anomaly: 异常检测结果字典
        
    Returns:
        告警消息对象
    """
    level_map = {
        'low': 'info',
        'medium': 'warning',
        'high': 'error',
        'critical': 'critical'
    }
    
    anomaly_type = anomaly.get('anomaly_type', 'unknown')
    severity = anomaly.get('severity', 'warning')
    description = anomaly.get('description', '检测到异常')
    details = anomaly.get('details', {})
    
    title_map = {
        'high_freq_ip': '高频 IP 访问告警',
        'error_spike': '服务器错误激增告警',
        'slow_request': '慢速请求告警'
    }
    
    title = title_map.get(anomaly_type, 'HTTP 日志异常告警')
    
    content_parts = [description]
    
    if anomaly_type == 'high_freq_ip' and 'ip' in details:
        content_parts.append(f"\n**IP 地址**: {details['ip']}")
        content_parts.append(f"**请求次数**: {details.get('request_count', 'N/A')}")
        content_parts.append(f"**时间窗口**: {details.get('time_window_seconds', 'N/A')} 秒")
    elif anomaly_type == 'error_spike' and 'time_bucket' in details:
        content_parts.append(f"\n**时间段**: {details['time_bucket']}")
        content_parts.append(f"**错误率**: {details.get('error_rate', 0) * 100:.1f}%")
        content_parts.append(f"**5xx 数量**: {details.get('5xx_count', 'N/A')}")
    elif anomaly_type == 'slow_request' and 'url' in details:
        content_parts.append(f"\n**URL**: {details['url']}")
        content_parts.append(f"**慢请求数量**: {details.get('slow_request_count', 'N/A')}")
        content_parts.append(f"**平均响应时间**: {details.get('avg_response_time', 'N/A')}s")
    
    return AlertMessage(
        title=title,
        content='\n'.join(content_parts),
        level=level_map.get(severity, 'warning'),
        anomaly_type=anomaly_type
    )


def send_anomaly_alerts(anomalies: Dict[str, List]) -> Dict[str, Any]:
    """
    便捷函数：发送异常告警。
    
    Args:
        anomalies: 异常检测结果字典
        
    Returns:
        发送结果摘要
    """
    manager = AlertManager()
    
    all_results = []
    total_sent = 0
    total_failed = 0
    
    for anomaly_type, anomaly_list in anomalies.items():
        for anomaly in anomaly_list:
            if hasattr(anomaly, 'to_dict'):
                anomaly_dict = anomaly.to_dict()
            else:
                anomaly_dict = anomaly
            
            message = create_alert_from_anomaly(anomaly_dict)
            result = manager.send_alert(message)
            all_results.append(result)
            
            if result.get('sent'):
                total_sent += 1
            else:
                total_failed += 1
    
    return {
        'total_alerts': len(all_results),
        'sent': total_sent,
        'failed': total_failed,
        'details': all_results
    }


if __name__ == "__main__":
    test_anomaly = {
        'anomaly_type': 'high_freq_ip',
        'severity': 'high',
        'description': 'IP 192.168.1.100 在 60 秒内发起 500 次请求',
        'details': {
            'ip': '192.168.1.100',
            'request_count': 500,
            'time_window_seconds': 60
        }
    }
    
    message = create_alert_from_anomaly(test_anomaly)
    print(f"告警消息: {message.to_dict()}")
    
    manager = AlertManager()
    result = manager.send_alert(message)
    print(f"发送结果: {result}")
