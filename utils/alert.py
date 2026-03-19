"""
告警推送模块

功能：封装告警推送工具函数，支持企业微信/钉钉机器人
"""

import json
import hmac
import hashlib
import base64
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, Any, Optional

from config import ALERT_CONFIG


class AlertManager:
    """
    告警管理器类
    
    用于发送告警信息到企业微信/钉钉机器人，并记录告警日志
    """
    
    def __init__(self, config: Dict = None):
        """
        初始化告警管理器
        
        Args:
            config: 告警配置字典，默认使用 settings.py 中的配置
        """
        self.config = config or ALERT_CONFIG
        self.log_file = self.config.get('log_file', 'alert.log')
    
    def _write_alert_log(self, message: str, alert_type: str = "INFO"):
        """
        写入告警日志
        
        Args:
            message: 日志消息
            alert_type: 告警类型
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{alert_type}] {message}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except IOError as e:
            print(f"警告: 无法写入告警日志: {e}")
    
    def _send_http_post(self, url: str, data: Dict[str, Any], headers: Dict[str, str] = None) -> bool:
        """
        发送 HTTP POST 请求
        
        Args:
            url: 请求 URL
            data: 请求数据
            headers: 请求头
            
        Returns:
            bool: 请求是否成功
        """
        try:
            json_data = json.dumps(data).encode('utf-8')
            
            default_headers = {
                'Content-Type': 'application/json',
                'Content-Length': len(json_data),
            }
            if headers:
                default_headers.update(headers)
            
            req = urllib.request.Request(
                url,
                data=json_data,
                headers=default_headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                result = response.read().decode('utf-8')
                
                # 检查响应
                try:
                    result_json = json.loads(result)
                    # 企业微信返回 errcode
                    if 'errcode' in result_json:
                        if result_json['errcode'] == 0:
                            return True
                        else:
                            print(f"企业微信API错误: {result_json.get('errmsg', '未知错误')}")
                            return False
                    # 钉钉返回 errcode
                    if 'errcode' in result_json:
                        if result_json['errcode'] == 0:
                            return True
                        else:
                            print(f"钉钉API错误: {result_json.get('errmsg', '未知错误')}")
                            return False
                    return True
                except json.JSONDecodeError:
                    return True
                    
        except urllib.error.URLError as e:
            print(f"网络请求错误: {e}")
            return False
        except Exception as e:
            print(f"发送请求时发生错误: {e}")
            return False
    
    def _generate_dingtalk_sign(self, secret: str, timestamp: str) -> str:
        """
        生成钉钉机器人签名
        
        Args:
            secret: 钉钉机器人密钥
            timestamp: 时间戳
            
        Returns:
            str: 签名
        """
        string_to_sign = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(
            secret.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return sign
    
    def send_wechat_alert(self, message: str, title: str = "HTTP日志告警") -> bool:
        """
        发送企业微信告警
        
        Args:
            message: 告警消息内容
            title: 告警标题
            
        Returns:
            bool: 发送是否成功，未启用返回 None
        """
        wechat_config = self.config.get('wechat', {})
        
        if not wechat_config.get('enabled', False):
            print("企业微信告警未启用")
            return None
        
        webhook_url = wechat_config.get('webhook_url', '')
        if not webhook_url:
            print("企业微信 Webhook URL 未配置")
            return False
        
        # 构建消息
        data = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"**{title}**\n\n{message}\n\n> 发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        
        success = self._send_http_post(webhook_url, data)
        
        if success:
            self._write_alert_log(f"企业微信告警发送成功: {title}", "SUCCESS")
            print("企业微信告警已发送")
        else:
            self._write_alert_log(f"企业微信告警发送失败: {title}", "FAILED")
        
        return success
    
    def send_dingtalk_alert(self, message: str, title: str = "HTTP日志告警") -> bool:
        """
        发送钉钉告警
        
        Args:
            message: 告警消息内容
            title: 告警标题
            
        Returns:
            bool: 发送是否成功，未启用返回 None
        """
        dingtalk_config = self.config.get('dingtalk', {})
        
        if not dingtalk_config.get('enabled', False):
            print("钉钉告警未启用")
            return None
        
        webhook_url = dingtalk_config.get('webhook_url', '')
        if not webhook_url:
            print("钉钉 Webhook URL 未配置")
            return False
        
        # 生成签名
        secret = dingtalk_config.get('secret', '')
        if secret:
            timestamp = str(round(datetime.now().timestamp() * 1000))
            sign = self._generate_dingtalk_sign(secret, timestamp)
            webhook_url = f"{webhook_url}&timestamp={timestamp}&sign={sign}"
        
        # 构建消息
        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": f"### {title}\n\n{message}\n\n---\n发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        
        success = self._send_http_post(webhook_url, data)
        
        if success:
            self._write_alert_log(f"钉钉告警发送成功: {title}", "SUCCESS")
            print("钉钉告警已发送")
        else:
            self._write_alert_log(f"钉钉告警发送失败: {title}", "FAILED")
        
        return success
    
    def send_alert(
        self, 
        message: str, 
        title: str = "HTTP日志告警",
        alert_types: list = None
    ) -> Dict[str, Any]:
        """
        发送告警到所有启用的渠道
        
        Args:
            message: 告警消息内容
            title: 告警标题
            alert_types: 指定发送的告警类型 ['wechat', 'dingtalk']，默认发送所有启用的
            
        Returns:
            Dict[str, Any]: 各渠道发送结果，None 表示未启用，True/False 表示成功/失败
        """
        results = {}
        
        if alert_types is None:
            alert_types = ['wechat', 'dingtalk']
        
        if 'wechat' in alert_types:
            results['wechat'] = self.send_wechat_alert(message, title)
        
        if 'dingtalk' in alert_types:
            results['dingtalk'] = self.send_dingtalk_alert(message, title)
        
        # 过滤掉 None 值（未启用的）
        active_results = {k: v for k, v in results.items() if v is not None}
        
        # 如果没有启用的渠道，记录到日志
        if not active_results:
            self._write_alert_log(f"告警未发送（无启用渠道）: {title} - {message}", "WARNING")
            print("没有启用的告警渠道，告警信息已记录到日志文件")
        
        return results
    
    def send_anomaly_alert(
        self, 
        anomalies: Dict[str, Any],
        stats: Dict[str, Any] = None
    ) -> Dict[str, bool]:
        """
        发送异常检测告警
        
        Args:
            anomalies: 异常检测结果
            stats: 统计数据（可选）
            
        Returns:
            Dict[str, bool]: 各渠道发送结果
        """
        summary = anomalies.get('summary', {})
        total_anomalies = summary.get('total_anomalies', 0)
        
        if total_anomalies == 0:
            print("没有异常需要告警")
            return {}
        
        # 构建告警消息
        lines = [f"检测到 **{total_anomalies}** 个异常：\n"]
        
        # 高频 IP
        high_freq_ips = anomalies.get('high_frequency_ips', [])
        if high_freq_ips:
            lines.append(f"🚨 **高频 IP**: {len(high_freq_ips)} 个")
            for ip_data in high_freq_ips[:3]:
                lines.append(f"  - {ip_data['ip']}: {ip_data['request_count']} 请求/{ip_data['time_window_minutes']}分钟")
            lines.append("")
        
        # 5xx 错误
        error_spikes = anomalies.get('server_error_spikes', [])
        if error_spikes:
            lines.append(f"🔥 **5xx 错误激增**: {len(error_spikes)} 个时间段")
            for spike in error_spikes[:3]:
                lines.append(f"  - {spike['time_window_start'][:16]}: {spike['error_rate']}% ({spike['error_5xx_count']}/{spike['total_requests']})")
            lines.append("")
        
        # 慢速请求
        slow_reqs = anomalies.get('slow_requests', [])
        if slow_reqs:
            lines.append(f"🐌 **慢速请求**: {len(slow_reqs)} 个")
            for req in slow_reqs[:3]:
                url = req['url'][:30] + "..." if len(req['url']) > 30 else req['url']
                lines.append(f"  - {req['ip']}: {req['response_time']}s - {url}")
            lines.append("")
        
        # 添加统计摘要
        if stats:
            basic = stats.get('basic_metrics', {})
            pv_uv = stats.get('pv_uv', {})
            lines.append("---\n")
            lines.append("**统计摘要**:")
            lines.append(f"- 总请求数: {pv_uv.get('pv', 0):,}")
            lines.append(f"- 独立访客: {pv_uv.get('uv', 0):,}")
        
        message = "\n".join(lines)
        
        return self.send_alert(message, "HTTP日志异常告警")


# 便捷函数
def send_alert(
    message: str, 
    title: str = "HTTP日志告警",
    config: Dict = None
) -> Dict[str, bool]:
    """
    便捷函数：发送告警
    
    Args:
        message: 告警消息内容
        title: 告警标题
        config: 可选的自定义告警配置
        
    Returns:
        Dict[str, bool]: 各渠道发送结果
    """
    manager = AlertManager(config)
    return manager.send_alert(message, title)


def send_anomaly_alert(
    anomalies: Dict[str, Any],
    stats: Dict[str, Any] = None,
    config: Dict = None
) -> Dict[str, bool]:
    """
    便捷函数：发送异常检测告警
    
    Args:
        anomalies: 异常检测结果
        stats: 统计数据（可选）
        config: 可选的自定义告警配置
        
    Returns:
        Dict[str, bool]: 各渠道发送结果
    """
    manager = AlertManager(config)
    return manager.send_anomaly_alert(anomalies, stats)
