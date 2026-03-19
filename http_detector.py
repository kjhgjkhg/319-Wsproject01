"""
HTTP 异常检测模块

功能：实现异常检测逻辑，包括：
      1. 高频 IP 检测（10分钟内请求次数超过阈值）
      2. 5xx 服务器错误占比检测（超过10%的时间段）
      3. 慢速请求检测（响应时间超过5秒）
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional

from config import THRESHOLDS


class AnomalyDetector:
    """
    异常检测器类
    
    用于检测 HTTP 日志中的异常模式，包括高频 IP、5xx 错误激增、慢速请求
    """
    
    def __init__(self, thresholds: Dict = None):
        """
        初始化检测器
        
        Args:
            thresholds: 阈值配置字典，默认使用 settings.py 中的配置
        """
        self.thresholds = thresholds or THRESHOLDS
    
    def detect_high_frequency_ips(
        self, 
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        检测高频 IP
        
        统计在指定时间窗口内请求次数超过阈值的 IP 列表
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            List[Dict[str, Any]]: 异常 IP 列表，每项包含：
                - ip: IP 地址
                - request_count: 请求次数
                - time_window: 时间窗口描述
                - first_seen: 首次出现时间
                - last_seen: 最后出现时间
                - urls: 访问的 URL 列表（去重）
        """
        config = self.thresholds['high_freq_ip']
        time_window = config['time_window_minutes']
        max_requests = config['max_requests']
        
        if not logs:
            return []
        
        # 按时间排序
        sorted_logs = sorted(logs, key=lambda x: x['timestamp'])
        
        # 滑动窗口统计
        ip_windows = defaultdict(lambda: {
            'count': 0,
            'urls': set(),
            'first_seen': None,
            'last_seen': None,
        })
        
        anomalies = []
        detected_ips = set()
        
        # 使用滑动窗口
        for i, log in enumerate(sorted_logs):
            ip = log['ip']
            timestamp = log['timestamp']
            url = log['url']
            
            # 计算窗口边界
            window_start = timestamp - timedelta(minutes=time_window)
            
            # 统计当前窗口内的请求
            window_logs = [
                l for l in sorted_logs[max(0, i-1000):i+1]
                if l['ip'] == ip and l['timestamp'] >= window_start
            ]
            
            request_count = len(window_logs)
            
            # 检查是否超过阈值
            if request_count > max_requests and ip not in detected_ips:
                urls = set(l['url'] for l in window_logs)
                timestamps = [l['timestamp'] for l in window_logs]
                
                anomalies.append({
                    'ip': ip,
                    'request_count': request_count,
                    'time_window_minutes': time_window,
                    'threshold': max_requests,
                    'first_seen': min(timestamps).isoformat(),
                    'last_seen': max(timestamps).isoformat(),
                    'urls': list(urls)[:10],  # 限制 URL 数量
                    'urls_count': len(urls),
                })
                detected_ips.add(ip)
        
        # 按请求次数降序排序
        anomalies.sort(key=lambda x: x['request_count'], reverse=True)
        return anomalies
    
    def detect_server_error_spikes(
        self, 
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        检测 5xx 服务器错误激增
        
        统计在指定时间窗口内 5xx 错误占比超过阈值的时间段
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            List[Dict[str, Any]]: 异常时间段列表，每项包含：
                - time_window_start: 时间窗口开始
                - time_window_end: 时间窗口结束
                - total_requests: 总请求数
                - error_5xx_count: 5xx 错误数
                - error_rate: 错误占比
                - threshold: 阈值
                - affected_urls: 受影响的 URL 列表
        """
        config = self.thresholds['server_error_rate']
        time_window = config['time_window_minutes']
        max_error_rate = config['max_error_rate']
        
        if not logs:
            return []
        
        # 按时间排序
        sorted_logs = sorted(logs, key=lambda x: x['timestamp'])
        
        # 按时间窗口分组
        windows = defaultdict(lambda: {
            'total': 0,
            'errors_5xx': 0,
            'urls': defaultdict(int),
        })
        
        for log in sorted_logs:
            # 按时间窗口分组（以 time_window 分钟为单位）
            timestamp = log['timestamp']
            window_key = timestamp.replace(
                minute=(timestamp.minute // time_window) * time_window,
                second=0,
                microsecond=0
            )
            
            windows[window_key]['total'] += 1
            
            if 500 <= log['status'] < 600:
                windows[window_key]['errors_5xx'] += 1
                windows[window_key]['urls'][log['url']] += 1
        
        # 检测异常窗口
        anomalies = []
        for window_time, stats in sorted(windows.items()):
            if stats['total'] > 0:
                error_rate = stats['errors_5xx'] / stats['total']
                
                if error_rate > max_error_rate:
                    # 获取受影响最严重的 URL
                    affected_urls = sorted(
                        stats['urls'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5]
                    
                    anomalies.append({
                        'time_window_start': window_time.isoformat(),
                        'time_window_end': (window_time + timedelta(minutes=time_window)).isoformat(),
                        'total_requests': stats['total'],
                        'error_5xx_count': stats['errors_5xx'],
                        'error_rate': round(error_rate * 100, 2),
                        'threshold': max_error_rate * 100,
                        'affected_urls': [{'url': url, 'count': count} for url, count in affected_urls],
                    })
        
        return anomalies
    
    def detect_slow_requests(
        self, 
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        检测慢速请求
        
        识别响应时间超过阈值的请求
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            List[Dict[str, Any]]: 慢速请求列表，每项包含：
                - ip: 客户端 IP
                - timestamp: 请求时间
                - method: 请求方法
                - url: 请求 URL
                - status: 状态码
                - response_time: 响应时间(秒)
                - threshold: 阈值
        """
        config = self.thresholds['slow_request']
        max_response_time = config['max_response_time']
        
        slow_requests = []
        
        for log in logs:
            response_time = log.get('response_time')
            
            # 检查是否有响应时间字段且超过阈值
            if response_time is not None and response_time > max_response_time:
                slow_requests.append({
                    'ip': log['ip'],
                    'timestamp': log['timestamp'].isoformat(),
                    'method': log['method'],
                    'url': log['url'],
                    'status': log['status'],
                    'response_time': response_time,
                    'threshold': max_response_time,
                })
        
        # 按响应时间降序排序
        slow_requests.sort(key=lambda x: x['response_time'], reverse=True)
        
        return slow_requests
    
    def detect_all_anomalies(
        self, 
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        执行所有异常检测
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, Any]: 包含所有检测结果的字典：
                - high_frequency_ips: 高频 IP 列表
                - server_error_spikes: 5xx 错误激增列表
                - slow_requests: 慢速请求列表
                - summary: 异常汇总统计
        """
        print("开始异常检测...")
        
        # 执行各项检测
        high_freq_ips = self.detect_high_frequency_ips(logs)
        print(f"  检测到 {len(high_freq_ips)} 个高频 IP")
        
        error_spikes = self.detect_server_error_spikes(logs)
        print(f"  检测到 {len(error_spikes)} 个 5xx 错误激增时间段")
        
        slow_requests = self.detect_slow_requests(logs)
        print(f"  检测到 {len(slow_requests)} 个慢速请求")
        
        # 生成汇总
        summary = {
            'total_anomalies': len(high_freq_ips) + len(error_spikes) + len(slow_requests),
            'high_frequency_ip_count': len(high_freq_ips),
            'server_error_spike_count': len(error_spikes),
            'slow_request_count': len(slow_requests),
            'detection_time': datetime.now().isoformat(),
        }
        
        return {
            'high_frequency_ips': high_freq_ips,
            'server_error_spikes': error_spikes,
            'slow_requests': slow_requests,
            'summary': summary,
        }
    
    def update_thresholds(self, new_thresholds: Dict):
        """
        更新阈值配置
        
        Args:
            new_thresholds: 新的阈值配置字典
        """
        self.thresholds.update(new_thresholds)
        print("阈值配置已更新")


# 便捷函数
def detect_anomalies(logs: List[Dict[str, Any]], thresholds: Dict = None) -> Dict[str, Any]:
    """
    便捷函数：执行所有异常检测
    
    Args:
        logs: 解析后的日志记录列表
        thresholds: 可选的自定义阈值配置
        
    Returns:
        Dict[str, Any]: 检测结果字典
    """
    detector = AnomalyDetector(thresholds)
    return detector.detect_all_anomalies(logs)
