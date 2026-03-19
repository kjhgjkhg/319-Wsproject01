"""
HTTP 异常检测模块

该模块实现异常检测逻辑，包括：
- 高频 IP 检测
- 5xx 错误激增检测
- 慢速请求识别
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config.settings import (
    HIGH_FREQ_IP_THRESHOLD, HIGH_FREQ_TIME_WINDOW,
    ERROR_RATE_THRESHOLD, SLOW_REQUEST_THRESHOLD
)
from http_parser import LogEntry


@dataclass
class AnomalyResult:
    """
    异常检测结果数据类。
    
    Attributes:
        anomaly_type: 异常类型标识
        severity: 严重程度（low/medium/high/critical）
        description: 异常描述
        details: 详细信息字典
        timestamp: 检测时间
        affected_items: 受影响的项目列表
    """
    anomaly_type: str
    severity: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    affected_items: List[Any] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        将结果转换为字典格式。
        
        Returns:
            包含所有字段的字典
        """
        return {
            'anomaly_type': self.anomaly_type,
            'severity': self.severity,
            'description': self.description,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'affected_items': self.affected_items
        }


class HighFreqIPDetector:
    """
    高频 IP 检测器。
    
    检测在指定时间窗口内请求次数超过阈值的 IP 地址。
    """
    
    def __init__(self, threshold: int = None, time_window: int = None):
        """
        初始化检测器。
        
        Args:
            threshold: 请求次数阈值，默认使用配置值
            time_window: 时间窗口（秒），默认使用配置值
        """
        self.threshold = threshold or HIGH_FREQ_IP_THRESHOLD
        self.time_window = time_window or HIGH_FREQ_TIME_WINDOW
    
    def detect(self, entries: List[LogEntry]) -> List[AnomalyResult]:
        """
        执行高频 IP 检测。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            检测到的异常结果列表
        """
        if not entries:
            return []
        
        ip_requests: Dict[str, List[datetime]] = defaultdict(list)
        
        for entry in entries:
            if entry.timestamp and entry.ip:
                ip_requests[entry.ip].append(entry.timestamp)
        
        anomalies: List[AnomalyResult] = []
        
        for ip, timestamps in ip_requests.items():
            timestamps.sort()
            
            window_start = 0
            for window_end, ts in enumerate(timestamps):
                while (timestamps[window_end] - timestamps[window_start]).total_seconds() > self.time_window:
                    window_start += 1
                
                count = window_end - window_start + 1
                if count >= self.threshold:
                    window_duration = (timestamps[window_end] - timestamps[window_start]).total_seconds()
                    
                    anomalies.append(AnomalyResult(
                        anomaly_type='high_freq_ip',
                        severity='high',
                        description=f'IP {ip} 在 {window_duration:.0f} 秒内发起 {count} 次请求，超过阈值 {self.threshold}',
                        details={
                            'ip': ip,
                            'request_count': count,
                            'time_window_seconds': window_duration,
                            'threshold': self.threshold,
                            'start_time': timestamps[window_start].isoformat(),
                            'end_time': timestamps[window_end].isoformat()
                        },
                        affected_items=[ip]
                    ))
                    break
        
        return anomalies


class ErrorSpikeDetector:
    """
    错误激增检测器。
    
    检测 5xx 服务器错误占比超过阈值的时间段。
    """
    
    def __init__(self, threshold: float = None, time_window: int = 600):
        """
        初始化检测器。
        
        Args:
            threshold: 错误率阈值（0-1），默认使用配置值
            time_window: 统计时间窗口（秒）
        """
        self.threshold = threshold or ERROR_RATE_THRESHOLD
        self.time_window = time_window
    
    def detect(self, entries: List[LogEntry]) -> List[AnomalyResult]:
        """
        执行错误激增检测。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            检测到的异常结果列表
        """
        if not entries:
            return []
        
        valid_entries = [e for e in entries if e.timestamp and e.status]
        if not valid_entries:
            return []
        
        valid_entries.sort(key=lambda x: x.timestamp)
        
        time_buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: {'total': 0, '5xx': 0, '4xx': 0})
        
        for entry in valid_entries:
            bucket_key = entry.timestamp.strftime('%Y-%m-%d %H:%M')
            time_buckets[bucket_key]['total'] += 1
            
            if 500 <= entry.status < 600:
                time_buckets[bucket_key]['5xx'] += 1
            elif 400 <= entry.status < 500:
                time_buckets[bucket_key]['4xx'] += 1
        
        anomalies: List[AnomalyResult] = []
        
        for bucket_key, counts in time_buckets.items():
            if counts['total'] == 0:
                continue
            
            error_rate = counts['5xx'] / counts['total']
            
            if error_rate > self.threshold:
                anomalies.append(AnomalyResult(
                    anomaly_type='error_spike',
                    severity='critical',
                    description=f'时间段 {bucket_key} 的 5xx 错误率为 {error_rate:.1%}，超过阈值 {self.threshold:.0%}',
                    details={
                        'time_bucket': bucket_key,
                        'total_requests': counts['total'],
                        '5xx_count': counts['5xx'],
                        '4xx_count': counts['4xx'],
                        'error_rate': error_rate,
                        'threshold': self.threshold
                    },
                    affected_items=[bucket_key]
                ))
        
        return anomalies


class SlowRequestDetector:
    """
    慢速请求检测器。
    
    识别响应时间超过阈值的请求。
    """
    
    def __init__(self, threshold: float = None):
        """
        初始化检测器。
        
        Args:
            threshold: 响应时间阈值（秒），默认使用配置值
        """
        self.threshold = threshold or SLOW_REQUEST_THRESHOLD
    
    def detect(self, entries: List[LogEntry]) -> List[AnomalyResult]:
        """
        执行慢速请求检测。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            检测到的异常结果列表
        """
        if not entries:
            return []
        
        slow_requests = [
            entry for entry in entries 
            if entry.response_time is not None and entry.response_time > self.threshold
        ]
        
        if not slow_requests:
            return []
        
        slow_requests.sort(key=lambda x: x.response_time, reverse=True)
        
        url_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'count': 0, 'total_time': 0.0, 'max_time': 0.0})
        
        for entry in slow_requests:
            url_stats[entry.url]['count'] += 1
            url_stats[entry.url]['total_time'] += entry.response_time
            url_stats[entry.url]['max_time'] = max(url_stats[entry.url]['max_time'], entry.response_time)
        
        top_slow_urls = sorted(
            url_stats.items(), 
            key=lambda x: x[1]['count'], 
            reverse=True
        )[:10]
        
        anomalies: List[AnomalyResult] = []
        
        for url, stats in top_slow_urls:
            avg_time = stats['total_time'] / stats['count']
            anomalies.append(AnomalyResult(
                anomaly_type='slow_request',
                severity='medium',
                description=f'URL {url} 有 {stats["count"]} 个慢请求，平均响应时间 {avg_time:.2f}s，最大 {stats["max_time"]:.2f}s',
                details={
                    'url': url,
                    'slow_request_count': stats['count'],
                    'avg_response_time': avg_time,
                    'max_response_time': stats['max_time'],
                    'threshold': self.threshold
                },
                affected_items=[url]
            ))
        
        return anomalies


class AnomalyDetector:
    """
    综合异常检测器。
    
    整合所有检测器，提供统一的检测接口。
    """
    
    def __init__(self, 
                 high_freq_threshold: int = None,
                 error_rate_threshold: float = None,
                 slow_request_threshold: float = None):
        """
        初始化综合检测器。
        
        Args:
            high_freq_threshold: 高频 IP 阈值
            error_rate_threshold: 错误率阈值
            slow_request_threshold: 慢请求阈值
        """
        self.high_freq_detector = HighFreqIPDetector(threshold=high_freq_threshold)
        self.error_spike_detector = ErrorSpikeDetector(threshold=error_rate_threshold)
        self.slow_request_detector = SlowRequestDetector(threshold=slow_request_threshold)
    
    def detect_all(self, entries: List[LogEntry]) -> Dict[str, List[AnomalyResult]]:
        """
        执行所有异常检测。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            按异常类型分类的检测结果字典
        """
        results = {
            'high_freq_ip': self.high_freq_detector.detect(entries),
            'error_spike': self.error_spike_detector.detect(entries),
            'slow_request': self.slow_request_detector.detect(entries)
        }
        
        return results
    
    def get_summary(self, results: Dict[str, List[AnomalyResult]]) -> Dict[str, Any]:
        """
        获取检测结果摘要。
        
        Args:
            results: 检测结果字典
            
        Returns:
            摘要信息字典
        """
        summary = {
            'total_anomalies': 0,
            'by_type': {},
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }
        
        for anomaly_type, anomalies in results.items():
            count = len(anomalies)
            summary['by_type'][anomaly_type] = count
            summary['total_anomalies'] += count
            
            for anomaly in anomalies:
                summary['by_severity'][anomaly.severity] += 1
        
        return summary


def detect_anomalies(entries: List[LogEntry]) -> Dict[str, List[AnomalyResult]]:
    """
    便捷函数：执行所有异常检测。
    
    Args:
        entries: 日志条目列表
        
    Returns:
        检测结果字典
    """
    detector = AnomalyDetector()
    return detector.detect_all(entries)


if __name__ == "__main__":
    from http_parser import parse_log_files
    
    entries, errors = parse_log_files()
    results = detect_anomalies(entries)
    
    detector = AnomalyDetector()
    summary = detector.get_summary(results)
    
    print(f"\n异常检测摘要:")
    print(f"  总计异常: {summary['total_anomalies']}")
    for atype, count in summary['by_type'].items():
        print(f"  - {atype}: {count}")
    for severity, count in summary['by_severity'].items():
        if count > 0:
            print(f"  - {severity}: {count}")
