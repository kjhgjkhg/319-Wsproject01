"""
HTTP 统计分析模块

该模块负责统计核心指标，包括：
- 按小时/URL 统计请求量
- 状态码分布
- 响应时间分布
- QPS、PV/UV 等核心指标
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import statistics

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config.settings import STATS_TIME_WINDOW
from http_parser import LogEntry


@dataclass
class StatisticsResult:
    """
    统计结果数据类。
    
    Attributes:
        total_requests: 总请求数
        unique_ips: 唯一 IP 数
        unique_urls: 唯一 URL 数
        total_bytes: 总传输字节数
        avg_response_time: 平均响应时间
        qps: 每秒查询率
        pv: 页面访问量
        uv: 独立访客数
        status_distribution: 状态码分布
        method_distribution: 请求方法分布
        hourly_distribution: 按小时分布
        top_urls: 热门 URL
        top_ips: 高频 IP
        response_time_stats: 响应时间统计
    """
    total_requests: int = 0
    unique_ips: int = 0
    unique_urls: int = 0
    total_bytes: int = 0
    avg_response_time: Optional[float] = None
    qps: float = 0.0
    pv: int = 0
    uv: int = 0
    status_distribution: Dict[str, int] = field(default_factory=dict)
    method_distribution: Dict[str, int] = field(default_factory=dict)
    hourly_distribution: Dict[str, int] = field(default_factory=dict)
    top_urls: List[Dict[str, Any]] = field(default_factory=list)
    top_ips: List[Dict[str, Any]] = field(default_factory=list)
    response_time_stats: Dict[str, float] = field(default_factory=dict)
    time_range: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        将统计结果转换为字典格式。
        
        Returns:
            包含所有统计指标的字典
        """
        return {
            'total_requests': self.total_requests,
            'unique_ips': self.unique_ips,
            'unique_urls': self.unique_urls,
            'total_bytes': self.total_bytes,
            'avg_response_time': self.avg_response_time,
            'qps': round(self.qps, 2),
            'pv': self.pv,
            'uv': self.uv,
            'status_distribution': self.status_distribution,
            'method_distribution': self.method_distribution,
            'hourly_distribution': self.hourly_distribution,
            'top_urls': self.top_urls,
            'top_ips': self.top_ips,
            'response_time_stats': self.response_time_stats,
            'time_range': self.time_range
        }


class LogAnalyzer:
    """
    日志分析器类。
    
    提供多种统计功能，计算核心指标。
    """
    
    def __init__(self, time_window: int = None):
        """
        初始化分析器。
        
        Args:
            time_window: 统计时间窗口（秒）
        """
        self.time_window = time_window or STATS_TIME_WINDOW
    
    def _get_status_category(self, status: int) -> str:
        """
        获取状态码类别。
        
        Args:
            status: HTTP 状态码
            
        Returns:
            状态码类别字符串
        """
        if 200 <= status < 300:
            return '2xx'
        elif 300 <= status < 400:
            return '3xx'
        elif 400 <= status < 500:
            return '4xx'
        elif 500 <= status < 600:
            return '5xx'
        else:
            return 'other'
    
    def analyze(self, entries: List[LogEntry]) -> StatisticsResult:
        """
        执行完整统计分析。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            统计结果对象
        """
        if not entries:
            return StatisticsResult()
        
        result = StatisticsResult()
        
        result.total_requests = len(entries)
        
        unique_ips = set()
        unique_urls = set()
        total_bytes = 0
        response_times: List[float] = []
        
        status_counts: Dict[str, int] = defaultdict(int)
        method_counts: Dict[str, int] = defaultdict(int)
        hourly_counts: Dict[str, int] = defaultdict(int)
        url_counts: Dict[str, int] = defaultdict(int)
        ip_counts: Dict[str, int] = defaultdict(int)
        
        timestamps: List[datetime] = []
        min_time: Optional[datetime] = None
        max_time: Optional[datetime] = None
        
        for entry in entries:
            if entry.ip:
                unique_ips.add(entry.ip)
                ip_counts[entry.ip] += 1
            
            if entry.url:
                unique_urls.add(entry.url)
                url_counts[entry.url] += 1
            
            total_bytes += entry.bytes_sent
            
            if entry.response_time is not None:
                response_times.append(entry.response_time)
            
            status_category = self._get_status_category(entry.status)
            status_counts[status_category] += 1
            status_counts[str(entry.status)] += 1
            
            if entry.method:
                method_counts[entry.method] += 1
            
            if entry.timestamp:
                timestamps.append(entry.timestamp)
                hourly_key = entry.timestamp.strftime('%Y-%m-%d %H:00')
                hourly_counts[hourly_key] += 1
                
                if min_time is None or entry.timestamp < min_time:
                    min_time = entry.timestamp
                if max_time is None or entry.timestamp > max_time:
                    max_time = entry.timestamp
        
        result.unique_ips = len(unique_ips)
        result.unique_urls = len(unique_urls)
        result.total_bytes = total_bytes
        
        if response_times:
            result.avg_response_time = round(statistics.mean(response_times), 3)
            result.response_time_stats = {
                'min': round(min(response_times), 3),
                'max': round(max(response_times), 3),
                'avg': round(statistics.mean(response_times), 3),
                'median': round(statistics.median(response_times), 3),
                'p95': round(sorted(response_times)[int(len(response_times) * 0.95)], 3) if len(response_times) > 20 else round(max(response_times), 3),
                'p99': round(sorted(response_times)[int(len(response_times) * 0.99)], 3) if len(response_times) > 100 else round(max(response_times), 3)
            }
        
        if timestamps and min_time and max_time:
            time_diff = (max_time - min_time).total_seconds()
            if time_diff > 0:
                result.qps = len(entries) / time_diff
        
        result.pv = result.total_requests
        result.uv = result.unique_ips
        
        result.status_distribution = dict(sorted(status_counts.items()))
        result.method_distribution = dict(sorted(method_counts.items(), key=lambda x: x[1], reverse=True))
        result.hourly_distribution = dict(sorted(hourly_counts.items()))
        
        top_urls = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        result.top_urls = [
            {'url': url, 'count': count, 'percentage': round(count / result.total_requests * 100, 2)}
            for url, count in top_urls
        ]
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        result.top_ips = [
            {'ip': ip, 'count': count, 'percentage': round(count / result.total_requests * 100, 2)}
            for ip, count in top_ips
        ]
        
        if min_time and max_time:
            result.time_range = {
                'start': min_time.isoformat(),
                'end': max_time.isoformat()
            }
        
        return result
    
    def analyze_by_hour(self, entries: List[LogEntry]) -> Dict[str, Dict[str, Any]]:
        """
        按小时分析日志数据。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            按小时分组的统计数据字典
        """
        hourly_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'total': 0,
            'bytes': 0,
            'response_times': [],
            'status_counts': defaultdict(int),
            'unique_ips': set()
        })
        
        for entry in entries:
            if not entry.timestamp:
                continue
            
            hour_key = entry.timestamp.strftime('%Y-%m-%d %H:00')
            hourly_data[hour_key]['total'] += 1
            hourly_data[hour_key]['bytes'] += entry.bytes_sent
            
            if entry.response_time is not None:
                hourly_data[hour_key]['response_times'].append(entry.response_time)
            
            status_cat = self._get_status_category(entry.status)
            hourly_data[hour_key]['status_counts'][status_cat] += 1
            
            if entry.ip:
                hourly_data[hour_key]['unique_ips'].add(entry.ip)
        
        result = {}
        for hour_key, data in sorted(hourly_data.items()):
            avg_time = None
            if data['response_times']:
                avg_time = round(statistics.mean(data['response_times']), 3)
            
            result[hour_key] = {
                'total_requests': data['total'],
                'unique_visitors': len(data['unique_ips']),
                'total_bytes': data['bytes'],
                'avg_response_time': avg_time,
                'status_distribution': dict(data['status_counts'])
            }
        
        return result
    
    def analyze_by_url(self, entries: List[LogEntry]) -> Dict[str, Dict[str, Any]]:
        """
        按 URL 分析日志数据。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            按 URL 分组的统计数据字典
        """
        url_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'total': 0,
            'bytes': 0,
            'response_times': [],
            'status_counts': defaultdict(int),
            'methods': defaultdict(int)
        })
        
        for entry in entries:
            if not entry.url:
                continue
            
            url = entry.url.split('?')[0]
            url_data[url]['total'] += 1
            url_data[url]['bytes'] += entry.bytes_sent
            
            if entry.response_time is not None:
                url_data[url]['response_times'].append(entry.response_time)
            
            status_cat = self._get_status_category(entry.status)
            url_data[url]['status_counts'][status_cat] += 1
            
            if entry.method:
                url_data[url]['methods'][entry.method] += 1
        
        result = {}
        for url, data in sorted(url_data.items(), key=lambda x: x[1]['total'], reverse=True)[:50]:
            avg_time = None
            if data['response_times']:
                avg_time = round(statistics.mean(data['response_times']), 3)
            
            result[url] = {
                'total_requests': data['total'],
                'total_bytes': data['bytes'],
                'avg_response_time': avg_time,
                'status_distribution': dict(data['status_counts']),
                'methods': dict(data['methods'])
            }
        
        return result
    
    def get_status_summary(self, entries: List[LogEntry]) -> Dict[str, Any]:
        """
        获取状态码摘要统计。
        
        Args:
            entries: 日志条目列表
            
        Returns:
            状态码统计摘要
        """
        status_counts: Dict[int, int] = defaultdict(int)
        
        for entry in entries:
            status_counts[entry.status] += 1
        
        total = len(entries)
        result = {
            'total_requests': total,
            'by_category': {},
            'by_code': {},
            'error_rate': 0.0
        }
        
        error_count = 0
        for code, count in sorted(status_counts.items()):
            result['by_code'][str(code)] = {
                'count': count,
                'percentage': round(count / total * 100, 2) if total > 0 else 0
            }
            
            category = self._get_status_category(code)
            if category not in result['by_category']:
                result['by_category'][category] = {'count': 0, 'percentage': 0}
            result['by_category'][category]['count'] += count
            
            if code >= 400:
                error_count += count
        
        for category in result['by_category']:
            result['by_category'][category]['percentage'] = round(
                result['by_category'][category]['count'] / total * 100, 2
            ) if total > 0 else 0
        
        result['error_rate'] = round(error_count / total * 100, 2) if total > 0 else 0
        
        return result


def analyze_logs(entries: List[LogEntry]) -> StatisticsResult:
    """
    便捷函数：执行日志统计分析。
    
    Args:
        entries: 日志条目列表
        
    Returns:
        统计结果对象
    """
    analyzer = LogAnalyzer()
    return analyzer.analyze(entries)


if __name__ == "__main__":
    from http_parser import parse_log_files
    
    entries, errors = parse_log_files()
    
    analyzer = LogAnalyzer()
    result = analyzer.analyze(entries)
    
    print(f"\n统计摘要:")
    print(f"  总请求数: {result.total_requests}")
    print(f"  唯一 IP: {result.unique_ips}")
    print(f"  唯一 URL: {result.unique_urls}")
    print(f"  QPS: {result.qps:.2f}")
    print(f"  平均响应时间: {result.avg_response_time}s")
    
    print(f"\n状态码分布:")
    for status, count in result.status_distribution.items():
        if len(status) <= 3:
            print(f"  {status}: {count}")
    
    print(f"\n热门 URL (Top 5):")
    for item in result.top_urls[:5]:
        print(f"  {item['url']}: {item['count']} ({item['percentage']}%)")
