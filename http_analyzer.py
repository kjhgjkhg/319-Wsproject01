"""
HTTP 统计分析模块

功能：统计核心指标，包括：
      1. 按小时/URL 统计请求量
      2. 状态码分布
      3. 响应时间分布
      4. 计算 QPS、PV/UV 等核心指标
"""

from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Tuple
from math import ceil

from config import STATS_CONFIG


class LogAnalyzer:
    """
    日志分析器类
    
    用于统计 HTTP 日志的核心指标，包括 QPS、PV/UV、状态码分布等
    """
    
    def __init__(self, config: Dict = None):
        """
        初始化分析器
        
        Args:
            config: 统计配置字典，默认使用 settings.py 中的配置
        """
        self.config = config or STATS_CONFIG
    
    def calculate_basic_metrics(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        计算基础指标
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, Any]: 基础指标字典，包含：
                - total_requests: 总请求数
                - total_bytes: 总传输字节数
                - unique_ips: 独立 IP 数 (UV)
                - time_range: 时间范围
                - duration_seconds: 时间跨度(秒)
        """
        if not logs:
            return {
                'total_requests': 0,
                'total_bytes': 0,
                'unique_ips': 0,
                'time_range': {'start': None, 'end': None},
                'duration_seconds': 0,
            }
        
        # 提取时间戳
        timestamps = [log['timestamp'] for log in logs]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = (end_time - start_time).total_seconds()
        
        # 统计独立 IP
        unique_ips = set(log['ip'] for log in logs)
        
        # 统计总字节数
        total_bytes = sum(log['bytes'] for log in logs)
        
        return {
            'total_requests': len(logs),
            'total_bytes': total_bytes,
            'unique_ips': len(unique_ips),
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
            },
            'duration_seconds': duration,
        }
    
    def calculate_qps(self, logs: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        计算 QPS (Queries Per Second)
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, float]: QPS 指标，包含：
                - overall_qps: 整体 QPS
                - peak_qps: 峰值 QPS
                - avg_qps_by_minute: 平均每分钟 QPS
        """
        if not logs:
            return {
                'overall_qps': 0.0,
                'peak_qps': 0.0,
                'avg_qps_by_minute': 0.0,
            }
        
        # 基础信息
        timestamps = [log['timestamp'] for log in logs]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration_seconds = max(1, (end_time - start_time).total_seconds())
        
        # 整体 QPS
        overall_qps = len(logs) / duration_seconds
        
        # 按秒统计请求数，计算峰值 QPS
        requests_by_second = defaultdict(int)
        for ts in timestamps:
            second_key = ts.replace(microsecond=0)
            requests_by_second[second_key] += 1
        
        peak_qps = max(requests_by_second.values()) if requests_by_second else 0
        
        # 按分钟统计
        requests_by_minute = defaultdict(int)
        for ts in timestamps:
            minute_key = ts.replace(second=0, microsecond=0)
            requests_by_minute[minute_key] += 1
        
        avg_qps_by_minute = sum(requests_by_minute.values()) / max(1, len(requests_by_minute))
        
        return {
            'overall_qps': round(overall_qps, 2),
            'peak_qps': peak_qps,
            'avg_qps_by_minute': round(avg_qps_by_minute, 2),
        }
    
    def calculate_pv_uv(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        计算 PV (Page Views) 和 UV (Unique Visitors)
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, int]: PV/UV 指标
        """
        # PV = 总请求数
        pv = len(logs)
        
        # UV = 独立 IP 数
        uv = len(set(log['ip'] for log in logs))
        
        return {
            'pv': pv,
            'uv': uv,
        }
    
    def analyze_hourly_distribution(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        按小时统计请求量分布
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            List[Dict[str, Any]]: 每小时统计数据
        """
        hourly_stats = defaultdict(lambda: {
            'count': 0,
            'bytes': 0,
            'unique_ips': set(),
            'status_codes': Counter(),
        })
        
        for log in logs:
            hour_key = log['timestamp'].strftime('%Y-%m-%d %H:00')
            
            hourly_stats[hour_key]['count'] += 1
            hourly_stats[hour_key]['bytes'] += log['bytes']
            hourly_stats[hour_key]['unique_ips'].add(log['ip'])
            hourly_stats[hour_key]['status_codes'][log['status']] += 1
        
        # 转换为列表并排序
        result = []
        for hour, stats in sorted(hourly_stats.items()):
            result.append({
                'hour': hour,
                'request_count': stats['count'],
                'bytes_transferred': stats['bytes'],
                'unique_visitors': len(stats['unique_ips']),
                'status_codes': dict(stats['status_codes']),
            })
        
        return result
    
    def analyze_url_distribution(self, logs: List[Dict[str, Any]], top_n: int = None) -> List[Dict[str, Any]]:
        """
        按 URL 统计请求量分布
        
        Args:
            logs: 解析后的日志记录列表
            top_n: 返回前 N 个 URL，默认使用配置中的值
            
        Returns:
            List[Dict[str, Any]]: URL 统计数据
        """
        if top_n is None:
            top_n = self.config.get('top_urls_limit', 20)
        
        url_stats = defaultdict(lambda: {
            'count': 0,
            'bytes': 0,
            'unique_ips': set(),
            'methods': Counter(),
            'status_codes': Counter(),
        })
        
        for log in logs:
            url = log['url']
            
            url_stats[url]['count'] += 1
            url_stats[url]['bytes'] += log['bytes']
            url_stats[url]['unique_ips'].add(log['ip'])
            url_stats[url]['methods'][log['method']] += 1
            url_stats[url]['status_codes'][log['status']] += 1
        
        # 转换为列表，按请求数排序
        result = []
        for url, stats in url_stats.items():
            result.append({
                'url': url,
                'request_count': stats['count'],
                'bytes_transferred': stats['bytes'],
                'unique_visitors': len(stats['unique_ips']),
                'methods': dict(stats['methods']),
                'status_codes': dict(stats['status_codes']),
            })
        
        # 按请求数降序排序并取前 N
        result.sort(key=lambda x: x['request_count'], reverse=True)
        return result[:top_n]
    
    def analyze_status_code_distribution(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析状态码分布
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, Any]: 状态码分布统计
        """
        status_codes = Counter(log['status'] for log in logs)
        total = len(logs)
        
        # 按类别分组
        categories = {
            '2xx': 0,
            '3xx': 0,
            '4xx': 0,
            '5xx': 0,
            'other': 0,
        }
        
        for status, count in status_codes.items():
            if 200 <= status < 300:
                categories['2xx'] += count
            elif 300 <= status < 400:
                categories['3xx'] += count
            elif 400 <= status < 500:
                categories['4xx'] += count
            elif 500 <= status < 600:
                categories['5xx'] += count
            else:
                categories['other'] += count
        
        # 计算百分比
        distribution = {}
        for code, count in sorted(status_codes.items()):
            distribution[str(code)] = {
                'count': count,
                'percentage': round(count / total * 100, 2),
            }
        
        category_percentages = {
            cat: round(count / total * 100, 2) if total > 0 else 0
            for cat, count in categories.items()
        }
        
        return {
            'total': total,
            'by_code': distribution,
            'by_category': {
                'counts': categories,
                'percentages': category_percentages,
            },
        }
    
    def analyze_response_time(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析响应时间分布
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, Any]: 响应时间统计
        """
        # 过滤出有响应时间的记录
        response_times = [log['response_time'] for log in logs if log.get('response_time') is not None]
        
        if not response_times:
            return {
                'count': 0,
                'min': None,
                'max': None,
                'avg': None,
                'percentiles': {},
            }
        
        # 排序用于计算分位数
        sorted_times = sorted(response_times)
        count = len(sorted_times)
        
        # 计算分位数
        def percentile(p: float) -> float:
            """计算百分位数"""
            k = (count - 1) * p / 100
            f = int(k)
            c = f + 1 if f + 1 < count else f
            return sorted_times[f] + (k - f) * (sorted_times[c] - sorted_times[f])
        
        percentiles = self.config.get('response_time_percentiles', [50, 90, 95, 99])
        percentile_values = {f'p{p}': round(percentile(p), 3) for p in percentiles}
        
        # 分布区间
        ranges = [
            (0, 0.1, '< 100ms'),
            (0.1, 0.5, '100ms - 500ms'),
            (0.5, 1, '500ms - 1s'),
            (1, 2, '1s - 2s'),
            (2, 5, '2s - 5s'),
            (5, float('inf'), '> 5s'),
        ]
        
        range_counts = {}
        for low, high, label in ranges:
            cnt = sum(1 for t in response_times if low <= t < high)
            range_counts[label] = {
                'count': cnt,
                'percentage': round(cnt / count * 100, 2),
            }
        
        return {
            'count': count,
            'min': round(min(response_times), 3),
            'max': round(max(response_times), 3),
            'avg': round(sum(response_times) / count, 3),
            'percentiles': percentile_values,
            'distribution': range_counts,
        }
    
    def analyze_top_ips(self, logs: List[Dict[str, Any]], top_n: int = None) -> List[Dict[str, Any]]:
        """
        分析 Top IP
        
        Args:
            logs: 解析后的日志记录列表
            top_n: 返回前 N 个 IP，默认使用配置中的值
            
        Returns:
            List[Dict[str, Any]]: Top IP 统计数据
        """
        if top_n is None:
            top_n = self.config.get('top_ips_limit', 20)
        
        ip_stats = defaultdict(lambda: {
            'count': 0,
            'bytes': 0,
            'urls': set(),
            'status_codes': Counter(),
        })
        
        for log in logs:
            ip = log['ip']
            ip_stats[ip]['count'] += 1
            ip_stats[ip]['bytes'] += log['bytes']
            ip_stats[ip]['urls'].add(log['url'])
            ip_stats[ip]['status_codes'][log['status']] += 1
        
        # 转换为列表并排序
        result = []
        for ip, stats in ip_stats.items():
            result.append({
                'ip': ip,
                'request_count': stats['count'],
                'bytes_transferred': stats['bytes'],
                'unique_urls': len(stats['urls']),
                'status_codes': dict(stats['status_codes']),
            })
        
        result.sort(key=lambda x: x['request_count'], reverse=True)
        return result[:top_n]
    
    def analyze_all(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行所有统计分析
        
        Args:
            logs: 解析后的日志记录列表
            
        Returns:
            Dict[str, Any]: 完整的统计分析结果
        """
        print("开始统计分析...")
        
        basic = self.calculate_basic_metrics(logs)
        print(f"  基础指标: {basic['total_requests']} 请求, {basic['unique_ips']} 独立 IP")
        
        qps = self.calculate_qps(logs)
        print(f"  QPS: 整体 {qps['overall_qps']}, 峰值 {qps['peak_qps']}")
        
        pv_uv = self.calculate_pv_uv(logs)
        print(f"  PV/UV: {pv_uv['pv']}/{pv_uv['uv']}")
        
        hourly = self.analyze_hourly_distribution(logs)
        print(f"  小时分布: {len(hourly)} 个时间段")
        
        urls = self.analyze_url_distribution(logs)
        print(f"  URL 分布: 分析了 Top {len(urls)} 个 URL")
        
        status_codes = self.analyze_status_code_distribution(logs)
        print(f"  状态码分布: 完成")
        
        response_time = self.analyze_response_time(logs)
        print(f"  响应时间: 分析了 {response_time['count']} 条记录")
        
        top_ips = self.analyze_top_ips(logs)
        print(f"  Top IP: 分析了 Top {len(top_ips)} 个 IP")
        
        return {
            'basic_metrics': basic,
            'qps': qps,
            'pv_uv': pv_uv,
            'hourly_distribution': hourly,
            'url_distribution': urls,
            'status_code_distribution': status_codes,
            'response_time_analysis': response_time,
            'top_ips': top_ips,
            'analysis_time': datetime.now().isoformat(),
        }


# 便捷函数
def analyze_logs(logs: List[Dict[str, Any]], config: Dict = None) -> Dict[str, Any]:
    """
    便捷函数：执行所有统计分析
    
    Args:
        logs: 解析后的日志记录列表
        config: 可选的自定义统计配置
        
    Returns:
        Dict[str, Any]: 完整的统计分析结果
    """
    analyzer = LogAnalyzer(config)
    return analyzer.analyze_all(logs)
