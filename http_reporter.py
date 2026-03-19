"""
HTTP 报告生成模块

该模块负责生成统计报告，包括：
- JSON 格式统计报告
- Markdown 格式可视化摘要
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent))
from config.settings import (
    OUTPUT_DIR, STATS_REPORT_FILE, ANALYSIS_SUMMARY_FILE, 
    get_output_path, ensure_directories
)
from http_analyzer import StatisticsResult
from http_detector import AnomalyResult


class JSONReporter:
    """
    JSON 报告生成器。
    
    生成结构化的 JSON 格式统计报告。
    """
    
    def __init__(self, output_path: Optional[Path] = None):
        """
        初始化报告生成器。
        
        Args:
            output_path: 输出文件路径，默认使用配置路径
        """
        self.output_path = output_path or get_output_path(STATS_REPORT_FILE)
    
    def generate(self, 
                 statistics: StatisticsResult,
                 anomalies: Dict[str, List[AnomalyResult]],
                 hourly_stats: Dict[str, Dict[str, Any]],
                 url_stats: Dict[str, Dict[str, Any]],
                 status_summary: Dict[str, Any],
                 parse_errors: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        生成完整的 JSON 报告。
        
        Args:
            statistics: 统计结果
            anomalies: 异常检测结果
            hourly_stats: 按小时统计
            url_stats: 按 URL 统计
            status_summary: 状态码摘要
            parse_errors: 解析错误列表
            
        Returns:
            完整的报告数据字典
        """
        report = {
            'meta': {
                'generated_at': datetime.now().isoformat(),
                'report_version': '1.0',
                'tool': 'HTTP Log Analyzer'
            },
            'summary': statistics.to_dict(),
            'anomalies': {
                'summary': {
                    'total': sum(len(v) for v in anomalies.values()),
                    'by_type': {k: len(v) for k, v in anomalies.items()}
                },
                'details': {
                    anomaly_type: [a.to_dict() for a in anomaly_list]
                    for anomaly_type, anomaly_list in anomalies.items()
                }
            },
            'statistics': {
                'hourly': hourly_stats,
                'by_url': url_stats,
                'status': status_summary
            }
        }
        
        if parse_errors:
            report['errors'] = {
                'parse_errors_count': len(parse_errors),
                'parse_errors': parse_errors[:100]
            }
        
        return report
    
    def save(self, report: Dict[str, Any]) -> Path:
        """
        保存报告到 JSON 文件。
        
        Args:
            report: 报告数据字典
            
        Returns:
            保存的文件路径
        """
        ensure_directories()
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        return self.output_path


class MarkdownReporter:
    """
    Markdown 报告生成器。
    
    生成可读性强的 Markdown 格式可视化摘要。
    """
    
    def __init__(self, output_path: Optional[Path] = None):
        """
        初始化报告生成器。
        
        Args:
            output_path: 输出文件路径，默认使用配置路径
        """
        self.output_path = output_path or get_output_path(ANALYSIS_SUMMARY_FILE)
    
    def _generate_bar_chart(self, data: Dict[str, int], max_width: int = 40, 
                            title: str = "") -> str:
        """
        生成简单的文本条形图。
        
        Args:
            data: 数据字典 {标签: 数值}
            max_width: 最大宽度（字符数）
            title: 图表标题
            
        Returns:
            Markdown 格式的条形图字符串
        """
        if not data:
            return ""
        
        max_value = max(data.values()) if data else 1
        lines = []
        
        if title:
            lines.append(f"**{title}**\n")
        
        for label, value in sorted(data.items(), key=lambda x: x[1], reverse=True)[:10]:
            bar_length = int((value / max_value) * max_width) if max_value > 0 else 0
            bar = '█' * bar_length
            lines.append(f"| {label:<15} | {bar:<{max_width}} | {value:>6} |")
        
        return '\n'.join(lines)
    
    def _generate_status_pie(self, distribution: Dict[str, int]) -> str:
        """
        生成状态码分布的文本表示。
        
        Args:
            distribution: 状态码分布字典
            
        Returns:
            Markdown 格式的状态码分布字符串
        """
        total = sum(distribution.values())
        if total == 0:
            return "无数据"
        
        lines = ["```\n"]
        
        categories = ['2xx', '3xx', '4xx', '5xx']
        colors = {'2xx': '🟢', '3xx': '🔵', '4xx': '🟡', '5xx': '🔴'}
        
        for cat in categories:
            if cat in distribution:
                count = distribution[cat]
                percentage = (count / total) * 100
                bar_length = int(percentage / 2)
                bar = '●' * bar_length
                lines.append(f"  {colors.get(cat, '⚪')} {cat}: {bar} {count} ({percentage:.1f}%)")
        
        lines.append("\n```")
        return '\n'.join(lines)
    
    def generate(self,
                 statistics: StatisticsResult,
                 anomalies: Dict[str, List[AnomalyResult]],
                 hourly_stats: Dict[str, Dict[str, Any]],
                 status_summary: Dict[str, Any]) -> str:
        """
        生成 Markdown 格式的可视化摘要。
        
        Args:
            statistics: 统计结果
            anomalies: 异常检测结果
            hourly_stats: 按小时统计
            status_summary: 状态码摘要
            
        Returns:
            Markdown 格式的报告字符串
        """
        lines = []
        
        lines.append("# HTTP 日志分析报告\n")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        lines.append("## 📊 核心指标概览\n")
        lines.append("| 指标 | 数值 |")
        lines.append("|------|------|")
        lines.append(f"| 总请求数 (PV) | {statistics.total_requests:,} |")
        lines.append(f"| 独立访客 (UV) | {statistics.unique_ips:,} |")
        lines.append(f"| 唯一 URL | {statistics.unique_urls:,} |")
        lines.append(f"| QPS | {statistics.qps:.2f} |")
        lines.append(f"| 总传输量 | {statistics.total_bytes / 1024 / 1024:.2f} MB |")
        if statistics.avg_response_time:
            lines.append(f"| 平均响应时间 | {statistics.avg_response_time:.3f}s |")
        if statistics.time_range:
            lines.append(f"| 时间范围 | {statistics.time_range.get('start', '-')} ~ {statistics.time_range.get('end', '-')} |")
        lines.append("")
        
        lines.append("## 📈 状态码分布\n")
        lines.append(self._generate_status_pie(statistics.status_distribution))
        lines.append("")
        
        if statistics.response_time_stats:
            lines.append("## ⏱️ 响应时间统计\n")
            lines.append("| 指标 | 数值 |")
            lines.append("|------|------|")
            for key, value in statistics.response_time_stats.items():
                lines.append(f"| {key.upper()} | {value:.3f}s |")
            lines.append("")
        
        anomaly_summary = {k: len(v) for k, v in anomalies.items()}
        total_anomalies = sum(anomaly_summary.values())
        
        lines.append("## 🚨 异常检测摘要\n")
        if total_anomalies == 0:
            lines.append("> ✅ 未检测到异常\n")
        else:
            lines.append(f"> ⚠️ 共检测到 **{total_anomalies}** 个异常\n")
            lines.append("| 异常类型 | 数量 | 严重程度 |")
            lines.append("|----------|------|----------|")
            
            severity_map = {'high_freq_ip': '高', 'error_spike': '严重', 'slow_request': '中'}
            for atype, count in anomaly_summary.items():
                if count > 0:
                    lines.append(f"| {atype} | {count} | {severity_map.get(atype, '-')} |")
            lines.append("")
            
            for anomaly_type, anomaly_list in anomalies.items():
                if anomaly_list:
                    lines.append(f"### {anomaly_type} 详情\n")
                    for anomaly in anomaly_list[:5]:
                        lines.append(f"- **[{anomaly.severity.upper()}]** {anomaly.description}")
                    if len(anomaly_list) > 5:
                        lines.append(f"- ... 还有 {len(anomaly_list) - 5} 条记录")
                    lines.append("")
        
        lines.append("## 🔥 热门资源 (Top 10)\n")
        if statistics.top_urls:
            lines.append("| 排名 | URL | 请求数 | 占比 |")
            lines.append("|------|-----|--------|------|")
            for i, item in enumerate(statistics.top_urls[:10], 1):
                url_display = item['url'][:50] + '...' if len(item['url']) > 50 else item['url']
                lines.append(f"| {i} | `{url_display}` | {item['count']:,} | {item['percentage']:.1f}% |")
            lines.append("")
        
        lines.append("## 🌐 高频访问 IP (Top 10)\n")
        if statistics.top_ips:
            lines.append("| 排名 | IP 地址 | 请求数 | 占比 |")
            lines.append("|------|---------|--------|------|")
            for i, item in enumerate(statistics.top_ips[:10], 1):
                lines.append(f"| {i} | `{item['ip']}` | {item['count']:,} | {item['percentage']:.1f}% |")
            lines.append("")
        
        if hourly_stats:
            lines.append("## 📅 按小时流量分布\n")
            hourly_counts = {k: v['total_requests'] for k, v in hourly_stats.items()}
            lines.append(self._generate_bar_chart(hourly_counts, title="请求量趋势"))
            lines.append("")
        
        lines.append("---")
        lines.append("*报告由 HTTP Log Analyzer 自动生成*\n")
        
        return '\n'.join(lines)
    
    def save(self, content: str) -> Path:
        """
        保存报告到 Markdown 文件。
        
        Args:
            content: Markdown 内容字符串
            
        Returns:
            保存的文件路径
        """
        ensure_directories()
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return self.output_path


class ReportGenerator:
    """
    综合报告生成器。
    
    整合 JSON 和 Markdown 报告生成功能。
    """
    
    def __init__(self):
        """初始化报告生成器。"""
        self.json_reporter = JSONReporter()
        self.markdown_reporter = MarkdownReporter()
    
    def generate_all(self,
                     statistics: StatisticsResult,
                     anomalies: Dict[str, List[AnomalyResult]],
                     hourly_stats: Dict[str, Dict[str, Any]],
                     url_stats: Dict[str, Dict[str, Any]],
                     status_summary: Dict[str, Any],
                     parse_errors: List[Dict[str, Any]] = None) -> tuple:
        """
        生成所有格式的报告。
        
        Args:
            statistics: 统计结果
            anomalies: 异常检测结果
            hourly_stats: 按小时统计
            url_stats: 按 URL 统计
            status_summary: 状态码摘要
            parse_errors: 解析错误列表
            
        Returns:
            (JSON 文件路径, Markdown 文件路径) 元组
        """
        json_report = self.json_reporter.generate(
            statistics, anomalies, hourly_stats, url_stats, status_summary, parse_errors
        )
        json_path = self.json_reporter.save(json_report)
        
        markdown_content = self.markdown_reporter.generate(
            statistics, anomalies, hourly_stats, status_summary
        )
        markdown_path = self.markdown_reporter.save(markdown_content)
        
        return json_path, markdown_path


def generate_reports(statistics: StatisticsResult,
                     anomalies: Dict[str, List[AnomalyResult]],
                     hourly_stats: Dict[str, Dict[str, Any]],
                     url_stats: Dict[str, Dict[str, Any]],
                     status_summary: Dict[str, Any],
                     parse_errors: List[Dict[str, Any]] = None) -> tuple:
    """
    便捷函数：生成所有报告。
    
    Args:
        statistics: 统计结果
        anomalies: 异常检测结果
        hourly_stats: 按小时统计
        url_stats: 按 URL 统计
        status_summary: 状态码摘要
        parse_errors: 解析错误列表
        
    Returns:
        (JSON 文件路径, Markdown 文件路径) 元组
    """
    generator = ReportGenerator()
    return generator.generate_all(
        statistics, anomalies, hourly_stats, url_stats, status_summary, parse_errors
    )


if __name__ == "__main__":
    from http_parser import parse_log_files
    from http_analyzer import LogAnalyzer
    from http_detector import detect_anomalies
    
    entries, errors = parse_log_files()
    
    analyzer = LogAnalyzer()
    statistics = analyzer.analyze(entries)
    hourly_stats = analyzer.analyze_by_hour(entries)
    url_stats = analyzer.analyze_by_url(entries)
    status_summary = analyzer.get_status_summary(entries)
    
    anomalies = detect_anomalies(entries)
    
    json_path, md_path = generate_reports(
        statistics, anomalies, hourly_stats, url_stats, status_summary, errors
    )
    
    print(f"\n报告已生成:")
    print(f"  JSON 报告: {json_path}")
    print(f"  Markdown 摘要: {md_path}")
