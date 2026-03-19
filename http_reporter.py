"""
HTTP 报告生成模块

功能：生成 JSON 格式统计报告和 Markdown 格式的可视化摘要
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List

from config import OUTPUT_DIR, STATS_REPORT_FILE, ANALYSIS_SUMMARY_FILE


class ReportGenerator:
    """
    报告生成器类
    
    用于生成 JSON 格式的统计报告和 Markdown 格式的可视化摘要
    """
    
    def __init__(self, output_dir: str = None):
        """
        初始化报告生成器
        
        Args:
            output_dir: 输出目录，默认使用配置中的 OUTPUT_DIR
        """
        self.output_dir = output_dir or OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_json_report(
        self, 
        stats: Dict[str, Any], 
        anomalies: Dict[str, Any],
        filename: str = None
    ) -> str:
        """
        生成 JSON 格式的统计报告
        
        Args:
            stats: 统计分析结果
            anomalies: 异常检测结果
            filename: 输出文件名，默认使用配置中的 STATS_REPORT_FILE
            
        Returns:
            str: 生成的文件路径
        """
        if filename is None:
            filename = STATS_REPORT_FILE
        
        filepath = os.path.join(self.output_dir, filename)
        
        # 合并统计和异常数据
        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': stats,
            'anomalies': anomalies,
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"JSON 报告已生成: {filepath}")
            return filepath
        except IOError as e:
            print(f"错误: 无法写入 JSON 报告: {e}")
            raise
    
    def _generate_ascii_chart(self, data: List[float], width: int = 50, height: int = 10) -> str:
        """
        生成 ASCII 字符图表
        
        Args:
            data: 数据列表
            width: 图表宽度
            height: 图表高度
            
        Returns:
            str: ASCII 图表字符串
        """
        if not data:
            return "无数据"
        
        max_val = max(data)
        min_val = min(data)
        
        if max_val == min_val:
            return "数据值相同"
        
        # 将数据映射到图表高度
        chart = []
        for i in range(height):
            threshold = max_val - (max_val - min_val) * (i / height)
            row = ""
            for val in data[:width]:
                if val >= threshold:
                    row += "█"
                else:
                    row += " "
            chart.append(row)
        
        return "\n".join(chart)
    
    def _generate_bar_chart(self, labels: List[str], values: List[int], max_width: int = 40) -> str:
        """
        生成水平条形图
        
        Args:
            labels: 标签列表
            values: 数值列表
            max_width: 最大条形宽度
            
        Returns:
            str: 条形图字符串
        """
        if not values:
            return "无数据"
        
        max_val = max(values)
        lines = []
        
        for label, value in zip(labels, values):
            bar_length = int((value / max_val) * max_width) if max_val > 0 else 0
            bar = "█" * bar_length
            lines.append(f"{label:20s} |{bar:<{max_width}s}| {value}")
        
        return "\n".join(lines)
    
    def _format_bytes(self, bytes_val: int) -> str:
        """
        格式化字节数为人类可读格式
        
        Args:
            bytes_val: 字节数
            
        Returns:
            str: 格式化后的字符串
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} TB"
    
    def _generate_summary_md(
        self, 
        stats: Dict[str, Any], 
        anomalies: Dict[str, Any]
    ) -> str:
        """
        生成 Markdown 格式的可视化摘要内容
        
        Args:
            stats: 统计分析结果
            anomalies: 异常检测结果
            
        Returns:
            str: Markdown 内容
        """
        lines = []
        
        # 标题
        lines.append("# HTTP 日志分析报告")
        lines.append(f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("\n---\n")
        
        # 基础指标概览
        lines.append("## 📊 基础指标概览\n")
        
        basic = stats.get('basic_metrics', {})
        pv_uv = stats.get('pv_uv', {})
        qps = stats.get('qps', {})
        
        lines.append("| 指标 | 数值 |")
        lines.append("|------|------|")
        lines.append(f"| 总请求数 (PV) | {pv_uv.get('pv', 0):,} |")
        lines.append(f"| 独立访客 (UV) | {pv_uv.get('uv', 0):,} |")
        lines.append(f"| 总传输数据 | {self._format_bytes(basic.get('total_bytes', 0))} |")
        lines.append(f"| 整体 QPS | {qps.get('overall_qps', 0)} |")
        lines.append(f"| 峰值 QPS | {qps.get('peak_qps', 0)} |")
        
        time_range = basic.get('time_range', {})
        if time_range.get('start') and time_range.get('end'):
            lines.append(f"| 时间范围 | {time_range['start']} ~ {time_range['end']} |")
        
        lines.append("")
        
        # 状态码分布
        lines.append("## 📈 状态码分布\n")
        
        status_dist = stats.get('status_code_distribution', {})
        by_category = status_dist.get('by_category', {})
        percentages = by_category.get('percentages', {})
        
        lines.append("| 类别 | 占比 | 可视化 |")
        lines.append("|------|------|--------|")
        
        for cat in ['2xx', '3xx', '4xx', '5xx']:
            pct = percentages.get(cat, 0)
            bar = "█" * int(pct / 2)
            lines.append(f"| {cat} | {pct}% | {bar} |")
        
        lines.append("")
        
        # Top URL
        lines.append("## 🔗 Top 10 URL\n")
        
        urls = stats.get('url_distribution', [])[:10]
        if urls:
            lines.append("| URL | 请求数 | 占比 |")
            lines.append("|-----|--------|------|")
            total_requests = basic.get('total_requests', 1)
            for url_data in urls:
                url = url_data['url']
                count = url_data['request_count']
                pct = count / total_requests * 100
                # 截断过长的 URL
                display_url = url[:50] + "..." if len(url) > 50 else url
                lines.append(f"| {display_url} | {count:,} | {pct:.1f}% |")
        else:
            lines.append("暂无数据")
        
        lines.append("")
        
        # Top IP
        lines.append("## 🌐 Top 10 IP\n")
        
        ips = stats.get('top_ips', [])[:10]
        if ips:
            lines.append("| IP | 请求数 | 独立 URL 数 |")
            lines.append("|----|--------|-------------|")
            for ip_data in ips:
                ip = ip_data['ip']
                count = ip_data['request_count']
                urls_count = ip_data['unique_urls']
                lines.append(f"| {ip} | {count:,} | {urls_count} |")
        else:
            lines.append("暂无数据")
        
        lines.append("")
        
        # 响应时间分析
        lines.append("## ⏱️ 响应时间分析\n")
        
        rt = stats.get('response_time_analysis', {})
        if rt.get('count', 0) > 0:
            lines.append("| 指标 | 数值 |")
            lines.append("|------|------|")
            lines.append(f"| 样本数 | {rt['count']:,} |")
            lines.append(f"| 最小值 | {rt['min']}s |")
            lines.append(f"| 最大值 | {rt['max']}s |")
            lines.append(f"| 平均值 | {rt['avg']}s |")
            
            percentiles = rt.get('percentiles', {})
            for p, val in percentiles.items():
                lines.append(f"| {p} | {val}s |")
            
            lines.append("")
            lines.append("### 响应时间分布\n")
            
            dist = rt.get('distribution', {})
            for label, data in dist.items():
                pct = data.get('percentage', 0)
                bar = "█" * int(pct / 2)
                lines.append(f"- {label}: {data['count']:,} ({pct}%) {bar}")
        else:
            lines.append("暂无响应时间数据")
        
        lines.append("")
        
        # 小时分布
        lines.append("## 📅 小时级流量分布\n")
        
        hourly = stats.get('hourly_distribution', [])
        if hourly:
            lines.append("| 时间段 | 请求数 | UV |")
            lines.append("|--------|--------|-----|")
            for h in hourly[:24]:  # 最多显示24小时
                hour = h['hour']
                count = h['request_count']
                uv = h['unique_visitors']
                lines.append(f"| {hour} | {count:,} | {uv:,} |")
        else:
            lines.append("暂无数据")
        
        lines.append("")
        
        # 异常检测汇总
        lines.append("## ⚠️ 异常检测汇总\n")
        
        summary = anomalies.get('summary', {})
        total_anomalies = summary.get('total_anomalies', 0)
        
        lines.append(f"**共检测到 {total_anomalies} 个异常**\n")
        
        # 高频 IP
        high_freq_ips = anomalies.get('high_frequency_ips', [])
        if high_freq_ips:
            lines.append(f"### 🚨 高频 IP ({len(high_freq_ips)} 个)\n")
            lines.append("| IP | 请求数 | 时间窗口 | 阈值 |")
            lines.append("|----|--------|----------|------|")
            for ip_data in high_freq_ips[:5]:
                ip = ip_data['ip']
                count = ip_data['request_count']
                window = ip_data['time_window_minutes']
                threshold = ip_data['threshold']
                lines.append(f"| {ip} | {count} | {window}分钟 | {threshold} |")
            lines.append("")
        
        # 5xx 错误激增
        error_spikes = anomalies.get('server_error_spikes', [])
        if error_spikes:
            lines.append(f"### 🔥 5xx 错误激增 ({len(error_spikes)} 个时间段)\n")
            lines.append("| 时间段 | 错误率 | 总请求 | 5xx数量 |")
            lines.append("|--------|--------|--------|----------|")
            for spike in error_spikes[:5]:
                time_start = spike['time_window_start'][:16]  # 截断到分钟
                rate = spike['error_rate']
                total = spike['total_requests']
                errors = spike['error_5xx_count']
                lines.append(f"| {time_start} | {rate}% | {total} | {errors} |")
            lines.append("")
        
        # 慢速请求
        slow_reqs = anomalies.get('slow_requests', [])
        if slow_reqs:
            lines.append(f"### 🐌 慢速请求 ({len(slow_reqs)} 个)\n")
            lines.append("| IP | URL | 响应时间 | 阈值 |")
            lines.append("|----|-----|----------|------|")
            for req in slow_reqs[:5]:
                ip = req['ip']
                url = req['url'][:40] + "..." if len(req['url']) > 40 else req['url']
                rt = req['response_time']
                threshold = req['threshold']
                lines.append(f"| {ip} | {url} | {rt}s | {threshold}s |")
            lines.append("")
        
        if not high_freq_ips and not error_spikes and not slow_reqs:
            lines.append("✅ 未检测到异常")
        
        lines.append("")
        lines.append("---\n")
        lines.append("*报告由 HTTP 日志分析工具自动生成*")
        
        return "\n".join(lines)
    
    def generate_markdown_summary(
        self, 
        stats: Dict[str, Any], 
        anomalies: Dict[str, Any],
        filename: str = None
    ) -> str:
        """
        生成 Markdown 格式的可视化摘要
        
        Args:
            stats: 统计分析结果
            anomalies: 异常检测结果
            filename: 输出文件名，默认使用配置中的 ANALYSIS_SUMMARY_FILE
            
        Returns:
            str: 生成的文件路径
        """
        if filename is None:
            filename = ANALYSIS_SUMMARY_FILE
        
        filepath = os.path.join(self.output_dir, filename)
        
        # 生成 Markdown 内容
        content = self._generate_summary_md(stats, anomalies)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Markdown 摘要已生成: {filepath}")
            return filepath
        except IOError as e:
            print(f"错误: 无法写入 Markdown 摘要: {e}")
            raise
    
    def generate_all_reports(
        self, 
        stats: Dict[str, Any], 
        anomalies: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        生成所有报告
        
        Args:
            stats: 统计分析结果
            anomalies: 异常检测结果
            
        Returns:
            Dict[str, str]: 生成的文件路径字典
        """
        print("开始生成报告...")
        
        json_path = self.generate_json_report(stats, anomalies)
        md_path = self.generate_markdown_summary(stats, anomalies)
        
        return {
            'json_report': json_path,
            'markdown_summary': md_path,
        }


# 便捷函数
def generate_reports(
    stats: Dict[str, Any], 
    anomalies: Dict[str, Any],
    output_dir: str = None
) -> Dict[str, str]:
    """
    便捷函数：生成所有报告
    
    Args:
        stats: 统计分析结果
        anomalies: 异常检测结果
        output_dir: 可选的自定义输出目录
        
    Returns:
        Dict[str, str]: 生成的文件路径字典
    """
    generator = ReportGenerator(output_dir)
    return generator.generate_all_reports(stats, anomalies)
