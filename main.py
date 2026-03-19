"""
HTTP 日志分析与告警系统 - 主程序入口

该程序批量解析 Nginx/Apache 格式的 HTTP 访问日志，
识别异常请求，生成可视化统计报告，并支持告警推送。

用法:
    python main.py [选项]

选项:
    --no-alert       禁用告警推送
    --force          强制重新解析所有文件（忽略增量处理）
    --verbose        显示详细输出
    --config FILE    指定配置文件路径
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config.settings import (
    ensure_directories, INPUT_DIR, OUTPUT_DIR,
    update_threshold, update_alert_webhook, ALERT_CONFIG,
    STATS_REPORT_FILE, ANALYSIS_SUMMARY_FILE
)
from http_parser import LogFileProcessor, LogParser
from http_detector import AnomalyDetector, detect_anomalies
from http_analyzer import LogAnalyzer
from http_reporter import generate_reports
from utils.alert import send_anomaly_alerts


def parse_arguments():
    """
    解析命令行参数。
    
    Returns:
        解析后的参数命名空间
    """
    parser = argparse.ArgumentParser(
        description='HTTP 日志分析与告警系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python main.py                    # 正常运行
    python main.py --no-alert         # 禁用告警
    python main.py --force            # 强制重新解析
    python main.py --verbose          # 详细输出
        """
    )
    
    parser.add_argument(
        '--no-alert',
        action='store_true',
        help='禁用告警推送功能'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='强制重新解析所有文件（忽略增量处理）'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='显示详细输出'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='指定配置文件路径'
    )
    
    parser.add_argument(
        '--high-freq-threshold',
        type=int,
        default=None,
        help='高频 IP 阈值（次/10分钟）'
    )
    
    parser.add_argument(
        '--error-rate-threshold',
        type=float,
        default=None,
        help='错误率阈值（如 0.1 表示 10%%）'
    )
    
    parser.add_argument(
        '--slow-request-threshold',
        type=float,
        default=None,
        help='慢请求阈值（秒）'
    )
    
    parser.add_argument(
        '--wechat-webhook',
        type=str,
        default=None,
        help='企业微信机器人 Webhook 地址'
    )
    
    parser.add_argument(
        '--dingtalk-webhook',
        type=str,
        default=None,
        help='钉钉机器人 Webhook 地址'
    )
    
    return parser.parse_args()


def print_banner():
    """打印程序横幅。"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║           HTTP 日志分析与告警系统 v1.0                        ║
║     HTTP Log Analyzer & Alert System                          ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """
    主函数，协调整个分析流程。
    
    Returns:
        退出码（0 表示成功，非 0 表示失败）
    """
    args = parse_arguments()
    
    print_banner()
    
    start_time = datetime.now()
    print(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"输入目录: {INPUT_DIR}")
    print(f"输出目录: {OUTPUT_DIR}")
    
    ensure_directories()
    
    if args.high_freq_threshold:
        update_threshold(high_freq_ip=args.high_freq_threshold)
        print(f"高频 IP 阈值已更新: {args.high_freq_threshold}")
    if args.error_rate_threshold:
        update_threshold(error_rate=args.error_rate_threshold)
        print(f"错误率阈值已更新: {args.error_rate_threshold}")
    if args.slow_request_threshold:
        update_threshold(slow_request=args.slow_request_threshold)
        print(f"慢请求阈值已更新: {args.slow_request_threshold}")
    
    if args.wechat_webhook:
        update_alert_webhook(wechat=args.wechat_webhook)
        print("企业微信 Webhook 已配置")
    if args.dingtalk_webhook:
        update_alert_webhook(dingtalk=args.dingtalk_webhook)
        print("钉钉 Webhook 已配置")
    
    print("\n" + "=" * 60)
    print("阶段 1: 日志解析")
    print("=" * 60)
    
    processor = LogFileProcessor()
    
    if args.force:
        processor._hash_record.clear()
        print("已启用强制模式，将重新解析所有文件")
    
    entries, parse_errors = processor.parse_all_files()
    
    if not entries:
        print("\n警告: 未解析到任何日志条目")
        print(f"请确保 {INPUT_DIR} 目录下存在 .log 或 .txt 格式的日志文件")
        return 1
    
    print(f"\n解析完成: {len(entries)} 条日志")
    if parse_errors:
        print(f"解析错误: {len(parse_errors)} 条")
        if args.verbose:
            for error in parse_errors[:10]:
                print(f"  - {error}")
    
    print("\n" + "=" * 60)
    print("阶段 2: 异常检测")
    print("=" * 60)
    
    detector = AnomalyDetector()
    anomalies = detector.detect_all(entries)
    anomaly_summary = detector.get_summary(anomalies)
    
    print(f"\n异常检测完成:")
    print(f"  总计异常: {anomaly_summary['total_anomalies']}")
    for atype, count in anomaly_summary['by_type'].items():
        print(f"  - {atype}: {count}")
    
    if args.verbose and anomaly_summary['total_anomalies'] > 0:
        print("\n异常详情:")
        for atype, anomaly_list in anomalies.items():
            if anomaly_list:
                print(f"\n  [{atype}]:")
                for anomaly in anomaly_list[:5]:
                    print(f"    - {anomaly.description}")
    
    print("\n" + "=" * 60)
    print("阶段 3: 统计分析")
    print("=" * 60)
    
    analyzer = LogAnalyzer()
    
    print("\n计算核心指标...")
    statistics = analyzer.analyze(entries)
    
    print(f"  总请求数 (PV): {statistics.total_requests:,}")
    print(f"  独立访客 (UV): {statistics.unique_ips:,}")
    print(f"  唯一 URL: {statistics.unique_urls:,}")
    print(f"  QPS: {statistics.qps:.2f}")
    if statistics.avg_response_time:
        print(f"  平均响应时间: {statistics.avg_response_time:.3f}s")
    
    print("\n计算按小时统计...")
    hourly_stats = analyzer.analyze_by_hour(entries)
    print(f"  时间段数: {len(hourly_stats)}")
    
    print("\n计算按 URL 统计...")
    url_stats = analyzer.analyze_by_url(entries)
    print(f"  URL 数: {len(url_stats)}")
    
    print("\n计算状态码分布...")
    status_summary = analyzer.get_status_summary(entries)
    print(f"  错误率: {status_summary['error_rate']:.2f}%")
    
    print("\n" + "=" * 60)
    print("阶段 4: 生成报告")
    print("=" * 60)
    
    json_path, md_path = generate_reports(
        statistics, anomalies, hourly_stats, url_stats, 
        status_summary, parse_errors if args.verbose else None
    )
    
    print(f"\n报告已生成:")
    print(f"  JSON 报告: {json_path}")
    print(f"  Markdown 摘要: {md_path}")
    
    if not args.no_alert and anomaly_summary['total_anomalies'] > 0:
        print("\n" + "=" * 60)
        print("阶段 5: 告警推送")
        print("=" * 60)
        
        if ALERT_CONFIG.get('enabled', False):
            alert_result = send_anomaly_alerts(anomalies)
            print(f"\n告警推送完成:")
            print(f"  发送成功: {alert_result['sent']}")
            print(f"  发送失败: {alert_result['failed']}")
            
            if alert_result['failed'] > 0 and args.verbose:
                for result in alert_result['details']:
                    if not result.get('sent'):
                        print(f"  - 失败原因: {result.get('reason', '未知')}")
        else:
            print("\n告警功能已禁用，跳过推送")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 60)
    print("执行完成")
    print("=" * 60)
    print(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总耗时: {duration:.2f} 秒")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n用户中断执行")
        sys.exit(130)
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
