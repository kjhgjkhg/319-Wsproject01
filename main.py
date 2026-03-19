"""
HTTP 日志分析与异常告警工具 - 主程序入口

功能：批量解析 Nginx/Apache 格式的 HTTP 访问日志，
      识别异常请求（高频 IP、4xx/5xx 错误激增、慢速请求），
      生成可视化统计报告，并支持基于规则的自动化告警推送。

用法:
    python main.py                    # 使用默认配置分析日志
    python main.py --reset            # 重置处理记录，重新分析所有日志
    python main.py --no-alert         # 不发送告警
    python main.py --input-dir ./logs # 指定输入目录
    python main.py --output-dir ./out # 指定输出目录
"""

import argparse
import sys
import os

# 导入各模块
from http_parser import LogParser, parse_logs
from http_detector import AnomalyDetector, detect_anomalies
from http_analyzer import LogAnalyzer, analyze_logs
from http_reporter import ReportGenerator, generate_reports
from utils.alert import AlertManager, send_anomaly_alert
from config import INPUT_DIR, OUTPUT_DIR, THRESHOLDS, ALERT_CONFIG


def parse_arguments():
    """
    解析命令行参数
    
    Returns:
        argparse.Namespace: 解析后的参数
    """
    parser = argparse.ArgumentParser(
        description='HTTP 日志分析与异常告警工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                    # 使用默认配置分析日志
  python main.py --reset            # 重置处理记录，重新分析所有日志
  python main.py --no-alert         # 不发送告警
  python main.py --input-dir ./logs # 指定输入目录
  python main.py --output-dir ./out # 指定输出目录
        """
    )
    
    parser.add_argument(
        '--input-dir',
        type=str,
        default=INPUT_DIR,
        help=f'输入目录路径 (默认: {INPUT_DIR})'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default=OUTPUT_DIR,
        help=f'输出目录路径 (默认: {OUTPUT_DIR})'
    )
    
    parser.add_argument(
        '--reset',
        action='store_true',
        help='重置已处理文件记录，重新分析所有日志'
    )
    
    parser.add_argument(
        '--no-alert',
        action='store_true',
        help='不发送告警通知'
    )
    
    parser.add_argument(
        '--alert-types',
        nargs='+',
        choices=['wechat', 'dingtalk'],
        help='指定告警类型 (wechat/dingtalk)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='显示详细输出'
    )
    
    return parser.parse_args()


def validate_environment(args):
    """
    验证运行环境
    
    Args:
        args: 命令行参数
        
    Returns:
        bool: 环境验证是否通过
    """
    # 检查输入目录
    if not os.path.exists(args.input_dir):
        print(f"错误: 输入目录不存在: {args.input_dir}")
        print("请确保日志文件放在该目录中，或使用 --input-dir 指定其他目录")
        return False
    
    # 确保输出目录存在
    os.makedirs(args.output_dir, exist_ok=True)
    
    return True


def main():
    """
    主函数
    
    协调各模块完成日志分析流程：
    1. 解析日志文件
    2. 统计分析
    3. 异常检测
    4. 生成报告
    5. 发送告警（可选）
    """
    # 解析命令行参数
    args = parse_arguments()
    
    print("=" * 60)
    print("HTTP 日志分析与异常告警工具")
    print("=" * 60)
    print()
    
    # 验证环境
    if not validate_environment(args):
        sys.exit(1)
    
    print(f"输入目录: {args.input_dir}")
    print(f"输出目录: {args.output_dir}")
    print()
    
    # 步骤 1: 解析日志
    print("【步骤 1/5】解析日志文件...")
    print("-" * 40)
    
    parser = LogParser()
    
    # 如果需要重置，清除处理记录
    if args.reset:
        print("重置处理记录...")
        parser.reset_processed_records()
    
    try:
        logs = list(parser.parse_directory(args.input_dir, skip_processed=not args.reset))
    except Exception as e:
        print(f"错误: 解析日志失败: {e}")
        sys.exit(1)
    
    if not logs:
        print("警告: 没有解析到任何日志记录")
        print("请检查：")
        print("  1. 输入目录中是否有 .log 或 .txt 格式的日志文件")
        print("  2. 日志格式是否为 Nginx Combined Log Format")
        print("  3. 使用 --reset 参数重新处理所有文件")
        sys.exit(0)
    
    print(f"成功解析 {len(logs)} 条日志记录")
    print()
    
    # 步骤 2: 统计分析
    print("【步骤 2/5】统计分析...")
    print("-" * 40)
    
    try:
        analyzer = LogAnalyzer()
        stats = analyzer.analyze_all(logs)
    except Exception as e:
        print(f"错误: 统计分析失败: {e}")
        sys.exit(1)
    
    print()
    
    # 步骤 3: 异常检测
    print("【步骤 3/5】异常检测...")
    print("-" * 40)
    
    try:
        detector = AnomalyDetector()
        anomalies = detector.detect_all_anomalies(logs)
    except Exception as e:
        print(f"错误: 异常检测失败: {e}")
        sys.exit(1)
    
    print()
    
    # 步骤 4: 生成报告
    print("【步骤 4/5】生成报告...")
    print("-" * 40)
    
    try:
        generator = ReportGenerator(args.output_dir)
        report_paths = generator.generate_all_reports(stats, anomalies)
        
        print()
        print("报告生成完成:")
        for report_type, path in report_paths.items():
            print(f"  - {report_type}: {path}")
    except Exception as e:
        print(f"错误: 生成报告失败: {e}")
        sys.exit(1)
    
    print()
    
    # 步骤 5: 发送告警
    if not args.no_alert:
        print("【步骤 5/5】发送告警...")
        print("-" * 40)
        
        try:
            alert_manager = AlertManager()
            
            # 检查是否有异常需要告警
            summary = anomalies.get('summary', {})
            if summary.get('total_anomalies', 0) > 0:
                results = alert_manager.send_anomaly_alert(anomalies, stats)
                
                if results:
                    print()
                    print("告警发送结果:")
                    for channel, success in results.items():
                        if success is None:
                            status = "未启用"
                        elif success:
                            status = "成功"
                        else:
                            status = "失败"
                        print(f"  - {channel}: {status}")
                else:
                    print("没有启用任何告警渠道，告警信息已记录到日志")
            else:
                print("未检测到异常，无需发送告警")
                
        except Exception as e:
            print(f"警告: 发送告警失败: {e}")
            print("告警信息已记录到日志文件")
    else:
        print("【步骤 5/5】跳过告警发送 (--no-alert)")
    
    print()
    print("=" * 60)
    print("分析完成!")
    print("=" * 60)
    
    # 输出统计摘要
    basic = stats.get('basic_metrics', {})
    pv_uv = stats.get('pv_uv', {})
    qps = stats.get('qps', {})
    
    print()
    print("统计摘要:")
    print(f"  总请求数 (PV): {pv_uv.get('pv', 0):,}")
    print(f"  独立访客 (UV): {pv_uv.get('uv', 0):,}")
    print(f"  整体 QPS: {qps.get('overall_qps', 0)}")
    print(f"  峰值 QPS: {qps.get('peak_qps', 0)}")
    
    # 输出异常摘要
    summary = anomalies.get('summary', {})
    print()
    print("异常摘要:")
    print(f"  高频 IP: {summary.get('high_frequency_ip_count', 0)} 个")
    print(f"  5xx 错误激增: {summary.get('server_error_spike_count', 0)} 个时间段")
    print(f"  慢速请求: {summary.get('slow_request_count', 0)} 个")


if __name__ == '__main__':
    main()
