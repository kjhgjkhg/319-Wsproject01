"""
HTTP 日志解析模块

功能：解析 Nginx Combined Log Format 格式的 HTTP 访问日志，
      提取标准化字段（IP、时间戳、请求方法、URL、状态码、响应时间等）
"""

import re
import os
import hashlib
from datetime import datetime
from typing import Iterator, Dict, Any, Optional, Tuple
from fnmatch import fnmatch

from config import (
    INPUT_DIR,
    ALLOWED_EXTENSIONS,
    IGNORE_PATTERN,
    NGINX_LOG_PATTERN,
    TIME_FORMAT,
    PROCESSED_FILES_RECORD,
)


class LogParser:
    """
    HTTP 日志解析器类
    
    支持解析标准 Nginx Combined Log Format 日志，
    自动识别请求方法、URL、状态码、响应时间、客户端 IP 等字段
    """
    
    def __init__(self):
        """初始化解析器，编译正则表达式"""
        self.pattern = re.compile(NGINX_LOG_PATTERN, re.VERBOSE)
        self.processed_files = self._load_processed_files()
    
    def _load_processed_files(self) -> Dict[str, str]:
        """
        加载已处理文件的哈希记录
        
        Returns:
            Dict[str, str]: 文件名到哈希值的映射字典
        """
        if os.path.exists(PROCESSED_FILES_RECORD):
            try:
                import json
                with open(PROCESSED_FILES_RECORD, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"警告: 无法加载已处理文件记录: {e}")
                return {}
        return {}
    
    def _save_processed_files(self):
        """保存已处理文件的哈希记录"""
        try:
            import json
            os.makedirs(os.path.dirname(PROCESSED_FILES_RECORD), exist_ok=True)
            with open(PROCESSED_FILES_RECORD, 'w', encoding='utf-8') as f:
                json.dump(self.processed_files, f, ensure_ascii=False, indent=2)
        except IOError as e:
            print(f"警告: 无法保存已处理文件记录: {e}")
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """
        计算文件的 MD5 哈希值
        
        Args:
            filepath: 文件路径
            
        Returns:
            str: 文件的 MD5 哈希值
        """
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
        except IOError as e:
            print(f"警告: 无法读取文件 {filepath}: {e}")
            return ""
        return hash_md5.hexdigest()
    
    def _is_file_processed(self, filepath: str) -> bool:
        """
        检查文件是否已处理（基于哈希值）
        
        Args:
            filepath: 文件路径
            
        Returns:
            bool: 如果文件已处理且未变更返回 True
        """
        filename = os.path.basename(filepath)
        current_hash = self._calculate_file_hash(filepath)
        
        if not current_hash:
            return False
            
        if filename in self.processed_files:
            return self.processed_files[filename] == current_hash
        return False
    
    def _mark_file_processed(self, filepath: str):
        """
        标记文件为已处理
        
        Args:
            filepath: 文件路径
        """
        filename = os.path.basename(filepath)
        file_hash = self._calculate_file_hash(filepath)
        if file_hash:
            self.processed_files[filename] = file_hash
            self._save_processed_files()
    
    def _should_parse_file(self, filename: str) -> bool:
        """
        判断文件是否应该被解析
        
        规则：
        1. 文件扩展名必须是 .log 或 .txt
        2. 文件名不能匹配 ignore_*.log 模式
        
        Args:
            filename: 文件名
            
        Returns:
            bool: 如果文件应该被解析返回 True
        """
        # 检查扩展名
        if not filename.endswith(ALLOWED_EXTENSIONS):
            return False
        
        # 检查是否匹配忽略模式
        if fnmatch(filename, IGNORE_PATTERN):
            return False
        
        return True
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        解析时间戳字符串
        
        Args:
            timestamp_str: 时间戳字符串，格式如 "01/Jan/2024:12:00:00 +0800"
            
        Returns:
            Optional[datetime]: 解析后的 datetime 对象，解析失败返回 None
        """
        try:
            # 处理时区格式
            timestamp_str = timestamp_str.replace('+0800', ' +0800')
            return datetime.strptime(timestamp_str.strip(), TIME_FORMAT)
        except ValueError as e:
            print(f"警告: 无法解析时间戳 '{timestamp_str}': {e}")
            return None
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        解析单行日志
        
        Args:
            line: 日志行字符串
            
        Returns:
            Optional[Dict[str, Any]]: 解析后的字段字典，解析失败返回 None
            包含字段: ip, user, timestamp, method, url, protocol, status, 
                    bytes, referer, user_agent, response_time
        """
        line = line.strip()
        if not line:
            return None
        
        match = self.pattern.match(line)
        if not match:
            print(f"警告: 无法解析日志行: {line[:100]}...")
            return None
        
        data = match.groupdict()
        
        # 转换数据类型
        try:
            parsed_data = {
                'ip': data['ip'],
                'user': data['user'] if data['user'] != '-' else None,
                'timestamp': self._parse_timestamp(data['timestamp']),
                'method': data['method'],
                'url': data['url'],
                'protocol': data['protocol'],
                'status': int(data['status']),
                'bytes': int(data['bytes']),
                'referer': data['referer'] if data['referer'] != '-' else None,
                'user_agent': data['user_agent'],
                'response_time': float(data['response_time']) if data.get('response_time') else None,
            }
            
            # 如果时间戳解析失败，返回 None
            if parsed_data['timestamp'] is None:
                return None
                
            return parsed_data
            
        except (ValueError, TypeError) as e:
            print(f"警告: 数据类型转换失败: {e}")
            return None
    
    def parse_file(self, filepath: str, skip_processed: bool = True) -> Iterator[Dict[str, Any]]:
        """
        解析单个日志文件
        
        Args:
            filepath: 日志文件路径
            skip_processed: 是否跳过已处理的文件（增量处理）
            
        Yields:
            Dict[str, Any]: 解析后的日志记录字典
        """
        filename = os.path.basename(filepath)
        
        # 检查是否应该解析
        if not self._should_parse_file(filename):
            print(f"跳过文件（不符合规则）: {filename}")
            return
        
        # 检查是否已处理
        if skip_processed and self._is_file_processed(filepath):
            print(f"跳过文件（已处理）: {filename}")
            return
        
        print(f"正在解析文件: {filename}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                error_count = 0
                
                for line in f:
                    line_count += 1
                    parsed = self.parse_line(line)
                    if parsed:
                        parsed['source_file'] = filename
                        parsed['line_number'] = line_count
                        yield parsed
                    else:
                        error_count += 1
                
                print(f"文件 {filename} 解析完成: {line_count} 行, {error_count} 个错误")
                
                # 标记为已处理
                self._mark_file_processed(filepath)
                
        except IOError as e:
            print(f"错误: 无法读取文件 {filepath}: {e}")
    
    def parse_directory(self, directory: str = None, skip_processed: bool = True) -> Iterator[Dict[str, Any]]:
        """
        解析目录中的所有日志文件
        
        Args:
            directory: 日志目录路径，默认使用配置中的 INPUT_DIR
            skip_processed: 是否跳过已处理的文件
            
        Yields:
            Dict[str, Any]: 解析后的日志记录字典
        """
        if directory is None:
            directory = INPUT_DIR
        
        if not os.path.exists(directory):
            print(f"错误: 输入目录不存在: {directory}")
            return
        
        if not os.path.isdir(directory):
            print(f"错误: 路径不是目录: {directory}")
            return
        
        files = os.listdir(directory)
        log_files = [f for f in files if self._should_parse_file(f)]
        
        if not log_files:
            print(f"警告: 目录 {directory} 中没有找到符合条件的日志文件")
            return
        
        print(f"找到 {len(log_files)} 个待解析文件")
        
        for filename in log_files:
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                yield from self.parse_file(filepath, skip_processed)
    
    def reset_processed_records(self):
        """重置已处理文件记录（用于重新处理所有文件）"""
        self.processed_files = {}
        if os.path.exists(PROCESSED_FILES_RECORD):
            try:
                os.remove(PROCESSED_FILES_RECORD)
                print("已重置处理记录")
            except IOError as e:
                print(f"警告: 无法删除处理记录文件: {e}")


# 便捷函数
def parse_logs(directory: str = None, skip_processed: bool = True) -> list:
    """
    便捷函数：解析目录中的所有日志并返回列表
    
    Args:
        directory: 日志目录路径
        skip_processed: 是否跳过已处理的文件
        
    Returns:
        list: 解析后的日志记录列表
    """
    parser = LogParser()
    return list(parser.parse_directory(directory, skip_processed))
