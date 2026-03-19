"""
HTTP 日志解析模块

该模块负责解析 Nginx/Apache 格式的 HTTP 访问日志，
提取标准化字段并返回结构化数据。
"""

import re
import hashlib
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent))
from config.settings import (
    LOG_PATTERNS, DATETIME_FORMATS, INPUT_DIR, 
    OUTPUT_DIR, ALLOWED_EXTENSIONS, IGNORE_PREFIX,
    HASH_RECORD_FILE, get_output_path
)


@dataclass
class LogEntry:
    """
    日志条目数据类，存储单条日志的解析结果。
    
    Attributes:
        ip: 客户端 IP 地址
        timestamp: 请求时间戳
        method: HTTP 请求方法（GET/POST/PUT/DELETE 等）
        url: 请求的 URL 路径
        protocol: HTTP 协议版本
        status: HTTP 响应状态码
        bytes_sent: 响应字节数
        referer: 请求来源页面
        user_agent: 客户端 User-Agent
        response_time: 响应时间（秒），可选
        raw_line: 原始日志行，用于调试
        file_path: 日志文件路径
        line_number: 日志行号
    """
    ip: str
    timestamp: Optional[datetime]
    method: str
    url: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    response_time: Optional[float] = None
    raw_line: str = ""
    file_path: str = ""
    line_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """
        将日志条目转换为字典格式。
        
        Returns:
            包含所有字段的字典，时间戳转换为 ISO 格式字符串
        """
        result = asdict(self)
        if self.timestamp:
            result['timestamp'] = self.timestamp.isoformat()
        return result


class LogParser:
    """
    日志解析器类，负责解析单条日志行。
    
    支持多种 Nginx/Apache 日志格式，自动识别并提取字段。
    """
    
    def __init__(self):
        """初始化解析器，编译正则表达式模式。"""
        self._patterns: Dict[str, re.Pattern] = {}
        for name, pattern in LOG_PATTERNS.items():
            self._patterns[name] = re.compile(pattern)
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        解析时间戳字符串为 datetime 对象。
        
        Args:
            timestamp_str: 时间戳字符串
            
        Returns:
            解析后的 datetime 对象，解析失败返回 None
        """
        for fmt in DATETIME_FORMATS:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        return None
    
    def parse_line(self, line: str, file_path: str = "", 
                   line_number: int = 0) -> Optional[LogEntry]:
        """
        解析单条日志行。
        
        Args:
            line: 原始日志行
            file_path: 日志文件路径（用于追踪）
            line_number: 行号（用于追踪）
            
        Returns:
            解析成功返回 LogEntry 对象，失败返回 None
        """
        line = line.strip()
        if not line:
            return None
        
        for pattern_name, pattern in self._patterns.items():
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                
                timestamp = self._parse_timestamp(groups.get('timestamp', ''))
                
                response_time = None
                if groups.get('response_time'):
                    try:
                        response_time = float(groups['response_time'])
                    except ValueError:
                        pass
                
                try:
                    status = int(groups.get('status', 0))
                    bytes_sent = int(groups.get('bytes', 0))
                except ValueError:
                    status = 0
                    bytes_sent = 0
                
                return LogEntry(
                    ip=groups.get('ip', ''),
                    timestamp=timestamp,
                    method=groups.get('method', ''),
                    url=groups.get('url', ''),
                    protocol=groups.get('protocol', ''),
                    status=status,
                    bytes_sent=bytes_sent,
                    referer=groups.get('referer', ''),
                    user_agent=groups.get('user_agent', ''),
                    response_time=response_time,
                    raw_line=line,
                    file_path=str(file_path),
                    line_number=line_number
                )
        
        return None


class LogFileProcessor:
    """
    日志文件处理器，负责批量处理日志文件。
    
    支持文件过滤、增量处理和错误处理。
    """
    
    def __init__(self, parser: Optional[LogParser] = None):
        """
        初始化文件处理器。
        
        Args:
            parser: 日志解析器实例，不提供则创建新实例
        """
        self.parser = parser or LogParser()
        self._hash_record: Dict[str, str] = {}
        self._load_hash_record()
    
    def _load_hash_record(self) -> None:
        """加载已处理文件的哈希记录。"""
        hash_file = get_output_path(HASH_RECORD_FILE)
        if hash_file.exists():
            try:
                with open(hash_file, 'r', encoding='utf-8') as f:
                    self._hash_record = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._hash_record = {}
    
    def _save_hash_record(self) -> None:
        """保存已处理文件的哈希记录。"""
        hash_file = get_output_path(HASH_RECORD_FILE)
        try:
            with open(hash_file, 'w', encoding='utf-8') as f:
                json.dump(self._hash_record, f, indent=2)
        except IOError as e:
            print(f"警告：无法保存哈希记录文件: {e}")
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """
        计算文件的 MD5 哈希值。
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件的 MD5 哈希值
        """
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except IOError:
            return ""
    
    def _should_process_file(self, file_path: Path) -> Tuple[bool, str]:
        """
        判断文件是否应该被处理。
        
        Args:
            file_path: 文件路径
            
        Returns:
            (是否处理, 原因) 元组
        """
        if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
            return False, f"文件扩展名不在允许列表中: {file_path.suffix}"
        
        if file_path.name.startswith(IGNORE_PREFIX):
            return False, f"文件名以 {IGNORE_PREFIX} 开头，已忽略"
        
        file_hash = self._calculate_file_hash(file_path)
        file_key = str(file_path)
        
        if file_key in self._hash_record:
            if self._hash_record[file_key] == file_hash:
                return False, "文件内容未变化，已跳过（增量处理）"
        
        return True, file_hash
    
    def get_log_files(self) -> List[Path]:
        """
        获取所有需要处理的日志文件列表。
        
        Returns:
            符合条件的日志文件路径列表
        """
        if not INPUT_DIR.exists():
            print(f"警告：输入目录不存在: {INPUT_DIR}")
            return []
        
        log_files = []
        for file_path in INPUT_DIR.iterdir():
            if file_path.is_file():
                should_process, _ = self._should_process_file(file_path)
                if should_process:
                    log_files.append(file_path)
        
        return sorted(log_files)
    
    def parse_file(self, file_path: Path) -> Tuple[List[LogEntry], List[Dict[str, Any]]]:
        """
        解析单个日志文件。
        
        Args:
            file_path: 日志文件路径
            
        Returns:
            (解析成功的日志条目列表, 解析失败的行信息列表)
        """
        entries: List[LogEntry] = []
        errors: List[Dict[str, Any]] = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    entry = self.parser.parse_line(line, str(file_path), line_number)
                    if entry:
                        entries.append(entry)
                    else:
                        errors.append({
                            'file': str(file_path),
                            'line_number': line_number,
                            'line': line.strip()[:200],
                            'error': '无法匹配日志格式'
                        })
        except IOError as e:
            errors.append({
                'file': str(file_path),
                'line_number': 0,
                'line': '',
                'error': f'文件读取失败: {e}'
            })
            return entries, errors
        
        _, file_hash = self._should_process_file(file_path)
        if file_hash:
            self._hash_record[str(file_path)] = file_hash
        
        return entries, errors
    
    def parse_all_files(self) -> Tuple[List[LogEntry], List[Dict[str, Any]]]:
        """
        解析所有日志文件。
        
        Returns:
            (所有解析成功的日志条目, 所有解析错误信息)
        """
        all_entries: List[LogEntry] = []
        all_errors: List[Dict[str, Any]] = []
        
        log_files = self.get_log_files()
        print(f"发现 {len(log_files)} 个待处理日志文件")
        
        for file_path in log_files:
            print(f"正在解析: {file_path.name}")
            entries, errors = self.parse_file(file_path)
            all_entries.extend(entries)
            all_errors.extend(errors)
            
            if errors:
                print(f"  - 解析成功: {len(entries)} 条, 失败: {len(errors)} 条")
            else:
                print(f"  - 解析成功: {len(entries)} 条")
        
        self._save_hash_record()
        
        return all_entries, all_errors


def parse_log_files() -> Tuple[List[LogEntry], List[Dict[str, Any]]]:
    """
    便捷函数：解析所有日志文件。
    
    Returns:
        (所有解析成功的日志条目, 所有解析错误信息)
    """
    processor = LogFileProcessor()
    return processor.parse_all_files()


if __name__ == "__main__":
    entries, errors = parse_log_files()
    print(f"\n总计解析: {len(entries)} 条日志")
    if errors:
        print(f"解析错误: {len(errors)} 条")
        for error in errors[:5]:
            print(f"  - {error}")
