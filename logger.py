"""
Logging Module for LeakMon
Handles audit logs and reporting of detected secrets.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
from .secret_detector import Detection, SeverityLevel


class LeakMonLogger:
    """Logger for LeakMon detections and events"""
    
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.path.expanduser("~/.leakmon/logs")
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log files
        self.detections_log = self.log_dir / "detections.jsonl"
        self.events_log = self.log_dir / "events.jsonl"
        
    def log_detection(self, filepath: str, detections: List[Detection]):
        """Log detected secrets to the detections log"""
        timestamp = datetime.now().isoformat()
        
        for detection in detections:
            log_entry = {
                "timestamp": timestamp,
                "filepath": filepath,
                "type": detection.type,
                "severity": detection.severity.value,
                "confidence": detection.confidence,
                "line_number": detection.line_number,
                "column_start": detection.column_start,
                "column_end": detection.column_end,
                "context": detection.context,
                "value_hash": self._hash_value(detection.value)  # Don't log actual secret
            }
            
            self._write_log_entry(self.detections_log, log_entry)
    
    def log_event(self, event_type: str, message: str, metadata: Dict[str, Any] = None):
        """Log general events"""
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "message": message,
            "metadata": metadata or {}
        }
        
        self._write_log_entry(self.events_log, log_entry)
    
    def _write_log_entry(self, log_file: Path, entry: Dict[str, Any]):
        """Write a log entry to the specified file"""
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"Error writing to log file {log_file}: {e}")
    
    def _hash_value(self, value: str) -> str:
        """Create a hash of the detected value for logging purposes"""
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()[:16]
    
    def get_daily_report(self, date: str = None) -> Dict[str, Any]:
        """Generate a daily report of detections"""
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")
        
        report = {
            "date": date,
            "total_detections": 0,
            "by_severity": {
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "by_type": {},
            "files_affected": set(),
            "detections": []
        }
        
        try:
            with open(self.detections_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_date = entry["timestamp"][:10]  # Extract date part
                        
                        if entry_date == date:
                            report["total_detections"] += 1
                            report["by_severity"][entry["severity"]] += 1
                            
                            detection_type = entry["type"]
                            report["by_type"][detection_type] = report["by_type"].get(detection_type, 0) + 1
                            
                            report["files_affected"].add(entry["filepath"])
                            report["detections"].append(entry)
                    
                    except json.JSONDecodeError:
                        continue
        
        except FileNotFoundError:
            pass
        
        # Convert set to list for JSON serialization
        report["files_affected"] = list(report["files_affected"])
        
        return report
    
    def get_summary_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get summary statistics for the last N days"""
        from datetime import timedelta
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        stats = {
            "period": f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
            "total_detections": 0,
            "by_severity": {"high": 0, "medium": 0, "low": 0},
            "by_type": {},
            "unique_files": set(),
            "daily_counts": {}
        }
        
        try:
            with open(self.detections_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_datetime = datetime.fromisoformat(entry["timestamp"])
                        
                        if start_date <= entry_datetime <= end_date:
                            stats["total_detections"] += 1
                            stats["by_severity"][entry["severity"]] += 1
                            
                            detection_type = entry["type"]
                            stats["by_type"][detection_type] = stats["by_type"].get(detection_type, 0) + 1
                            
                            stats["unique_files"].add(entry["filepath"])
                            
                            date_key = entry_datetime.strftime("%Y-%m-%d")
                            stats["daily_counts"][date_key] = stats["daily_counts"].get(date_key, 0) + 1
                    
                    except (json.JSONDecodeError, ValueError):
                        continue
        
        except FileNotFoundError:
            pass
        
        # Convert set to list for JSON serialization
        stats["unique_files"] = list(stats["unique_files"])
        
        return stats

