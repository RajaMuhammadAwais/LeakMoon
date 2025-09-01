"""
LeakMon Core Module
Contains the main functionality for secret detection and file watching.
"""

from .secret_detector import SecretDetector, Detection, SeverityLevel
from .file_watcher import FileWatcher

__all__ = ['SecretDetector', 'Detection', 'SeverityLevel', 'FileWatcher']

