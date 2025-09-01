"""
File Watcher Module for LeakMon
Monitors file system changes in real-time using watchdog.
"""

import os
import time
from pathlib import Path
from typing import Callable, List, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from .secret_detector import SecretDetector, Detection


class LeakMonEventHandler(FileSystemEventHandler):
    """Custom event handler for file system events"""
    
    def __init__(self, callback: Callable[[str, List[Detection]], None]):
        super().__init__()
        self.callback = callback
        self.detector = SecretDetector()
        self.ignored_extensions = {'.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', 
                                 '.bin', '.obj', '.o', '.a', '.lib', '.zip', '.tar', 
                                 '.gz', '.bz2', '.7z', '.rar', '.pdf', '.doc', '.docx',
                                 '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.jpeg', 
                                 '.png', '.gif', '.bmp', '.svg', '.ico', '.mp3', 
                                 '.mp4', '.avi', '.mov', '.wmv', '.flv'}
        self.ignored_dirs = {'.git', '.svn', '.hg', '__pycache__', 'node_modules', 
                           '.venv', 'venv', '.env', 'env', '.tox', 'dist', 'build',
                           '.pytest_cache', '.coverage', '.mypy_cache'}
        
    def should_ignore_file(self, filepath: str) -> bool:
        """Check if file should be ignored based on extension or path"""
        path = Path(filepath)
        
        # Check file extension
        if path.suffix.lower() in self.ignored_extensions:
            return True
        
        # Check if file is in ignored directory
        for part in path.parts:
            if part in self.ignored_dirs:
                return True
        
        # Check file size (ignore very large files)
        try:
            if os.path.getsize(filepath) > 10 * 1024 * 1024:  # 10MB
                return True
        except OSError:
            return True
        
        return False
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and not self.should_ignore_file(event.src_path):
            self.scan_file(event.src_path)
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and not self.should_ignore_file(event.src_path):
            # Small delay to ensure file is fully written
            time.sleep(0.1)
            self.scan_file(event.src_path)
    
    def scan_file(self, filepath: str):
        """Scan a file for secrets and call callback if any found"""
        try:
            detections = self.detector.scan_file(filepath)
            if detections:
                self.callback(filepath, detections)
        except Exception as e:
            print(f"Error scanning file {filepath}: {e}")


class FileWatcher:
    """Main file watcher class"""
    
    def __init__(self, watch_paths: List[str], callback: Callable[[str, List[Detection]], None]):
        self.watch_paths = watch_paths
        self.callback = callback
        self.observer = Observer()
        self.event_handler = LeakMonEventHandler(callback)
        self.is_running = False
        
    def start(self):
        """Start watching the specified paths"""
        if self.is_running:
            return
        
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.event_handler, path, recursive=True)
                print(f"🔍 Watching: {path}")
            else:
                print(f"⚠️  Path does not exist: {path}")
        
        self.observer.start()
        self.is_running = True
        print("🛡️  LeakMon file watcher started")
    
    def stop(self):
        """Stop watching"""
        if not self.is_running:
            return
        
        self.observer.stop()
        self.observer.join()
        self.is_running = False
        print("🛑 LeakMon file watcher stopped")
    
    def scan_existing_files(self):
        """Perform initial scan of existing files"""
        print("🔍 Performing initial scan of existing files...")
        detector = SecretDetector()
        total_files = 0
        total_detections = 0
        
        for watch_path in self.watch_paths:
            if not os.path.exists(watch_path):
                continue
                
            for root, dirs, files in os.walk(watch_path):
                # Remove ignored directories from dirs list to prevent walking into them
                dirs[:] = [d for d in dirs if d not in self.event_handler.ignored_dirs]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    if self.event_handler.should_ignore_file(filepath):
                        continue
                    
                    total_files += 1
                    try:
                        detections = detector.scan_file(filepath)
                        if detections:
                            total_detections += len(detections)
                            self.callback(filepath, detections)
                    except Exception as e:
                        print(f"Error scanning {filepath}: {e}")
        
        print(f"✅ Initial scan complete: {total_files} files scanned, {total_detections} detections found")
    
    def is_watching(self) -> bool:
        """Check if watcher is currently running"""
        return self.is_running

