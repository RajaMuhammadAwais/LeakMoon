#!/usr/bin/env python3
"""
LeakMon - Real-Time Secret & PII Leak Detection
Main CLI application entry point
"""

import os
import sys
import argparse
import signal
import time
from pathlib import Path

# Add the current directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.file_watcher import FileWatcher
from core.secret_detector import SecretDetector, Detection
from core.logger import LeakMonLogger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout


class LeakMonCLI:
    """Command-line interface for LeakMon"""
    
    def __init__(self):
        self.console = Console()
        self.logger = LeakMonLogger()
        self.file_watcher = None
        self.is_running = False
        self.detections_count = 0
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signal"""
        self.console.print("\n🛑 Stopping LeakMon...")
        self.stop_monitoring()
        sys.exit(0)
    
    def detection_callback(self, filepath: str, detections: list):
        """Callback for when secrets are detected"""
        self.detections_count += len(detections)
        
        # Log detections
        self.logger.log_detection(filepath, detections)
        
        # Display detections
        for detection in detections:
            self.display_detection(filepath, detection)
    
    def display_detection(self, filepath: str, detection: Detection):
        """Display a detection in the console"""
        severity_colors = {
            'high': 'red',
            'medium': 'yellow',
            'low': 'cyan'
        }
        
        severity_icons = {
            'high': '🚨',
            'medium': '⚠️',
            'low': 'ℹ️'
        }
        
        color = severity_colors.get(detection.severity.value, 'white')
        icon = severity_icons.get(detection.severity.value, '🔍')
        
        # Create detection panel
        detection_text = Text()
        detection_text.append(f"{icon} ", style="bold")
        detection_text.append(f"{detection.type.replace('_', ' ').title()}", style=f"bold {color}")
        detection_text.append(f" (Confidence: {detection.confidence:.0%})", style="dim")
        
        details = f"""File: {filepath}:{detection.line_number}
Context: {detection.context}
Preview: {detection.value[:50]}{'...' if len(detection.value) > 50 else ''}"""
        
        panel = Panel(
            details,
            title=detection_text,
            border_style=color,
            padding=(0, 1)
        )
        
        self.console.print(panel)
    
    def start_monitoring(self, paths: list):
        """Start file monitoring"""
        if self.is_running:
            self.console.print("❌ Already monitoring", style="red")
            return
        
        self.console.print("🛡️ Starting LeakMon...", style="bold blue")
        
        # Validate paths
        valid_paths = []
        for path in paths:
            if os.path.exists(path):
                valid_paths.append(path)
                self.console.print(f"✅ Watching: {path}", style="green")
            else:
                self.console.print(f"❌ Path not found: {path}", style="red")
        
        if not valid_paths:
            self.console.print("❌ No valid paths to monitor", style="red")
            return
        
        # Start file watcher
        self.file_watcher = FileWatcher(valid_paths, self.detection_callback)
        self.file_watcher.start()
        
        # Perform initial scan
        self.console.print("🔍 Performing initial scan...", style="yellow")
        self.file_watcher.scan_existing_files()
        
        self.is_running = True
        self.logger.log_event('monitoring_started', f'Started monitoring: {valid_paths}')
        
        self.console.print("✅ LeakMon is now monitoring for secrets and PII", style="bold green")
        self.console.print("Press Ctrl+C to stop monitoring", style="dim")
        
        # Keep running
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop file monitoring"""
        if not self.is_running:
            return
        
        if self.file_watcher:
            self.file_watcher.stop()
        
        self.is_running = False
        self.logger.log_event('monitoring_stopped', 'Stopped monitoring')
        self.console.print("🛑 LeakMon stopped", style="bold red")
    
    def scan_now(self, paths: list):
        """Perform one-time scan"""
        self.console.print("🔍 Scanning for secrets and PII...", style="bold blue")
        
        detector = SecretDetector()
        total_files = 0
        total_detections = 0
        
        for path in paths:
            if not os.path.exists(path):
                self.console.print(f"❌ Path not found: {path}", style="red")
                continue
            
            if os.path.isfile(path):
                # Single file
                detections = detector.scan_file(path)
                total_files += 1
                if detections:
                    total_detections += len(detections)
                    for detection in detections:
                        self.display_detection(path, detection)
            else:
                # Directory
                for root, dirs, files in os.walk(path):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for file in files:
                        if file.startswith('.'):
                            continue
                        
                        filepath = os.path.join(root, file)
                        try:
                            detections = detector.scan_file(filepath)
                            total_files += 1
                            if detections:
                                total_detections += len(detections)
                                for detection in detections:
                                    self.display_detection(filepath, detection)
                        except Exception as e:
                            self.console.print(f"Error scanning {filepath}: {e}", style="red")
        
        # Summary
        summary_text = f"Scan complete: {total_files} files scanned, {total_detections} detections found"
        if total_detections == 0:
            self.console.print(f"✅ {summary_text}", style="bold green")
        else:
            self.console.print(f"⚠️ {summary_text}", style="bold yellow")
    
    def show_report(self, date: str = None):
        """Show daily report"""
        report = self.logger.get_daily_report(date)
        
        # Create report table
        table = Table(title=f"LeakMon Report - {report['date']}")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        
        table.add_row("Total Detections", str(report['total_detections']))
        table.add_row("High Severity", str(report['by_severity']['high']))
        table.add_row("Medium Severity", str(report['by_severity']['medium']))
        table.add_row("Low Severity", str(report['by_severity']['low']))
        table.add_row("Files Affected", str(len(report['files_affected'])))
        
        self.console.print(table)
        
        # Show detection types
        if report['by_type']:
            type_table = Table(title="Detection Types")
            type_table.add_column("Type", style="cyan")
            type_table.add_column("Count", style="magenta")
            
            for detection_type, count in report['by_type'].items():
                type_table.add_row(detection_type.replace('_', ' ').title(), str(count))
            
            self.console.print(type_table)
    
    def show_stats(self, days: int = 7):
        """Show summary statistics"""
        stats = self.logger.get_summary_stats(days)
        
        # Create stats table
        table = Table(title=f"LeakMon Statistics - Last {days} Days")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Period", stats['period'])
        table.add_row("Total Detections", str(stats['total_detections']))
        table.add_row("High Severity", str(stats['by_severity']['high']))
        table.add_row("Medium Severity", str(stats['by_severity']['medium']))
        table.add_row("Low Severity", str(stats['by_severity']['low']))
        table.add_row("Unique Files", str(len(stats['unique_files'])))
        
        self.console.print(table)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="LeakMon - Real-Time Secret & PII Leak Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  leakmon init                    # Start monitoring current directory
  leakmon --scan-now              # Scan current directory once
  leakmon --paths /path1,/path2   # Monitor specific paths
  leakmon --report                # Show daily report
  leakmon --stats --days 30       # Show 30-day statistics
  leakmon --web                   # Start web interface
        """
    )
    
    parser.add_argument('command', nargs='?', default='init',
                       choices=['init', 'start', 'scan'],
                       help='Command to execute (default: init)')
    
    parser.add_argument('--paths', type=str, default='.',
                       help='Comma-separated paths to monitor (default: current directory)')
    
    parser.add_argument('--scan-now', action='store_true',
                       help='Perform one-time scan instead of monitoring')
    
    parser.add_argument('--report', action='store_true',
                       help='Show daily report')
    
    parser.add_argument('--date', type=str,
                       help='Date for report (YYYY-MM-DD, default: today)')
    
    parser.add_argument('--stats', action='store_true',
                       help='Show summary statistics')
    
    parser.add_argument('--days', type=int, default=7,
                       help='Number of days for statistics (default: 7)')
    
    parser.add_argument('--web', action='store_true',
                       help='Start web interface')
    
    args = parser.parse_args()
    
    cli = LeakMonCLI()
    
    # Parse paths
    paths = [p.strip() for p in args.paths.split(',') if p.strip()]
    
    try:
        if args.web:
            # Start web interface
            cli.console.print("🌐 Starting LeakMon Web Interface...", style="bold blue")
            cli.console.print("📊 Dashboard will be available at: http://localhost:5000", style="green")
            
            # Import and run web app
            from web.app import socketio, app
            socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
            
        elif args.report:
            cli.show_report(args.date)
            
        elif args.stats:
            cli.show_stats(args.days)
            
        elif args.scan_now:
            cli.scan_now(paths)
            
        else:
            # Default: start monitoring
            cli.start_monitoring(paths)
            
    except Exception as e:
        cli.console.print(f"❌ Error: {e}", style="bold red")
        sys.exit(1)


if __name__ == '__main__':
    main()

