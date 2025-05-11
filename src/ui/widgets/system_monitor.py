from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QTableWidget, QTableWidgetItem, QGroupBox, QComboBox)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
import psutil
import time
from datetime import datetime
import pyqtgraph as pg
from collections import deque
from src.utils.remote_connection import RemoteConnection

class SystemMonitorWidget(QWidget):
    """Widget for monitoring system resources and processes"""
    
    def __init__(self, parent=None, advanced=False, remote: RemoteConnection = None):
        super().__init__(parent)
        self.advanced = advanced
        self.remote = remote
        self.setup_ui()
        self.setup_graphs()
        self.setup_timer()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # Resource usage section
        resources_group = QGroupBox("System Resources")
        resources_layout = QVBoxLayout(resources_group)
        
        # CPU Usage
        cpu_group = QGroupBox("CPU Usage")
        cpu_layout = QVBoxLayout(cpu_group)
        
        self.cpu_graph = pg.PlotWidget()
        self.cpu_graph.setBackground('w')
        self.cpu_graph.setLabel('left', 'Usage', units='%')
        self.cpu_graph.setLabel('bottom', 'Time', units='s')
        self.cpu_graph.showGrid(x=True, y=True)
        cpu_layout.addWidget(self.cpu_graph)
        
        # CPU per core
        self.cpu_cores = {}
        cores_layout = QHBoxLayout()
        
        # Get CPU count from remote if available
        cpu_count = 1
        if self.remote:
            try:
                info = self.remote.get_system_info()
                cpu_count = info["cpu_count"]
            except:
                cpu_count = 1
        else:
            cpu_count = psutil.cpu_count()
            
        for i in range(cpu_count):
            core_group = QGroupBox(f"Core {i}")
            core_layout = QVBoxLayout(core_group)
            progress = QProgressBar()
            progress.setRange(0, 100)
            core_layout.addWidget(progress)
            cores_layout.addWidget(core_group)
            self.cpu_cores[i] = progress
        cpu_layout.addLayout(cores_layout)
        
        resources_layout.addWidget(cpu_group)
        
        # Memory Usage
        mem_group = QGroupBox("Memory Usage")
        mem_layout = QVBoxLayout(mem_group)
        
        self.mem_graph = pg.PlotWidget()
        self.mem_graph.setBackground('w')
        self.mem_graph.setLabel('left', 'Usage', units='%')
        self.mem_graph.setLabel('bottom', 'Time', units='s')
        self.mem_graph.showGrid(x=True, y=True)
        mem_layout.addWidget(self.mem_graph)
        
        # Memory details
        mem_details = QHBoxLayout()
        self.total_mem = QLabel()
        self.used_mem = QLabel()
        self.free_mem = QLabel()
        mem_details.addWidget(QLabel("Total:"))
        mem_details.addWidget(self.total_mem)
        mem_details.addWidget(QLabel("Used:"))
        mem_details.addWidget(self.used_mem)
        mem_details.addWidget(QLabel("Free:"))
        mem_details.addWidget(self.free_mem)
        mem_layout.addLayout(mem_details)
        
        resources_layout.addWidget(mem_group)
        
        # Disk Usage
        disk_widget = QWidget()
        disk_layout = QHBoxLayout(disk_widget)
        
        self.disk_label = QLabel("Disk Usage:")
        self.disk_bar = QProgressBar()
        self.disk_bar.setRange(0, 100)
        
        disk_layout.addWidget(self.disk_label)
        disk_layout.addWidget(self.disk_bar)
        resources_layout.addWidget(disk_widget)
        
        layout.addWidget(resources_group)
        
        # Process list
        processes_group = QGroupBox("Running Processes")
        processes_layout = QVBoxLayout(processes_group)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5 if self.advanced else 4)
        headers = ["PID", "Name", "CPU %", "Memory %"]
        if self.advanced:
            headers.append("Status")
        self.process_table.setHorizontalHeaderLabels(headers)
        self.process_table.horizontalHeader().setStretchLastSection(True)
        
        processes_layout.addWidget(self.process_table)
        layout.addWidget(processes_group)
        
        # Network Usage
        net_group = QGroupBox("Network Usage")
        net_layout = QVBoxLayout(net_group)
        
        self.net_graph = pg.PlotWidget()
        self.net_graph.setBackground('w')
        self.net_graph.setLabel('left', 'Speed', units='MB/s')
        self.net_graph.setLabel('bottom', 'Time', units='s')
        self.net_graph.showGrid(x=True, y=True)
        net_layout.addWidget(self.net_graph)
        
        # Network interface selection
        net_interface = QHBoxLayout()
        self.interface_combo = QComboBox()
        
        # Get network interfaces
        if self.remote:
            try:
                # Execute command to get network interfaces
                stdout, _ = self.remote.execute_command("ls /sys/class/net")
                interfaces = stdout.strip().split()
            except:
                interfaces = ["eth0"]  # Fallback
        else:
            interfaces = list(psutil.net_if_stats().keys())
            
        self.interface_combo.addItems(interfaces)
        net_interface.addWidget(QLabel("Interface:"))
        net_interface.addWidget(self.interface_combo)
        net_layout.addLayout(net_interface)
        
        layout.addWidget(net_group)
        
        # Apply styles
        self.apply_styles()
        
    def setup_graphs(self):
        """Set up the graph data structures"""
        # CPU data
        self.cpu_data = deque(maxlen=100)
        self.cpu_curve = self.cpu_graph.plot(pen='b')
        
        # Memory data
        self.mem_data = deque(maxlen=100)
        self.mem_curve = self.mem_graph.plot(pen='r')
        
        # Network data
        self.net_data = deque(maxlen=100)
        self.net_curve = self.net_graph.plot(pen='g')
        
        # Time data
        self.time_data = deque(maxlen=100)
        self.start_time = time.time()
        
        # Initial update
        self.update_stats()
        
    def setup_timer(self):
        """Set up the update timer"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)  # Update every second
        
    def cleanup(self):
        """Clean up resources and disconnect signals"""
        # Stop the update timer
        if hasattr(self, 'timer'):
            self.timer.stop()
            self.timer.timeout.disconnect(self.update_stats)

        # Clean up graphs
        if hasattr(self, 'cpu_graph'):
            self.cpu_graph.clear()
            self.cpu_graph.close()

        if hasattr(self, 'mem_graph'):
            self.mem_graph.clear()
            self.mem_graph.close()

        if hasattr(self, 'net_graph'):
            self.net_graph.clear()
            self.net_graph.close()

    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event)
        
    def update_stats(self):
        """Update all statistics"""
        if self.remote:
            self.update_remote_stats()
        else:
            self.update_local_stats()
            
    def update_remote_stats(self):
        """Update statistics for remote system"""
        try:
            # Get system info
            info = self.remote.get_system_info()
            
            # Update time
            current_time = time.time() - self.start_time
            self.time_data.append(current_time)
            
            # Update CPU - using more robust parsing
            stdout, _ = self.remote.execute_command("top -bn1 | grep '%Cpu'")
            cpu_line = stdout.strip().split('\n')[0]  # Get first CPU line
            # Try different formats
            try:
                # Format: "%Cpu(s):  5.9 us,  0.0 sy,  0.0 ni, 94.1 id"
                cpu_parts = cpu_line.split(':')[1].split(',')
                for part in cpu_parts:
                    if 'us' in part or 'user' in part:  # User CPU time
                        cpu_percent = float(part.strip().split()[0])
                        break
                else:
                    # If no user CPU found, try first number after Cpu(s):
                    cpu_percent = float(cpu_line.split(':')[1].strip().split()[0])
            except (IndexError, ValueError):
                # Fallback to simple number extraction
                cpu_percent = float([x for x in cpu_line.split() if x.replace('.','',1).isdigit()][0])
            
            self.cpu_data.append(cpu_percent)
            self.cpu_curve.setData(list(self.time_data), list(self.cpu_data))
            
            # Update CPU cores
            stdout, _ = self.remote.execute_command("top -bn1 -1 | grep '%Cpu'")
            core_lines = stdout.strip().split("\n")
            for i, line in enumerate(core_lines[1:]):  # Skip overall CPU line
                if i < len(self.cpu_cores):
                    try:
                        # Try the same parsing logic for each core
                        core_parts = line.split(':')[1].split(',')
                        for part in core_parts:
                            if 'us' in part or 'user' in part:
                                core_percent = float(part.strip().split()[0])
                                break
                        else:
                            core_percent = float(line.split(':')[1].strip().split()[0])
                    except (IndexError, ValueError):
                        core_percent = float([x for x in line.split() if x.replace('.','',1).isdigit()][0])
                    self.cpu_cores[i].setValue(int(core_percent))
            
            # Update Memory
            mem = info["memory"]
            mem_percent = (mem["used"] / mem["total"]) * 100
            self.mem_data.append(mem_percent)
            self.mem_curve.setData(list(self.time_data), list(self.mem_data))
            
            self.total_mem.setText(f"{mem['total'] / (1024**3):.1f} GB")
            self.used_mem.setText(f"{mem['used'] / (1024**3):.1f} GB")
            self.free_mem.setText(f"{mem['free'] / (1024**3):.1f} GB")
            
            # Update Disk
            disk = info["disk"]
            disk_percent = (disk["used"] / disk["total"]) * 100
            self.disk_bar.setValue(int(disk_percent))
            self.disk_label.setText(
                f"Disk Usage: {disk_percent:.1f}% ({self.format_bytes(disk['used'])}/{self.format_bytes(disk['total'])})"
            )
            
            # Update Process List
            stdout, _ = self.remote.execute_command("ps aux --sort=-%cpu | head -n 16")
            processes = []
            for line in stdout.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                processes.append({
                    "pid": parts[1],
                    "name": parts[10],
                    "cpu": float(parts[2]),
                    "mem": float(parts[3]),
                    "status": parts[7] if self.advanced else ""
                })
            
            self.process_table.setRowCount(len(processes))
            for i, proc in enumerate(processes):
                self.process_table.setItem(i, 0, QTableWidgetItem(proc["pid"]))
                self.process_table.setItem(i, 1, QTableWidgetItem(proc["name"]))
                self.process_table.setItem(i, 2, QTableWidgetItem(f"{proc['cpu']:.1f}%"))
                self.process_table.setItem(i, 3, QTableWidgetItem(f"{proc['mem']:.1f}%"))
                if self.advanced:
                    self.process_table.setItem(i, 4, QTableWidgetItem(proc["status"]))
            
            # Update Network
            interface = self.interface_combo.currentText()
            try:
                stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/statistics/tx_bytes")
                tx_bytes = int(stdout.strip() or "0")
                stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes")
                rx_bytes = int(stdout.strip() or "0")
                
                total_bytes = (tx_bytes + rx_bytes) / (1024**2)  # Convert to MB
                self.net_data.append(total_bytes)
                self.net_curve.setData(list(self.time_data), list(self.net_data))
            except (ValueError, OSError) as e:
                print(f"Error updating network stats: {str(e)}")
                # Use 0 as fallback value
                self.net_data.append(0)
                self.net_curve.setData(list(self.time_data), list(self.net_data))
            
        except Exception as e:
            print(f"Error updating remote stats: {str(e)}")
            
    def update_local_stats(self):
        """Update statistics for local system"""
        # Update time
        current_time = time.time() - self.start_time
        self.time_data.append(current_time)
        
        # Update CPU
        cpu_percent = psutil.cpu_percent()
        self.cpu_data.append(cpu_percent)
        self.cpu_curve.setData(list(self.time_data), list(self.cpu_data))
        
        # Update CPU cores
        for i, percent in enumerate(psutil.cpu_percent(percpu=True)):
            self.cpu_cores[i].setValue(int(percent))
        
        # Update Memory
        mem = psutil.virtual_memory()
        self.mem_data.append(mem.percent)
        self.mem_curve.setData(list(self.time_data), list(self.mem_data))
        
        self.total_mem.setText(f"{mem.total / (1024**3):.1f} GB")
        self.used_mem.setText(f"{mem.used / (1024**3):.1f} GB")
        self.free_mem.setText(f"{mem.free / (1024**3):.1f} GB")
        
        # Update Disk Usage
        disk = psutil.disk_usage('/')
        self.disk_bar.setValue(int(disk.percent))
        self.disk_label.setText(
            f"Disk Usage: {disk.percent}% ({self.format_bytes(disk.used)}/{self.format_bytes(disk.total)})"
        )
        
        # Update Process List
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                pinfo = proc.info
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        # Sort by CPU usage
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        
        # Update table
        self.process_table.setRowCount(min(len(processes), 15))  # Show top 15 processes
        
        for i, proc in enumerate(processes[:15]):
            self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(i, 2, QTableWidgetItem(f"{proc.get('cpu_percent', 0):.1f}%"))
            self.process_table.setItem(i, 3, QTableWidgetItem(f"{proc.get('memory_percent', 0):.1f}%"))
            
            if self.advanced:
                self.process_table.setItem(i, 4, QTableWidgetItem(proc.get('status', 'unknown')))
                
        # Update Network
        interface = self.interface_combo.currentText()
        net_io = psutil.net_io_counters(pernic=True)[interface]
        bytes_sent = net_io.bytes_sent / (1024**2)  # Convert to MB
        bytes_recv = net_io.bytes_recv / (1024**2)  # Convert to MB
        self.net_data.append(bytes_sent + bytes_recv)
        self.net_curve.setData(list(self.time_data), list(self.net_data))
        
    def format_bytes(self, bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.1f}{unit}"
            bytes /= 1024
        return f"{bytes:.1f}PB"
    
    def apply_styles(self):
        """Apply custom styles to the widget"""
        self.setStyleSheet("""
            QProgressBar {
                border: 2px solid #dcdde1;
                border-radius: 5px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #273c75;
                border-radius: 3px;
            }
            QLabel {
                min-width: 100px;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #dcdde1;
                border-radius: 5px;
                margin-top: 1em;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """) 