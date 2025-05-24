import contextlib
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QTableWidget, QTableWidgetItem, QGroupBox, QComboBox, QFrame, QSizePolicy, QGridLayout)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
import psutil  # Python system utilities - used for local system monitoring
import time
from datetime import datetime
import pyqtgraph as pg  # Plotting library for real-time graphs
from collections import deque  # Efficient list-like container with fast appends and pops
from src.utils.remote_connection import RemoteConnection
from src.ui.utils.theme_manager import ThemeManager
from src.ui.utils.theme_manager import ThemeManager
import logging # Add logging import

class CardWidget(QFrame):
    """A modern card-like widget with title and content for consistent UI"""
    
    def __init__(self, title, parent=None, icon=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName("card-widget")
        
        # Get theme styling from the theme manager
        theme = ThemeManager().get_theme_styles()
        
        # Create main layout
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(16, 16, 16, 16)
        self.layout.setSpacing(12)
        
        # Create card header with title and optional icon
        header = QWidget()
        header.setObjectName("card-header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 12)
        header_layout.setSpacing(10)
        
        # Add icon if provided
        if icon:
            icon_label = QLabel()
            icon_label.setObjectName("card-icon")
            icon_label.setFixedSize(24, 24)
            icon_label.setText(icon)  # Can be emoji or other text
            icon_label.setStyleSheet(f"""
                QLabel#card-icon {{
                    color: {theme['accent_primary']};
                    font-size: 16px;
                    background-color: {theme['accent_primary'] + '15'};  /* 15% opacity background */
                    border-radius: 12px;
                    qproperty-alignment: AlignCenter;
                }}
            """)
            header_layout.addWidget(icon_label)
        
        # Add title label
        self.title_label = QLabel(title)
        self.title_label.setObjectName("card-title")
        self.title_label.setStyleSheet(f"""
            QLabel#card-title {{
                color: {theme['text_primary']};
                font-weight: 600;
                font-size: 15px;
            }}
        """)
        header_layout.addWidget(self.title_label)
        
        header_layout.addStretch()
        
        self.layout.addWidget(header)
        
        # Add a separator line below the header
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet(f"""
            background-color: {theme['border_color']};
            border: none;
            max-height: 1px;
        """)
        self.layout.addWidget(separator)
        
        # Create content area for the card
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(0, 8, 0, 0)
        self.content_layout.setSpacing(12)
        
        self.layout.addWidget(self.content)
        
        # Apply card styling
        self.setStyleSheet(f"""
            QFrame#card-widget {{
                background-color: {theme['bg_tertiary']};
                border-radius: {theme['radius_md']};
                border: 1px solid {theme['border_color']};
            }}
        """)
        
    def add_widget(self, widget):
        """Add a widget to the card content"""
        self.content_layout.addWidget(widget)
        
    def add_layout(self, layout):
        """Add a layout to the card content"""
        self.content_layout.addLayout(layout)

class SystemMonitorWidget(QWidget):
    """Widget for monitoring system resources and processes in real-time
    
    This widget displays CPU, memory, disk, and network usage with graphs and metrics.
    It has two modes:
    - Basic (for junior admins): Shows essential system information
    - Advanced (for senior admins): Shows detailed metrics and more controls
    
    The widget can monitor either the local system or a remote system via SSH.
    """
    
    def __init__(self, parent=None, advanced=False, remote: RemoteConnection = None):
        super().__init__(parent)
        # Store whether this is advanced mode (for senior admins)
        self.advanced = advanced
        # Store the remote connection (if monitoring a remote system)
        self.remote = remote
        # Initialize logger for this widget
        self.logger = logging.getLogger(__name__)
        # Get theme manager for consistent styling
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.update_theme)
        
        # Create the UI components
        self.setup_ui()
        # Set up the real-time graphs
        self.setup_graphs()
        # Set up timers for periodic updates
        self.setup_timer()
        
    def update_static_system_info(self, hostname: str, os_info: str, kernel_info: str, uptime_info: str):
        """Updates the static system information labels within the card.
        
        This is called with data retrieved from the remote system.
        
        Args:
            hostname: The system hostname
            os_info: Operating system name and version
            kernel_info: Kernel version
            uptime_info: System uptime information
        """
        self.hostname_label.setText(f"Hostname: {hostname}")
        self.os_label.setText(f"Operating System: {os_info}")
        self.kernel_label.setText(f"Kernel Version: {kernel_info}")
        self.uptime_label.setText(f"Uptime: {uptime_info}")

    def setup_ui(self):
        """Set up the UI components for system monitoring
        
        Creates cards for:
        1. System information (hostname, OS, kernel, uptime)
        2. CPU usage (graph and per-core metrics)
        3. Memory usage (graph and details)
        4. Disk usage (graph and details)
        5. Network usage (graph and interface details)
        
        Advanced mode shows more detailed information.
        """
        theme = self.theme_manager.get_theme_styles()
        
        # Main layout contains all monitoring cards
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(20)
        
        # Top row layout - contains system info and CPU usage
        top_row = QHBoxLayout()
        top_row.setSpacing(20)
        
        # System information card - static system details
        system_info_card = CardWidget("System Information", icon="🖥️")
        system_info_layout = QVBoxLayout()
        system_info_layout.setSpacing(8)
        
        # Create labels for system information
        self.hostname_label = QLabel()
        self.hostname_label.setObjectName("info-label")
        self.os_label = QLabel()
        self.os_label.setObjectName("info-label")
        self.kernel_label = QLabel()
        self.kernel_label.setObjectName("info-label")
        self.uptime_label = QLabel()
        self.uptime_label.setObjectName("info-label")
        
        # Style the info labels with a subtle background
        info_label_style = f"""
            QLabel#info-label {{
                padding: 6px 10px;
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_sm']};
                border: 1px solid {theme['border_color']};
            }}
        """
        self.hostname_label.setStyleSheet(info_label_style)
        self.os_label.setStyleSheet(info_label_style)
        self.kernel_label.setStyleSheet(info_label_style)
        self.uptime_label.setStyleSheet(info_label_style)
        
        # Add labels to the system info layout
        system_info_layout.addWidget(self.hostname_label)
        system_info_layout.addWidget(self.os_label)
        system_info_layout.addWidget(self.kernel_label)
        system_info_layout.addWidget(self.uptime_label)
        system_info_layout.addStretch()
        
        # Add layout to the card
        system_info_card.add_layout(system_info_layout)
        # Add card to top row, with weight of 2
        top_row.addWidget(system_info_card, 2)
        
        # CPU usage card - shows real-time CPU usage graph
        cpu_card = CardWidget("CPU Usage", icon="⚡")
        cpu_layout = QVBoxLayout()
        cpu_layout.setSpacing(10)
        
        # Set graph colors from theme
        graph_bg_color = theme['chart_bg']
        grid_color = theme['chart_grid']
        
        # Create CPU usage graph using PyQtGraph
        self.cpu_graph = pg.PlotWidget()
        self.cpu_graph.setBackground(graph_bg_color)
        self.cpu_graph.setLabel('left', 'Usage', units='%')
        self.cpu_graph.setLabel('bottom', 'Time', units='s')
        self.cpu_graph.showGrid(x=True, y=True, alpha=0.3)
        self.cpu_graph.getAxis('left').setPen(theme['text_primary'])
        self.cpu_graph.getAxis('bottom').setPen(theme['text_primary'])
        self.cpu_graph.getAxis('left').setTextPen(theme['text_primary'])
        self.cpu_graph.getAxis('bottom').setTextPen(theme['text_primary'])
        self.cpu_graph.setMinimumHeight(180)
        
        # Add graph to CPU layout
        cpu_layout.addWidget(self.cpu_graph)
        
        # Create widget to show per-core CPU usage
        cores_widget = QWidget()
        cores_widget.setObjectName("cores-widget")
        cores_widget.setStyleSheet(f"""
            QWidget#cores-widget {{
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_sm']};
                padding: 8px;
            }}
        """)
        cores_grid = QGridLayout(cores_widget)
        cores_grid.setSpacing(10)
        cores_grid.setContentsMargins(8, 8, 8, 8)
        
        # Get CPU count - for remote system, this will be updated later
        cpu_count = 1
        if self.remote:
            try:
                info = self.remote.get_system_info()
                cpu_count = info["cpu_count"]
            except:
                cpu_count = 1
        else:
            cpu_count = psutil.cpu_count()
        
        self.cpu_cores = {}
        columns = 4
        for i in range(cpu_count):
            row = i // columns
            col = i % columns
            
            core_widget = QWidget()
            core_layout = QVBoxLayout(core_widget)
            core_layout.setContentsMargins(0, 0, 0, 0)
            core_layout.setSpacing(4)
            
            core_label = QLabel(f"Core {i}")
            core_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            core_label.setObjectName("core-label")
            
            progress = QProgressBar()
            progress.setRange(0, 100)
            progress.setTextVisible(True)
            progress.setObjectName("core-progress")
            progress.setMinimumWidth(60)
            progress.setFixedHeight(10)  # Slimmer more modern progress bar
            progress.setStyleSheet(f"""
                QProgressBar {{
                    border: none;
                    border-radius: 5px;
                    background-color: {theme['bg_primary']};
                    text-align: center;
                }}
                QProgressBar::chunk {{
                    background-color: {theme['accent_primary']};
                    border-radius: 5px;
                }}
            """)
            
            # Add percentage label underneath progress bar
            percentage = QLabel("0%")
            percentage.setAlignment(Qt.AlignmentFlag.AlignCenter)
            percentage.setObjectName("core-percentage")
            
            core_layout.addWidget(core_label)
            core_layout.addWidget(progress)
            core_layout.addWidget(percentage)
            
            cores_grid.addWidget(core_widget, row, col)
            self.cpu_cores[i] = (progress, percentage)  # Store both progress bar and label
        
        cpu_layout.addWidget(cores_widget)
        cpu_card.add_layout(cpu_layout)
        top_row.addWidget(cpu_card, 3)
        
        main_layout.addLayout(top_row)
        
        # Middle row with memory and disk
        middle_row = QHBoxLayout()
        middle_row.setSpacing(20)
        
        # Memory Card with RAM icon
        memory_card = CardWidget("Memory Usage", icon="🧠")
        memory_layout = QVBoxLayout()
        memory_layout.setSpacing(10)
        
        # Memory graph
        self.mem_graph = pg.PlotWidget()
        self.mem_graph.setBackground(graph_bg_color)
        self.mem_graph.setLabel('left', 'Usage', units='%')
        self.mem_graph.setLabel('bottom', 'Time', units='s')
        self.mem_graph.showGrid(x=True, y=True, alpha=0.3)
        self.mem_graph.getAxis('left').setPen(theme['text_primary'])
        self.mem_graph.getAxis('bottom').setPen(theme['text_primary'])
        self.mem_graph.getAxis('left').setTextPen(theme['text_primary'])
        self.mem_graph.getAxis('bottom').setTextPen(theme['text_primary'])
        self.mem_graph.setMinimumHeight(180)
        
        memory_layout.addWidget(self.mem_graph)
        
        # Memory details in a modern card layout
        mem_stats_container = QWidget()
        mem_stats_container.setObjectName("memory-stats-container")
        mem_stats_container.setStyleSheet(f"""
            QWidget#memory-stats-container {{
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_sm']};
                padding: 8px;
            }}
        """)
        mem_details = QHBoxLayout(mem_stats_container)
        mem_details.setSpacing(20)
        
        # Memory info with consistent styling
        self.total_mem = QLabel()
        self.total_mem.setObjectName("memory-label")
        self.used_mem = QLabel()
        self.used_mem.setObjectName("memory-label")
        self.free_mem = QLabel()
        self.free_mem.setObjectName("memory-label")
        
        total_container = QWidget()
        total_layout = QVBoxLayout(total_container)
        total_layout.setContentsMargins(0, 0, 0, 0)
        total_layout.setSpacing(2)
        total_title = QLabel("Total")
        total_title.setObjectName("memory-title")
        total_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        total_layout.addWidget(total_title)
        total_layout.addWidget(self.total_mem)
        
        used_container = QWidget()
        used_layout = QVBoxLayout(used_container)
        used_layout.setContentsMargins(0, 0, 0, 0)
        used_layout.setSpacing(2)
        used_title = QLabel("Used")
        used_title.setObjectName("memory-title")
        used_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        used_layout.addWidget(used_title)
        used_layout.addWidget(self.used_mem)
        
        free_container = QWidget()
        free_layout = QVBoxLayout(free_container)
        free_layout.setContentsMargins(0, 0, 0, 0)
        free_layout.setSpacing(2)
        free_title = QLabel("Free")
        free_title.setObjectName("memory-title")
        free_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        free_layout.addWidget(free_title)
        free_layout.addWidget(self.free_mem)
        
        mem_details.addWidget(total_container)
        mem_details.addWidget(used_container)
        mem_details.addWidget(free_container)
        mem_details.addStretch()
        
        memory_layout.addWidget(mem_stats_container)
        memory_card.add_layout(memory_layout)
        middle_row.addWidget(memory_card)
        
        # Disk Usage Card with disk icon
        disk_card = CardWidget("Disk Usage", icon="💾")
        disk_layout = QVBoxLayout()
        disk_layout.setSpacing(10)
        
        # Disk usage bar with percentage in a card-like container
        disk_progress_container = QWidget()
        disk_progress_container.setObjectName("disk-progress-container")
        disk_progress_container.setStyleSheet(f"""
            QWidget#disk-progress-container {{
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_sm']};
                padding: 12px;
            }}
        """)
        disk_progress_layout = QVBoxLayout(disk_progress_container)
        disk_progress_layout.setContentsMargins(8, 8, 8, 8)
        disk_progress_layout.setSpacing(8)
        
        # Disk usage bar heading with percentage
        disk_info = QHBoxLayout()
        self.disk_label = QLabel("Disk Usage")
        self.disk_label.setObjectName("disk-label")
        self.disk_label.setStyleSheet("font-weight: 500;")
        disk_info.addWidget(self.disk_label)
        disk_info.addStretch()
        
        self.disk_percentage = QLabel("0%")
        self.disk_percentage.setObjectName("disk-percentage")
        self.disk_percentage.setStyleSheet(f"color: {theme['accent_primary']}; font-weight: bold;")
        disk_info.addWidget(self.disk_percentage)
        
        disk_progress_layout.addLayout(disk_info)
        
        # Modern slim progress bar
        self.disk_bar = QProgressBar()
        self.disk_bar.setRange(0, 100)
        self.disk_bar.setTextVisible(False)
        self.disk_bar.setObjectName("disk-progress")
        self.disk_bar.setFixedHeight(12)
        self.disk_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 6px;
                background-color: {theme['bg_primary']};
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {theme['accent_primary']};
                border-radius: 6px;
            }}
        """)
        
        disk_progress_layout.addWidget(self.disk_bar)
        
        disk_layout.addWidget(disk_progress_container)
        
        # Disk details in a card-like container
        disk_details_container = QWidget()
        disk_details_container.setObjectName("disk-details-container")
        disk_details_container.setStyleSheet(f"""
            QWidget#disk-details-container {{
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_sm']};
                padding: 8px;
            }}
        """)
        disk_details = QHBoxLayout(disk_details_container)
        disk_details.setSpacing(20)
        
        # Disk space info with consistent styling
        self.total_disk = QLabel()
        self.total_disk.setObjectName("disk-detail-label")
        self.used_disk = QLabel()
        self.used_disk.setObjectName("disk-detail-label")
        self.free_disk = QLabel()
        self.free_disk.setObjectName("disk-detail-label")
        
        total_disk_container = QWidget()
        total_disk_layout = QVBoxLayout(total_disk_container)
        total_disk_layout.setContentsMargins(0, 0, 0, 0)
        total_disk_layout.setSpacing(2)
        total_disk_title = QLabel("Total")
        total_disk_title.setObjectName("disk-detail-title")
        total_disk_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        total_disk_layout.addWidget(total_disk_title)
        total_disk_layout.addWidget(self.total_disk)
        
        used_disk_container = QWidget()
        used_disk_layout = QVBoxLayout(used_disk_container)
        used_disk_layout.setContentsMargins(0, 0, 0, 0)
        used_disk_layout.setSpacing(2)
        used_disk_title = QLabel("Used")
        used_disk_title.setObjectName("disk-detail-title")
        used_disk_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        used_disk_layout.addWidget(used_disk_title)
        used_disk_layout.addWidget(self.used_disk)
        
        free_disk_container = QWidget()
        free_disk_layout = QVBoxLayout(free_disk_container)
        free_disk_layout.setContentsMargins(0, 0, 0, 0)
        free_disk_layout.setSpacing(2)
        free_disk_title = QLabel("Free")
        free_disk_title.setObjectName("disk-detail-title")
        free_disk_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        free_disk_layout.addWidget(free_disk_title)
        free_disk_layout.addWidget(self.free_disk)
        
        disk_details.addWidget(total_disk_container)
        disk_details.addWidget(used_disk_container)
        disk_details.addWidget(free_disk_container)
        disk_details.addStretch()
        
        disk_layout.addWidget(disk_details_container)
        disk_layout.addStretch()
        
        disk_card.add_layout(disk_layout)
        middle_row.addWidget(disk_card)
        
        main_layout.addLayout(middle_row)
        
        # Bottom row with processes and network
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(20)
        
        # Process List Card with process icon
        process_card = CardWidget("Running Processes", icon="🔄")
        process_layout = QVBoxLayout()
        process_layout.setSpacing(10)
        
        # Process table with modern styling
        self.process_table = QTableWidget()
        self.process_table.setObjectName("process-table")
        self.process_table.setColumnCount(5 if self.advanced else 4)
        headers = ["PID", "Name", "CPU %", "Memory %"]
        if self.advanced:
            headers.append("Status")
        self.process_table.setHorizontalHeaderLabels(headers)
        self.process_table.horizontalHeader().setStretchLastSection(True)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.setMinimumHeight(200)
        self.process_table.setShowGrid(False)
        self.process_table.setStyleSheet(f"""
            QTableWidget#process-table {{
                background-color: {theme['bg_secondary']}; 
                alternate-background-color: {theme['table_row_alt']}; 
                color: {theme['text_primary']};
                border: none; 
                gridline-color: {theme['border_color']}; 
                outline: 0;
            }}
            QTableWidget#process-table::item {{
                border-bottom: 1px solid {theme['border_color']};
                padding: 5px 8px;
                color: {theme['text_primary']};
            }}
            QTableWidget#process-table::item:selected {{
                background-color: {theme['table_selected']};
                color: {theme['text_primary']}; 
            }}
            QHeaderView::section {{
                background-color: {theme['table_header_bg']};
                color: {theme['text_primary']};
                padding: 8px 6px;
                border: none;
                border-bottom: 1px solid {theme['border_color']};
                font-weight: bold;
            }}
        """)
        
        process_layout.addWidget(self.process_table)
        process_card.add_layout(process_layout)
        bottom_row.addWidget(process_card)
        
        # Network Card with network icon
        network_card = CardWidget("Network Usage", icon="🌐")
        network_layout = QVBoxLayout()
        network_layout.setSpacing(10)
        
        # Network graph
        self.net_graph = pg.PlotWidget()
        self.net_graph.setBackground(graph_bg_color)
        self.net_graph.setLabel('left', 'Speed', units='MB/s')
        self.net_graph.setLabel('bottom', 'Time', units='s')
        self.net_graph.showGrid(x=True, y=True, alpha=0.3)
        self.net_graph.getAxis('left').setPen(theme['text_primary'])
        self.net_graph.getAxis('bottom').setPen(theme['text_primary'])
        self.net_graph.getAxis('left').setTextPen(theme['text_primary'])
        self.net_graph.getAxis('bottom').setTextPen(theme['text_primary'])
        self.net_graph.setMinimumHeight(180)
        
        network_layout.addWidget(self.net_graph)
        
        # Network interface selector in container
        net_controls_container = QWidget()
        net_controls_container.setObjectName("network-controls")
        net_controls_container.setStyleSheet(f"""
            QWidget#network-controls {{
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_sm']};
                padding: 8px;
            }}
        """)
        net_controls_layout = QVBoxLayout(net_controls_container)
        net_controls_layout.setContentsMargins(10, 10, 10, 10)
        net_controls_layout.setSpacing(10)
        
        net_interface_layout = QHBoxLayout()
        net_interface_layout.setSpacing(10)
        
        interface_label = QLabel("Interface:")
        interface_label.setObjectName("interface-label")
        interface_label.setStyleSheet("color: " + theme['text_secondary'] + ";")
        
        self.interface_combo = QComboBox()
        self.interface_combo.setObjectName("interface-combo")
        self.interface_combo.setMinimumHeight(30)
        self.interface_combo.setStyleSheet(f"""
            QComboBox {{
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                padding: 4px 8px;
                background-color: {theme['bg_tertiary']};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
        """)
        
        # Get network interfaces
        if self.remote:
            try:
                stdout, _ = self.remote.execute_command("ls /sys/class/net")
                interfaces = stdout.strip().split()
            except:
                interfaces = ["eth0"]  # Fallback
        else:
            interfaces = list(psutil.net_if_stats().keys())
            
        self.interface_combo.addItems(interfaces)
        self.interface_combo.currentIndexChanged.connect(self.update_stats)
        
        net_interface_layout.addWidget(interface_label)
        net_interface_layout.addWidget(self.interface_combo)
        net_interface_layout.addStretch()
        
        # Network stats display with improved styling
        self.net_stats_layout = QHBoxLayout()
        self.net_stats_layout.setSpacing(20)
        
        # Network stats with consistent styling
        self.sent_label = QLabel()
        self.sent_label.setObjectName("network-label")
        self.recv_label = QLabel()
        self.recv_label.setObjectName("network-label")
        
        sent_container = QWidget()
        sent_layout = QVBoxLayout(sent_container)
        sent_layout.setContentsMargins(0, 0, 0, 0)
        sent_layout.setSpacing(2)
        sent_title = QLabel("Sent")
        sent_title.setObjectName("network-title")
        sent_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        sent_layout.addWidget(sent_title)
        sent_layout.addWidget(self.sent_label)
        
        recv_container = QWidget()
        recv_layout = QVBoxLayout(recv_container)
        recv_layout.setContentsMargins(0, 0, 0, 0)
        recv_layout.setSpacing(2)
        recv_title = QLabel("Received")
        recv_title.setObjectName("network-title")
        recv_title.setStyleSheet("color: " + theme['text_secondary'] + "; font-size: 12px;")
        recv_layout.addWidget(recv_title)
        recv_layout.addWidget(self.recv_label)
        
        self.net_stats_layout.addWidget(sent_container)
        self.net_stats_layout.addWidget(recv_container)
        self.net_stats_layout.addStretch()
        
        net_controls_layout.addLayout(net_interface_layout)
        net_controls_layout.addLayout(self.net_stats_layout)
        
        network_layout.addWidget(net_controls_container)
        
        network_card.add_layout(network_layout)
        bottom_row.addWidget(network_card)
        
        main_layout.addLayout(bottom_row)
        
        # Apply styles
        self.apply_styles()
        
    def setup_graphs(self):
        """Set up the graph data structures"""
        theme = self.theme_manager.get_theme_styles()
        
        # Define pen colors based on theme
        cpu_pen = pg.mkPen(color=theme['chart_line1'], width=2)
        mem_pen = pg.mkPen(color=theme['chart_line2'], width=2)
        net_recv_pen = pg.mkPen(color=theme['chart_line3'], width=2)
        net_sent_pen = pg.mkPen(color=theme['chart_line4'], width=2)
        
        # CPU data
        self.cpu_data = deque(maxlen=100)
        self.cpu_curve = self.cpu_graph.plot(pen=cpu_pen)
        
        # Memory data
        self.mem_data = deque(maxlen=100)
        self.mem_curve = self.mem_graph.plot(pen=mem_pen)
        
        # Network data - separate lines for sent and received
        self.net_recv_data = deque(maxlen=100)
        self.net_sent_data = deque(maxlen=100)
        self.net_recv_curve = self.net_graph.plot(pen=net_recv_pen, name="Received")
        self.net_sent_curve = self.net_graph.plot(pen=net_sent_pen, name="Sent")
        
        # Add legend to network graph
        self.net_graph.addLegend()
        
        # Time data
        self.time_data = deque(maxlen=100)
        self.start_time = time.time()
        
        # Network counters for calculation
        self.last_net_io = None
        self.last_net_time = time.time()
        
        # Initial update
        self.update_stats()
        
    def setup_timer(self):
        """Set up timer for periodic updates"""
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_stats)
        # Update every 1 second (1000 ms) - DO NOT START IT HERE
        # self.timer.start(1000) 

    def start_monitoring(self):
        """Start the periodic updates if a remote connection exists."""
        if self.remote: # Only start if there's a remote target
            self.update_stats() # Perform an initial update immediately
            self.timer.start(1000)
            self.logger.info("SystemMonitorWidget: Monitoring started.")
        else:
            self.logger.warning("SystemMonitorWidget: Monitoring not started, no remote connection provided.")

    def stop_monitoring(self):
        """Stop the periodic updates."""
        self.timer.stop()
        self.logger.info("SystemMonitorWidget: Monitoring stopped.")

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
        if not self.remote or not self.remote.is_really_connected():
            # Only print the message if the timer is currently active (to avoid spam on initial setup)
            if self.timer.isActive():
                self.logger.warning("SystemMonitorWidget: Remote not connected. Stopping updates.")
            self.stop_monitoring() # Stop the timer
            # Optionally, update UI elements to show a disconnected state
            # For example, clear graphs or set labels to 'N/A' or 'Disconnected'
            if hasattr(self, 'hostname_label'): self.hostname_label.setText("Hostname: Disconnected")
            if hasattr(self, 'os_label'): self.os_label.setText("Operating System: N/A")
            if hasattr(self, 'kernel_label'): self.kernel_label.setText("Kernel Version: N/A")
            if hasattr(self, 'uptime_label'): self.uptime_label.setText("Uptime: N/A")
            
            # Clear graph data
            if hasattr(self, 'cpu_data'): self.cpu_data.clear(); self.cpu_curve.clear()
            if hasattr(self, 'mem_data'): self.mem_data.clear(); self.mem_curve.clear()
            if hasattr(self, 'net_recv_data'): self.net_recv_data.clear(); self.net_recv_curve.clear()
            if hasattr(self, 'net_sent_data'): self.net_sent_data.clear(); self.net_sent_curve.clear()
            # Set progress bars and labels to default/error state
            if hasattr(self, 'cpu_cores'):
                for core_pb, core_label in self.cpu_cores.values(): # Assuming cpu_cores is a dict
                    core_pb.setValue(0); core_label.setText("N/A")
            if hasattr(self, 'disk_bar'): self.disk_bar.setValue(0)
            if hasattr(self, 'disk_percentage'): self.disk_percentage.setText("N/A")
            if hasattr(self, 'process_table'): self.process_table.setRowCount(0) 
            return

        try:
            # Get system info
            # Check connection again before this specific call, as it might have dropped
            if not self.remote.is_really_connected():
                print("SystemMonitorWidget: Lost connection before fetching system info.")
                # Handle as above, or simply return to let the next timer tick catch it
                return

            system_info_dict = self.remote.get_system_info() # This is from RemoteConnection, not SeniorDashboardBackend
            if not system_info_dict or isinstance(system_info_dict.get("memory"), str): # crude check for error from get_system_info
                print(f"SystemMonitorWidget: Failed to get valid system info from remote: {system_info_dict.get('error', 'Unknown error')}")
                # Potentially set UI to error state here too
                return

            # Update time
            current_time = time.time() - self.start_time
            self.time_data.append(current_time)

            # Update CPU - using more robust parsing
            cpu_percent = 0.0  # Default to 0.0
            try:
                stdout, stderr = self.remote.execute_command("top -bn1 | grep '%Cpu'")

                if stdout.strip():
                    cpu_line = stdout.strip().split('\n')[0]  # Get first CPU line
                    # Try different formats
                    try:
                        # Format: "%Cpu(s):  5.9 us,  0.0 sy,  0.0 ni, 94.1 id"
                        cpu_parts = cpu_line.split(':')[1].split(',')
                        found_us = False
                        for part in cpu_parts:
                            if 'us' in part or 'user' in part:  # User CPU time
                                cpu_percent = float(part.strip().split()[0])
                                found_us = True
                                break
                        if not found_us:
                            # If no user CPU found, try first number after Cpu(s):
                            cpu_percent = float(cpu_line.split(':')[1].strip().split()[0])
                    except (IndexError, ValueError) as e_parse:
                        # Fallback to simple number extraction
                        numbers_in_line = [x for x in cpu_line.split() if x.replace('.', '', 1).isdigit()]
                        if numbers_in_line:
                            cpu_percent = float(numbers_in_line[0])
                        else:
                            cpu_percent = 0.0 # Explicitly set to 0 if no numbers found
                else:
                    cpu_percent = 0.0 # Set to 0 if stdout is empty

            except Exception as e_cmd:
                cpu_percent = 0.0 # Default to 0 on any other error

            self.cpu_data.append(cpu_percent)
            self.cpu_curve.setData(list(self.time_data), list(self.cpu_data))

            # Update CPU cores
            try:
                stdout_core, stderr_core = self.remote.execute_command("top -bn1 -1 | grep '%Cpu'")

                if stdout_core.strip():
                    core_lines = stdout_core.strip().split("\n")

                    for i, line in enumerate(core_lines):  # Skip overall CPU line if present
                        if i < len(self.cpu_cores):
                            core_percent = 0.0 # Default for the core
                            try:
                                # Try the same parsing logic for each core
                                core_parts = line.split(':')[1].split(',')
                                found_us_core = False
                                for part in core_parts:
                                    if 'us' in part or 'user' in part:
                                        core_percent = float(part.strip().split()[0])
                                        found_us_core = True
                                        break
                                if not found_us_core:
                                    core_percent = float(line.split(':')[1].strip().split()[0])
                            except (IndexError, ValueError) as e_parse_core:
                                numbers_in_core_line = [x for x in line.split() if x.replace('.', '', 1).isdigit()]
                                if numbers_in_core_line:
                                    core_percent = float(numbers_in_core_line[0])
                                else:
                                    core_percent = 0.0
                            except Exception as e_core_inner:
                                core_percent = 0.0

                            progress_bar, percentage_label = self.cpu_cores[i]
                            progress_bar.setValue(int(core_percent))
                            percentage_label.setText(f"{core_percent:.1f}%")
                        else:
                            # Set all core displays to 0 if no data
                            for i in range(len(self.cpu_cores)):
                                progress_bar, percentage_label = self.cpu_cores[i]
                                progress_bar.setValue(0)
                                percentage_label.setText("0.0%")

            except Exception as e_cmd_core:
                # Set all core displays to 0 on error
                for i in range(len(self.cpu_cores)):
                    progress_bar, percentage_label = self.cpu_cores[i]
                    progress_bar.setValue(0)
                    percentage_label.setText("0.0%")

            # Update Memory
            mem = system_info_dict["memory"]
            mem_percent = (mem["used"] / mem["total"]) * 100
            self.mem_data.append(mem_percent)
            self.mem_curve.setData(list(self.time_data), list(self.mem_data))

            self.total_mem.setText(f"{mem['total'] / (1024**3):.1f} GB")
            self.used_mem.setText(f"{mem['used'] / (1024**3):.1f} GB")
            self.free_mem.setText(f"{mem['free'] / (1024**3):.1f} GB")

            # Update Disk
            disk = system_info_dict["disk"]
            disk_percent = (disk["used"] / disk["total"]) * 100
            self.disk_bar.setValue(int(disk_percent))
            self.disk_percentage.setText(f"{disk_percent:.1f}%")
            self.disk_label.setText("Disk Usage")

            # Update disk details
            self.total_disk.setText(self.format_bytes(disk['total']))
            self.used_disk.setText(self.format_bytes(disk['used']))
            self.free_disk.setText(self.format_bytes(disk['free']))

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
                self._extracted_from_update_remote_stats_100(interface)
            except (ValueError, OSError) as e:
                print(f"Error updating network stats: {str(e)}")
                self._extracted_from_update_remote_stats_106(0)
        except Exception as e:
            self.logger.error(f"Error updating remote system stats: {e}", exc_info=True)
            # Optionally, disable timer or show an error message on the UI

    def _extracted_from_update_remote_stats_100(self, interface):
        # Get RX and TX bytes for this interface
        stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/statistics/tx_bytes")
        tx_bytes = int(stdout.strip() or "0")
        stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes")
        rx_bytes = int(stdout.strip() or "0")

        total_bytes = (tx_bytes + rx_bytes) / (1024**2)  # Convert to MB
        self._extracted_from_update_remote_stats_106(total_bytes)

    def _extracted_from_update_remote_stats_106(self, arg0):
        # Process List (Simplified: top 5 CPU consuming processes)
        self.net_recv_data.append(arg0)
        self.net_sent_data.append(0)  # Sent data is not provided in the command output
        self.net_recv_curve.setData(list(self.time_data), list(self.net_recv_data))
        self.net_sent_curve.setData(list(self.time_data), list(self.net_sent_data))
            
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
            if i in self.cpu_cores:
                progress_bar, percentage_label = self.cpu_cores[i]
                progress_bar.setValue(int(percent))
                percentage_label.setText(f"{percent:.1f}%")

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
        self.disk_percentage.setText(f"{disk.percent}%")
        self.disk_label.setText("Disk Usage")

        # Update disk details
        self.total_disk.setText(f"{self.format_bytes(disk.total)}")
        self.used_disk.setText(f"{self.format_bytes(disk.used)}")
        self.free_disk.setText(f"{self.format_bytes(disk.free)}")

        # Update Process List
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pinfo = proc.info
                processes.append(pinfo)
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
        self.net_recv_data.append(bytes_recv)
        self.net_sent_data.append(bytes_sent)
        self.net_recv_curve.setData(list(self.time_data), list(self.net_recv_data))
        self.net_sent_curve.setData(list(self.time_data), list(self.net_sent_data))
        
    def format_bytes(self, bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.1f}{unit}"
            bytes /= 1024
        return f"{bytes:.1f}PB"
    
    def apply_styles(self):
        """Apply custom styles to the widget"""
        theme = self.theme_manager.get_theme_styles()
        
        self.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {theme['border_color']};
                border-radius: 3px;
                text-align: center;
                height: 15px;
                font-size: 10px;
                background-color: {theme['bg_tertiary']};
                color: {theme['text_primary']};
            }}
            QProgressBar::chunk {{
                background-color: {theme['accent_primary']};
                border-radius: 2px;
            }}
            QLabel {{
                min-width: 60px;
                font-size: 11px;
                color: {theme['text_primary']};
            }}
            QGroupBox {{
                font-weight: bold;
                border: 1px solid {theme['border_color']};
                border-radius: 4px;
                margin-top: 0.8em;
                padding-top: 8px;
                font-size: 12px;
                color: {theme['text_primary']};
                background-color: {theme['bg_secondary']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 3px;
                color: {theme['text_primary']};
                background-color: {theme['bg_secondary']};
            }}
            QTableWidget {{
                font-size: 11px;
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                gridline-color: {theme['border_color']};
            }}
            QTableWidget::item {{
                padding: 2px;
            }}
            QHeaderView::section {{
                padding: 3px;
                font-size: 11px;
                background-color: {theme['table_header_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
            }}
            QComboBox {{
                height: 20px;
                font-size: 11px;
                padding: 1px 5px;
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
            }}
            QWidget {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
            }}
        """)

    def update_theme(self):
        """Update the widget's theme"""
        # Update graph backgrounds and colors
        theme = self.theme_manager.get_theme_styles()
        graph_bg_color = 'w' if self.theme_manager.current_theme == 'light' else '#1e1e1e'

        # Update graph backgrounds and axis colors
        if hasattr(self, 'cpu_graph'):
            self.cpu_graph.setBackground(graph_bg_color)
            with contextlib.suppress(AttributeError):
                self.cpu_graph.getAxis('left').setPen(theme['text_primary'])
                self.cpu_graph.getAxis('bottom').setPen(theme['text_primary'])
                self.cpu_graph.getAxis('left').setTextPen(theme['text_primary'])
                self.cpu_graph.getAxis('bottom').setTextPen(theme['text_primary'])
                # Update grid colors
                self.cpu_graph.showGrid(x=True, y=True, alpha=0.3)
        if hasattr(self, 'mem_graph'):
            self.mem_graph.setBackground(graph_bg_color)
            with contextlib.suppress(AttributeError):
                self.mem_graph.getAxis('left').setPen(theme['text_primary'])
                self.mem_graph.getAxis('bottom').setPen(theme['text_primary'])
                self.mem_graph.getAxis('left').setTextPen(theme['text_primary'])
                self.mem_graph.getAxis('bottom').setTextPen(theme['text_primary'])
                # Update grid colors
                self.mem_graph.showGrid(x=True, y=True, alpha=0.3)
        if hasattr(self, 'net_graph'):
            self.net_graph.setBackground(graph_bg_color)
            with contextlib.suppress(AttributeError):
                self.net_graph.getAxis('left').setPen(theme['text_primary'])
                self.net_graph.getAxis('bottom').setPen(theme['text_primary'])
                self.net_graph.getAxis('left').setTextPen(theme['text_primary'])
                self.net_graph.getAxis('bottom').setTextPen(theme['text_primary'])
                # Update grid colors
                self.net_graph.showGrid(x=True, y=True, alpha=0.3)
        # Update plot pens
        if hasattr(self, 'cpu_curve'):
            self.cpu_curve.setPen(pg.mkPen(color=theme['chart_line1'], width=2))
        if hasattr(self, 'mem_curve'):
            self.mem_curve.setPen(pg.mkPen(color=theme['chart_line2'], width=2))
        if hasattr(self, 'net_recv_curve'):
            self.net_recv_curve.setPen(pg.mkPen(color=theme['chart_line3'], width=2))
        if hasattr(self, 'net_sent_curve'):
            self.net_sent_curve.setPen(pg.mkPen(color=theme['chart_line4'], width=2))

        # Apply style updates
        self.apply_styles() 