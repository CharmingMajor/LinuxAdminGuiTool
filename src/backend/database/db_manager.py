import sqlite3
import os
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import logging

class DatabaseManager:
    """SQLite database manager for the Linux Admin GUI Tool"""

    def __init__(self, db_path: str = "config/app_data.db"):
        """Initialize the database manager
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_db()
    
    def _get_connection(self):
        """Get a database connection
        
        Returns:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        return conn
    
    def _init_db(self):
        """Initialize database tables if they don't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create reports table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                report_type TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
            ''')
            
            # Create system_logs table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT
            )
            ''')
            
            # Create user_settings table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                username TEXT PRIMARY KEY,
                settings TEXT NOT NULL
            )
            ''')
            
            # Create tasks table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                type TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'completed'
            )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {str(e)}")
            raise
    
    def add_report(self, from_user: str, to_user: str, report_type: str, description: str) -> bool:
        """Add a new report
        
        Args:
            from_user: Username of the reporter
            to_user: Username of the recipient
            report_type: Type of report
            description: Report description
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute(
                '''INSERT INTO reports (timestamp, from_user, to_user, report_type, description)
                VALUES (?, ?, ?, ?, ?)''',
                (timestamp, from_user, to_user, report_type, description)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding report: {str(e)}")
            return False
    
    def get_reports(self, user: str, role: str = None) -> List[Dict[str, Any]]:
        """Get reports for a user
        
        Args:
            user: Username
            role: User role (if 'senior', shows all reports sent to user)
            
        Returns:
            List of report dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if role == 'senior':
                # Senior users can see reports addressed to them
                cursor.execute(
                    '''SELECT * FROM reports WHERE to_user = ? ORDER BY timestamp DESC''',
                    (user,)
                )
            else:
                # Other users can only see reports they created
                cursor.execute(
                    '''SELECT * FROM reports WHERE from_user = ? ORDER BY timestamp DESC''',
                    (user,)
                )
            
            reports = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return reports
            
        except Exception as e:
            self.logger.error(f"Error getting reports: {str(e)}")
            return []
    
    def add_task_history(self, user: str, task_type: str, description: str) -> bool:
        """Add a task to history
        
        Args:
            user: Username
            task_type: Type of task
            description: Task description
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute(
                '''INSERT INTO tasks (timestamp, user, type, description)
                VALUES (?, ?, ?, ?)''',
                (timestamp, user, task_type, description)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding task history: {str(e)}")
            return False
    
    def get_task_history(self, user: str) -> List[Dict[str, Any]]:
        """Get task history for a user
        
        Args:
            user: Username
            
        Returns:
            List of task dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                '''SELECT * FROM tasks WHERE user = ? ORDER BY timestamp DESC''',
                (user,)
            )
            
            tasks = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return tasks
            
        except Exception as e:
            self.logger.error(f"Error getting task history: {str(e)}")
            return []
    
    def add_system_log(self, user: str, action: str, details: str = None) -> bool:
        """Add a system log entry
        
        Args:
            user: Username
            action: Action performed
            details: Additional details
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute(
                '''INSERT INTO system_logs (timestamp, user, action, details)
                VALUES (?, ?, ?, ?)''',
                (timestamp, user, action, details)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding system log: {str(e)}")
            return False
    
    def get_system_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system logs
        
        Args:
            limit: Maximum number of logs to retrieve
            
        Returns:
            List of log dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                '''SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT ?''',
                (limit,)
            )
            
            logs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return logs
            
        except Exception as e:
            self.logger.error(f"Error getting system logs: {str(e)}")
            return []
    
    def save_user_settings(self, username: str, settings: Dict[str, Any]) -> bool:
        """Save user settings
        
        Args:
            username: Username
            settings: Dictionary of settings
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Convert settings dict to JSON string
            settings_json = json.dumps(settings)
            
            # Insert or replace settings
            cursor.execute(
                '''INSERT OR REPLACE INTO user_settings (username, settings)
                VALUES (?, ?)''',
                (username, settings_json)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving user settings: {str(e)}")
            return False
    
    def get_user_settings(self, username: str) -> Dict[str, Any]:
        """Get user settings
        
        Args:
            username: Username
            
        Returns:
            Dictionary of settings
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                '''SELECT settings FROM user_settings WHERE username = ?''',
                (username,)
            )
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return json.loads(result[0])
            return {}
            
        except Exception as e:
            self.logger.error(f"Error getting user settings: {str(e)}")
            return {} 