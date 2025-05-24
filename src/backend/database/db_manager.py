import sqlite3
import os
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import logging

class DatabaseManager:
    # This class handles all database interactions for the application.
    # It uses SQLite for simplicity and because it's a local desktop tool.

    def __init__(self, db_path: str = "config/app_data.db"):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        
        # Ensure the directory for the database file exists before trying to connect/create.
        db_dir = os.path.dirname(db_path)
        if db_dir: # Check if dirname returned something (it would be empty for a db in current dir)
             os.makedirs(db_dir, exist_ok=True)
        
        self._init_db()
    
    def _get_connection(self):
        # Helper to get a new database connection. 
        # Connections shouldn't be stored long-term as class members in SQLite with multithreading (if ever used).
        conn = sqlite3.connect(self.db_path)
        return conn
    
    def _init_db(self):
        # This method sets up the database schema if the tables don't already exist.
        # It's called when the DatabaseManager is initialized.
        try:
            conn = self._get_connection() # Use helper to get connection
            cursor = conn.cursor()
            
            # Table for reports submitted by junior admins to senior admins.
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, -- Unique ID for each report
                timestamp TEXT NOT NULL,              -- When the report was submitted
                from_user TEXT NOT NULL,            -- Junior admin who submitted
                to_user TEXT NOT NULL,              -- Senior admin it's for (usually a generic senior role)
                report_type TEXT NOT NULL,          -- Category of the report (e.g., "User Creation")
                description TEXT NOT NULL,          -- Detailed content of the report
                status TEXT DEFAULT 'pending'         -- e.g., pending, in-progress, completed, rejected
            )
            ''')
            
            # Table for general system audit logs.
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,                 -- User who performed the action
                action TEXT NOT NULL,               -- Type of action (e.g., "User Login", "Command Executed")
                details TEXT                      -- JSON string or text with more details about the action
            )
            ''')
            
            # Table for storing user-specific UI settings or preferences.
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                username TEXT PRIMARY KEY,          -- Link settings to a specific user
                settings TEXT NOT NULL            -- JSON string containing the actual settings dictionary
            )
            ''')
            
            # Table to keep a history of tasks performed by users.
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                type TEXT NOT NULL,                 -- Type of task (e.g., "Create User", "Reset Password")
                description TEXT NOT NULL,          -- More details about the task
                status TEXT DEFAULT 'completed'     -- Status of the task (e.g., completed, failed)
            )
            ''')
            
            conn.commit() # Save changes to the database
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error during DB initialization: {str(e)}")
            # This is a critical error, if the DB can't be initialized, the app might not work.
            raise # Re-raise to be handled by a global error handler or to stop the app.
        except Exception as e:
            self.logger.error(f"Unexpected error initializing database: {str(e)}")
            raise
        finally:
            if conn: # Always ensure the connection is closed.
                conn.close()
    
    def add_report(self, from_user: str, to_user: str, report_type: str, description: str) -> bool:
        # Adds a new report to the database.
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # Standard timestamp format
            
            cursor.execute(
                '''INSERT INTO reports (timestamp, from_user, to_user, report_type, description)
                VALUES (?, ?, ?, ?, ?)''',
                (current_timestamp, from_user, to_user, report_type, description)
            )
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error adding report: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error adding report: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_reports(self, user: str, role: str = None) -> List[Dict[str, Any]]:
        # Retrieves reports. If role is 'senior', gets reports for that senior user.
        # Otherwise, gets reports submitted by the specified 'user'.
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row # Access columns by name
            cursor = conn.cursor()
            
            if role == 'senior':
                # Seniors see reports sent to them.
                cursor.execute(
                    '''SELECT * FROM reports WHERE to_user = ? ORDER BY timestamp DESC''',
                    (user,)
                )
            else:
                # Juniors (or other roles) see reports they created.
                cursor.execute(
                    '''SELECT * FROM reports WHERE from_user = ? ORDER BY timestamp DESC''',
                    (user,)
                )
            
            reports = [dict(row) for row in cursor.fetchall()] # Convert rows to dictionaries
            return reports
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error getting reports: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error getting reports: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def add_task_history(self, user: str, task_type: str, description: str, status: str = 'completed') -> bool:
        # Adds a record of a completed (or failed) task to the history.
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute(
                '''INSERT INTO tasks (timestamp, user, type, description, status)
                VALUES (?, ?, ?, ?, ?)''',
                (current_timestamp, user, task_type, description, status) # Added status here
            )
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error adding task history: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error adding task history: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_task_history(self, user: str) -> List[Dict[str, Any]]:
        # Retrieves task history for a specific user.
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                '''SELECT * FROM tasks WHERE user = ? ORDER BY timestamp DESC''',
                (user,)
            )
            
            tasks = [dict(row) for row in cursor.fetchall()]
            return tasks
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error getting task history: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error getting task history: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def add_system_log(self, user: str, action: str, details: Optional[str] = None) -> bool:
        # Adds an audit log entry to the system_logs table.
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute(
                '''INSERT INTO system_logs (timestamp, user, action, details)
                VALUES (?, ?, ?, ?)''',
                (current_timestamp, user, action, details)
            )
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error adding system log: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error adding system log: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_system_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        # Retrieves the most recent system logs, up to a given limit.
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Order by timestamp descending to get the latest logs first.
            cursor.execute(
                '''SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT ?''',
                (limit,)
            )
            
            logs = [dict(row) for row in cursor.fetchall()]
            return logs
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error getting system logs: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error getting system logs: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def save_user_settings(self, username: str, settings: Dict[str, Any]) -> bool:
        # Saves or updates user-specific settings as a JSON string.
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            settings_json = json.dumps(settings) # Convert the settings dictionary to a JSON string.
            
            # Use INSERT OR REPLACE to handle both new and existing settings for a user.
            cursor.execute(
                '''INSERT OR REPLACE INTO user_settings (username, settings)
                VALUES (?, ?)''',
                (username, settings_json)
            )
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error saving user settings for {username}: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error saving user settings for {username}: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_user_settings(self, username: str) -> Dict[str, Any]:
        # Retrieves user-specific settings, parsing them from JSON string back to a dictionary.
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                '''SELECT settings FROM user_settings WHERE username = ?''',
                (username,)
            )
            
            result = cursor.fetchone() # Fetch a single row
            
            if result and result[0]: # Check if a result was found and settings column is not empty
                return json.loads(result[0]) # Parse JSON string to dictionary
            return {} # Return an empty dictionary if no settings are found for the user.
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error getting user settings for {username}: {str(e)}")
            return {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding user settings JSON for {username}: {str(e)}. Returning empty settings.")
            return {}
        except Exception as e:
            self.logger.error(f"Unexpected error getting user settings for {username}: {str(e)}")
            return {}
        finally:
            if conn:
                conn.close() 