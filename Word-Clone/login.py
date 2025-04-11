import sys
import os
import pickle
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, 
                            QLabel, QVBoxLayout, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Google OAuth 2.0 scopes
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

class AuthThread(QThread):
    auth_complete = pyqtSignal(dict)
    auth_failed = pyqtSignal(str)

    def run(self):
        try:
            # Always start fresh - remove any existing tokens
            if os.path.exists('token.pickle'):
                os.remove('token.pickle')
                
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
            
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

            service = build('oauth2', 'v2', credentials=creds)
            user_info = service.userinfo().get().execute()
            self.auth_complete.emit(user_info)
        except Exception as e:
            self.auth_failed.emit(str(e))

class GoogleLoginApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.auth_thread = None

    def initUI(self):
        self.setWindowTitle('Word Processor - Login')
        self.setFixedSize(400, 300)
        self.setStyleSheet("""
            background-color: #f5f5f5;
            font-family: 'Segoe UI', Arial, sans-serif;
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        title_label = QLabel('Word Processor')
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            font-size: 24px; 
            font-weight: bold; 
            color: #333;
            margin-bottom: 20px;
        """)
        
        instruction_label = QLabel('Sign in with your Google account')
        instruction_label.setAlignment(Qt.AlignCenter)
        instruction_label.setStyleSheet("""
            font-size: 14px;
            color: #666;
        """)
        
        self.login_button = QPushButton('Continue with Google')
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #4285F4;
                color: white;
                border: none;
                padding: 12px;
                font-size: 16px;
                border-radius: 4px;
                min-width: 200px;
            }
            QPushButton:hover {
                background-color: #3367D6;
            }
        """)
        self.login_button.clicked.connect(self.start_auth)
        
        self.status_label = QLabel('')
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            font-size: 12px;
            color: #888;
            margin-top: 20px;
        """)

        layout.addStretch(1)
        layout.addWidget(title_label)
        layout.addWidget(instruction_label)
        layout.addWidget(self.login_button, 0, Qt.AlignCenter)
        layout.addWidget(self.status_label)
        layout.addStretch(1)
        
        self.setLayout(layout)

    def start_auth(self):
        if not os.path.exists('credentials.json'):
            QMessageBox.critical(self, "Error", 
                "Google API credentials not found.\n"
                "Please ensure 'credentials.json' is in the application directory.")
            return
            
        self.login_button.setEnabled(False)
        self.status_label.setText('Redirecting to Google authentication...')
        QApplication.processEvents()
        
        self.auth_thread = AuthThread()
        self.auth_thread.auth_complete.connect(self.on_auth_success)
        self.auth_thread.auth_failed.connect(self.on_auth_failed)
        self.auth_thread.start()

    def on_auth_success(self, user_info):
        # Import MainApp here to avoid circular imports
        from main import MainApp
        self.main_app = MainApp(user_email=user_info.get('email', ''))
        self.main_app.showMaximized()
        self.hide()

    def on_auth_failed(self, error):
        self.login_button.setEnabled(True)
        self.status_label.setText('Authentication failed. Please try again.')
        QMessageBox.critical(self, "Login Error", 
            f"Could not authenticate with Google:\n{error}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = GoogleLoginApp()
    login_window.show()
    sys.exit(app.exec_())