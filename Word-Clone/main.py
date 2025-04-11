import sys
import os
import json
import base64
import webbrowser
import urllib.parse
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtPrintSupport import *
import docx2txt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class MainApp(QMainWindow):
    def __init__(self, user_email=''):
        super().__init__()
        self.user_email = user_email
        self.path = ''
        
        # # Window setup
        self.title = "Word Clone"
        self.setWindowTitle(self.title)
        
        # Create main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create header bar with user info
        self.create_user_header(main_layout)
        
        # Editor section
        self.editor = QTextEdit()
        main_layout.addWidget(self.editor)

        # Initialize UI components
        self.create_menu_bar()
        self.create_toolbar()
        self.set_default_font()
        self.statusBar().showMessage("Ready")

    def create_user_header(self, parent_layout):
        """Create header bar with user email and logout button"""
        header = QWidget()
        header.setStyleSheet("""
            background-color: #f5f5f5;
            border-bottom: 1px solid #ddd;
            padding: 5px;
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 5, 10, 5)
        
        header_layout.addStretch()
        
        user_label = QLabel(f"User: {self.user_email}")
        user_label.setStyleSheet("""
            font-size: 12px;
            color: #555;
            padding: 2px 8px;
        """)
        header_layout.addWidget(user_label)
        
        logout_btn = QPushButton("Logout")
        logout_btn.setStyleSheet("""
            QPushButton {
                padding: 3px 10px;
                font-size: 12px;
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        logout_btn.clicked.connect(self.logout)
        header_layout.addWidget(logout_btn)
        
        parent_layout.addWidget(header)
    
    def logout(self):
        """Handle logout action"""
        reply = QMessageBox.question(
            self,
            'Confirm Logout',
            'Are you sure you want to logout?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.close()
            QApplication.quit()
    
    def save_pdf(self):
        """Save the current document as a PDF file"""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export as PDF",
            os.path.expanduser("~"),
            "PDF Files (*.pdf);;All Files (*)"
        )
        
        if not path:
            return
            
        try:
            if not path.lower().endswith('.pdf'):
                path += '.pdf'
                
            printer = QPrinter(QPrinter.HighResolution)
            printer.setOutputFormat(QPrinter.PdfFormat)
            printer.setOutputFileName(path)
            
            self.editor.document().print_(printer)
            
            self.statusBar().showMessage(f"Exported as PDF: {os.path.basename(path)}", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save PDF:\n{str(e)}")

    def create_menu_bar(self):
        menuBar = QMenuBar(self)

        # File menu
        file_menu = QMenu("File", self)
        menuBar.addMenu(file_menu)

        # File actions
        save_action = QAction('Save', self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.file_save)
        file_menu.addAction(save_action)

        open_action = QAction('Open', self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.file_open)
        file_menu.addAction(open_action)

        rename_action = QAction('Save As', self)
        rename_action.setShortcut("Ctrl+Shift+S")
        rename_action.triggered.connect(self.file_saveas)
        file_menu.addAction(rename_action)

        pdf_action = QAction("Save as PDF", self)
        pdf_action.triggered.connect(self.save_pdf)
        file_menu.addAction(pdf_action)
        
        protected_action = QAction("Save as Protected", self)
        protected_action.setShortcut("Ctrl+Shift+P")
        protected_action.triggered.connect(self.save_protected)
        file_menu.addAction(protected_action)
        
        # Add logout to File menu
        file_menu.addSeparator()
        logout_action = QAction('Logout', self)
        logout_action.setShortcut("Ctrl+L")
        logout_action.triggered.connect(self.logout)
        file_menu.addAction(logout_action)

        # Edit menu
        edit_menu = QMenu("Edit", self)
        menuBar.addMenu(edit_menu)

        # Edit actions
        paste_action = QAction('Paste', self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.editor.paste)
        edit_menu.addAction(paste_action)

        clear_action = QAction('Clear', self)
        clear_action.triggered.connect(self.editor.clear)
        edit_menu.addAction(clear_action)

        select_action = QAction('Select All', self)
        select_action.setShortcut("Ctrl+A")
        select_action.triggered.connect(self.editor.selectAll)
        edit_menu.addAction(select_action)

        # View menu
        view_menu = QMenu("View", self)
        menuBar.addMenu(view_menu)

        # View actions
        fullscr_action = QAction('Full Screen View', self)
        fullscr_action.setShortcut("F11")
        fullscr_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscr_action)

        self.setMenuBar(menuBar)

    def create_toolbar(self):
        ToolBar = QToolBar("Tools", self)

        # Undo/Redo
        undo_action = QAction(QIcon("undo.png"), 'Undo', self)
        undo_action.setShortcut("Ctrl+Z")
        undo_action.triggered.connect(self.editor.undo)
        ToolBar.addAction(undo_action)

        redo_action = QAction(QIcon("redo.png"), 'Redo', self)
        redo_action.setShortcut("Ctrl+Y")
        redo_action.triggered.connect(self.editor.redo)
        ToolBar.addAction(redo_action)

        ToolBar.addSeparator()

        # Copy/Cut/Paste
        copy_action = QAction(QIcon("copy.png"), 'Copy', self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.editor.copy)
        ToolBar.addAction(copy_action)

        cut_action = QAction(QIcon("cut.png"), 'Cut', self)
        cut_action.setShortcut("Ctrl+X")
        cut_action.triggered.connect(self.editor.cut)
        ToolBar.addAction(cut_action)

        paste_action = QAction(QIcon("paste.png"), 'Paste', self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.editor.paste)
        ToolBar.addAction(paste_action)

        ToolBar.addSeparator()

        # Font selection
        self.font_combo = QComboBox(self)
        self.font_combo.addItems(["Arial", "Times New Roman", "Courier New", "Verdana", "Georgia"])
        self.font_combo.activated.connect(self.set_font)
        ToolBar.addWidget(self.font_combo)

        # Font size
        self.font_size = QSpinBox(self)
        self.font_size.setRange(8, 72)
        self.font_size.setValue(12)
        self.font_size.valueChanged.connect(self.set_font_size)
        ToolBar.addWidget(self.font_size)

        ToolBar.addSeparator()

        # Text formatting
        bold_action = QAction(QIcon("bold.png"), 'Bold', self)
        bold_action.setShortcut("Ctrl+B")
        bold_action.triggered.connect(self.bold_text)
        ToolBar.addAction(bold_action)

        italic_action = QAction(QIcon("italic.png"), 'Italic', self)
        italic_action.setShortcut("Ctrl+I")
        italic_action.triggered.connect(self.italic_text)
        ToolBar.addAction(italic_action)

        underline_action = QAction(QIcon("underline.png"), 'Underline', self)
        underline_action.setShortcut("Ctrl+U")
        underline_action.triggered.connect(self.underline_text)
        ToolBar.addAction(underline_action)

        ToolBar.addSeparator()

        # Text alignment
        left_align_action = QAction(QIcon("left-align.png"), 'Align Left', self)
        left_align_action.triggered.connect(lambda: self.editor.setAlignment(Qt.AlignLeft))
        ToolBar.addAction(left_align_action)

        center_align_action = QAction(QIcon("center-align.png"), 'Center', self)
        center_align_action.triggered.connect(lambda: self.editor.setAlignment(Qt.AlignCenter))
        ToolBar.addAction(center_align_action)

        right_align_action = QAction(QIcon("right-align.png"), 'Align Right', self)
        right_align_action.triggered.connect(lambda: self.editor.setAlignment(Qt.AlignRight))
        ToolBar.addAction(right_align_action)

        self.addToolBar(ToolBar)

    def set_default_font(self):
        font = QFont('Times', 12)
        self.editor.setFont(font)
        self.editor.setFontPointSize(12)

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def italic_text(self):
        self.editor.setFontItalic(not self.editor.fontItalic())

    def underline_text(self):
        self.editor.setFontUnderline(not self.editor.fontUnderline())

    def bold_text(self):
        self.editor.setFontWeight(QFont.Bold if self.editor.fontWeight() != QFont.Bold else QFont.Normal)

    def set_font(self):
        font = self.font_combo.currentText()
        self.editor.setCurrentFont(QFont(font))

    def set_font_size(self):
        value = self.font_size.value()
        self.editor.setFontPointSize(value)

    def file_open(self):
        try:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Open File",
                os.path.expanduser("~"),
                "All Supported Files (*.txt *.docx *.protected);;"
                "Text Files (*.txt);;"
                "Word Documents (*.docx);;"
                "Protected Documents (*.protected);;"
                "All Files (*)"
            )
            
            if not path:
                return
                
            self.statusBar().showMessage("Opening file...")
            QApplication.processEvents()
            QApplication.setOverrideCursor(Qt.WaitCursor)
            
            path = os.path.normpath(path)
            
            if not os.access(path, os.R_OK):
                raise IOError("File is not readable or doesn't exist")
                
            if path.lower().endswith('.protected'):
                self.open_protected_file(path)
            else:
                self.open_normal_file(path)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open file:\n{str(e)}")
        finally:
            self.statusBar().clearMessage()
            QApplication.restoreOverrideCursor()

    def open_normal_file(self, path):
        try:
            if path.lower().endswith('.docx'):
                text = docx2txt.process(path)
            else:
                with open(path, 'r', encoding='utf-8') as f:
                    text = f.read()
                    
            self.editor.setText(text)
            self.path = path
            self.update_title()
            self.statusBar().showMessage(f"Opened {os.path.basename(path)}", 3000)
            
        except Exception as e:
            raise Exception(f"Failed to read file: {str(e)}")

    def open_protected_file(self, path):
        # Create a dialog for secret key input
        dialog = QDialog(self)
        dialog.setWindowTitle("Enter Decryption Key")
        dialog.setModal(True)
        dialog.setFixedSize(400, 200)
        
        layout = QVBoxLayout()
        
        label = QLabel("Please enter the secret key to decrypt the file:")
        layout.addWidget(label)
        
        key_input = QLineEdit()
        key_input.setEchoMode(QLineEdit.Password)  # Hide the input
        layout.addWidget(key_input)
        
        # Buttons
        button_box = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")
        
        button_box.addStretch()
        button_box.addWidget(ok_btn)
        button_box.addWidget(cancel_btn)
        layout.addLayout(button_box)
        
        dialog.setLayout(layout)
        
        # Connect buttons
        ok_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)
        
        # Show dialog and get result
        if dialog.exec_() != QDialog.Accepted:
            return
            
        secret_key = key_input.text().strip()
        
        if not secret_key:
            QMessageBox.warning(self, "Error", "No key provided")
            return
            
        try:
            # Decode the base64 key from user input
            key = base64.b64decode(secret_key)
            
            # Ensure key is 32 bytes (AES-256 requirement)
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes (256 bits) long")
            
            with open(path, 'rb') as f:
                iv = f.read(16)
                encrypted_data = f.read()
                
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            pad_length = decrypted_data[-1]
            if pad_length < 1 or pad_length > 16:
                raise ValueError("Invalid padding")
            decrypted_data = decrypted_data[:-pad_length]
            
            self.editor.setText(decrypted_data.decode('utf-8'))
            self.path = path
            self.update_title()
            self.statusBar().showMessage(f"Opened protected file {os.path.basename(path)}", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt file: {str(e)}")

    def file_save(self):
        if not self.path:
            self.file_saveas()
            return
            
        try:
            text = self.editor.toPlainText()
            
            with open(self.path, 'w', encoding='utf-8') as f:
                f.write(text)
                
            self.update_title()
            self.statusBar().showMessage(f"Saved {os.path.basename(self.path)}", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")

    def file_saveas(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File",
            os.path.expanduser("~"),
            "Text Files (*.txt);;All Files (*)"
        )
        
        if not path:
            return
            
        try:
            text = self.editor.toPlainText()
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
                
            self.path = path
            self.update_title()
            self.statusBar().showMessage(f"Saved as {os.path.basename(path)}", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")

    def save_protected(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Protected File",
            os.path.expanduser("~"),
            "Protected Documents (*.protected);;All Files (*)"
        )
        
        if not path:
            return
            
        try:
            # Generate random key and IV
            key = get_random_bytes(32)
            iv = get_random_bytes(16)
            
            # Get the text to encrypt
            text = self.editor.toPlainText().encode('utf-8')
            
            # Pad the text to be a multiple of 16 bytes (AES block size)
            pad_length = 16 - (len(text) % 16)
            text += bytes([pad_length] * pad_length)
            
            # Create cipher object and encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_data = cipher.encrypt(text)
            
            # Save the encrypted file
            with open(path, 'wb') as f:
                f.write(iv)
                f.write(encrypted_data)
            
            # Prepare key information
            key_info = {
                'key': base64.b64encode(key).decode('utf-8'),
                'file_path': os.path.basename(path),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'timestamp': QDateTime.currentDateTime().toString(Qt.ISODate)
            }
            
            # Send via Gmail compose window
            self.send_via_gmail_compose(key_info)
            
            self.path = path
            self.update_title()
            self.statusBar().showMessage(f"Saved protected file {os.path.basename(path)}", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save protected file: {str(e)}")

    def send_via_gmail_compose(self, key_info):
        """Open Gmail compose window with key information"""
        try:
            # Prepare the email body
            email_body = (
                f"Here is your decryption key for the protected document:\n\n"
                f"File Name: {key_info['file_path']}\n"
                f"Created: {key_info['timestamp']}\n"
                f"Encryption Key: {key_info['key']}\n"
                f"Initialization Vector: {key_info['iv']}\n\n"
                f"IMPORTANT:\n"
                f"- Keep this email secure\n"
                f"- Without this key, your document cannot be decrypted\n"
                f"- Do not share this key with anyone you don't trust"
            )
            
            # URL encode the subject and body
            subject = f"Your Document Decryption Key for {key_info['file_path']}"
            encoded_subject = urllib.parse.quote(subject)
            encoded_body = urllib.parse.quote(email_body)
            
            # Construct Gmail compose URL
            gmail_url = (
                f"https://mail.google.com/mail/u/0/?view=cm&fs=1"
                f"&to={urllib.parse.quote(self.user_email)}"
                f"&su={encoded_subject}"
                f"&body={encoded_body}"
            )
            
            # Open the URL in default browser
            webbrowser.open(gmail_url)
            
            QMessageBox.information(
                self,
                "Success",
                "A Gmail compose window has been opened with the decryption key.\n"
                "Please review and send the email manually."
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Gmail compose window: {str(e)}\n\n"
                "Falling back to saving key to file."
            )
            self.save_key_to_file(key_info, os.path.dirname(self.path) if self.path else os.path.expanduser("~"))

    def save_key_to_file(self, key_info, directory):
        """Save the encryption key to a file as fallback"""
        try:
            key_path = os.path.join(directory, f"{key_info['file_path']}.key")
            
            if os.path.exists(key_path):
                reply = QMessageBox.question(
                    self,
                    "Key File Exists",
                    f"A key file already exists at:\n{key_path}\nOverwrite?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return False
            
            with open(key_path, 'w') as f:
                json.dump(key_info, f, indent=2)
                
            QMessageBox.information(
                self,
                "Key Saved",
                f"Encryption key saved to:\n{key_path}\n\n"
                "IMPORTANT: Keep this file secure! Without it, your document cannot be decrypted."
            )
            return True
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save key file:\n{str(e)}\n\n"
                "Please manually note down this information:\n\n"
                f"Key: {key_info['key']}\n"
                f"IV: {key_info['iv']}"
            )
            return False

    def update_title(self):
        basename = os.path.basename(self.path) if self.path else "Untitled"
        self.setWindowTitle(f"{basename} - {self.title}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Warning)
    msg.setText("Please run login.py to start the application")
    msg.setWindowTitle("Invalid Launch")
    msg.exec_()
    sys.exit(1)