import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QLineEdit, QPushButton, QCheckBox, QFileDialog, QWidget, QHBoxLayout, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal
from core.passive import passive_enum
from core.active import active_enum
from core.brute import brute_force
import asyncio
from PyQt5.QtCore import QThread, pyqtSignal

class EnumerationThread(QThread):
    results_signal = pyqtSignal(str)  # Signal to send results back to the GUI

    def __init__(self, domain, wordlist, resolver_file, verbose, all_engines, passive, active, bruteforce):
        super().__init__()
        self.domain = domain
        self.wordlist = wordlist
        self.resolver_file = resolver_file
        self.verbose = verbose
        self.all_engines = all_engines
        self.passive = passive
        self.active = active
        self.bruteforce = bruteforce

    def run(self):
        results = ""
        try:
            if self.passive:
                results += "Starting Passive Enumeration...\n"
                results += passive_enum(self.domain, None, self.verbose, self.all_engines) + "\n"

            if self.active:
                results += "Starting Active DNS Probing...\n"
                results += active_enum(self.domain, None, self.verbose) + "\n"

            if self.bruteforce:
                results += "Starting Subdomain Brute-forcing...\n"
                results += asyncio.run(brute_force(self.domain, self.wordlist, self.resolver_file, None, self.verbose)) + "\n"

            results += "Enumeration Process Completed.\n"
        except Exception as e:
            results += f"Error: {e}\n"

        self.results_signal.emit(results)  # Send results back to the GUI


class AutoDNSGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoDNS - GUI")
        self.setGeometry(100, 100, 800, 600)

        # Main Layout
        layout = QVBoxLayout()

        # Domain Input
        self.domain_label = QLabel("Target Domain:")
        self.domain_input = QLineEdit()
        layout.addWidget(self.domain_label)
        layout.addWidget(self.domain_input)

        # Wordlist Input
        self.wordlist_label = QLabel("Custom Wordlist (Optional):")
        self.wordlist_input = QLineEdit()
        self.wordlist_button = QPushButton("Browse")
        self.wordlist_button.clicked.connect(self.browse_wordlist)
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(self.wordlist_input)
        wordlist_layout.addWidget(self.wordlist_button)
        layout.addWidget(self.wordlist_label)
        layout.addLayout(wordlist_layout)

        # Resolver File Input
        self.resolver_label = QLabel("Custom Resolver File (Optional):")
        self.resolver_input = QLineEdit()
        self.resolver_button = QPushButton("Browse")
        self.resolver_button.clicked.connect(self.browse_resolver_file)
        resolver_layout = QHBoxLayout()
        resolver_layout.addWidget(self.resolver_input)
        resolver_layout.addWidget(self.resolver_button)
        layout.addWidget(self.resolver_label)
        layout.addLayout(resolver_layout)

        # Output Display
        self.results_label = QLabel("Results:")
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        layout.addWidget(self.results_label)
        layout.addWidget(self.results_display)

        # Checkboxes for Options
        self.passive_checkbox = QCheckBox("Perform Passive Enumeration")
        self.active_checkbox = QCheckBox("Perform Active DNS Probing")
        self.bruteforce_checkbox = QCheckBox("Perform Subdomain Brute-forcing")
        self.all_engines_checkbox = QCheckBox("Use All Engines")
        self.verbose_checkbox = QCheckBox("Enable Verbose Output")
        layout.addWidget(self.passive_checkbox)
        layout.addWidget(self.active_checkbox)
        layout.addWidget(self.bruteforce_checkbox)
        layout.addWidget(self.all_engines_checkbox)
        layout.addWidget(self.verbose_checkbox)

        # Start Button
        self.start_button = QPushButton("Start Enumeration")
        self.start_button.clicked.connect(self.start_enumeration)
        layout.addWidget(self.start_button)

        # Set Main Widget
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def browse_wordlist(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File")
        if file_name:
            self.wordlist_input.setText(file_name)

    def browse_resolver_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Resolver File")
        if file_name:
            self.resolver_input.setText(file_name)

    def start_enumeration(self):
        # Gather inputs
        domain = self.domain_input.text()
        wordlist = self.wordlist_input.text()
        resolver_file = self.resolver_input.text()
        verbose = self.verbose_checkbox.isChecked()
        all_engines = self.all_engines_checkbox.isChecked()
        passive = self.passive_checkbox.isChecked()
        active = self.active_checkbox.isChecked()
        bruteforce = self.bruteforce_checkbox.isChecked()

        if not domain:
            self.results_display.append("Error: Please enter a target domain.")
            return

        # Create and start the thread
        self.thread = EnumerationThread(domain, wordlist, resolver_file, verbose, all_engines, passive, active, bruteforce)
        self.thread.results_signal.connect(self.display_results)
        self.thread.start()

    def display_results(self, results):
        self.results_display.append(results)
def launch_pyqt_gui():
    app = QApplication(sys.argv)
    gui = AutoDNSGUI()
    gui.show()
    sys.exit(app.exec_())