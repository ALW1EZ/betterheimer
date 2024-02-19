from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QCheckBox,
    QMenu,
    QPushButton,
    QAction,
    QFileDialog,
    QMessageBox,
    QSpinBox,
    QHBoxLayout,
    QTabWidget,
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
from mcstatus import JavaServer
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import ipaddress
import subprocess
import os


class Worker(QThread):
    update_signal = pyqtSignal(list)
    finished_signal = pyqtSignal()

    def __init__(self, network, only_with_players, version_text, max_workers):
        super().__init__()
        self.network = network
        self.only_with_players = only_with_players
        self.version_text = version_text
        self.is_running = True
        self.max_workers = max_workers

    def run(self):
        def scan_port(ip, only_with_players, version_text):
            if not self.is_running:
                return
            try:
                server = JavaServer.lookup(ip + ":25565")
                status = server.status()
                player_texts = (
                    f"{', '.join([player.name for player in status.players.sample])}"
                    if status.players.online > 0
                    else "No players online."
                )

                info_line = [
                    ip,
                    status.version.name,
                    status.motd.to_plain(),
                    str(status.players.online),
                    player_texts,
                ]

                if (
                    only_with_players
                    and status.players.online > 0
                    and (version_text in status.version.name if version_text else True)
                ):
                    self.update_signal.emit(info_line)
                elif not only_with_players and (
                    version_text in status.version.name if version_text else True
                ):
                    self.update_signal.emit(info_line)
            except (
                TimeoutError,
                BrokenPipeError,
                ConnectionResetError,
                OSError,
            ):
                pass

        futures = []
        try:
            network = ipaddress.IPv4Network(self.network)
        except ValueError as e:
            QMessageBox.critical(None, "Error", f"Invalid network range: {e}")
            self.finished_signal.emit()
            return

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for ip in network:
                if not self.is_running:
                    break
                future = executor.submit(
                    scan_port, str(ip), self.only_with_players, self.version_text
                )
                futures.append(future)

        for future in futures:
            future.cancel()

        self.finished_signal.emit()

    def stop(self):
        self.is_running = False


class MainWindow(QWidget):
    
    def is_node_installed(self):
        return (
            os.system("node -v > /dev/null  2>&1") == 0
            or os.system("nodejs -v > /dev/null  2>&1") == 0
        )

    def __init__(self):
        super().__init__()
        self.setWindowTitle("BetterHeimer")
        self.initUI()
        self.setStyleSheet("background-color: #333; color: white;")
        if not self.is_node_installed():
            self.tabWidget.setTabEnabled(1, False)
            self.tabWidget.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
            self.tabWidget.tabBar().customContextMenuRequested.connect(
                self.showNodeNotInstalledMenu
            )

    def showNodeNotInstalledMenu(self, position):
        contextMenu = QMenu(self)
        nodeNotInstalledAction = QAction(
            "If you don't have Node.js installed on your system (PATH), you cannot use this module",
            self,
        )
        contextMenu.addAction(nodeNotInstalledAction)
        contextMenu.exec_(self.tabWidget.tabBar().mapToGlobal(position))

    def initUI(self):
        mainLayout = QVBoxLayout()
        self.tabWidget = QTabWidget()
        scanTab = QWidget()
        scanLayout = QVBoxLayout()

        self.betterHeimerLabel = QLabel("BetterHeimer")
        self.betterHeimerLabel.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.betterHeimerLabel.setFont(QFont("Monospace", 12))
        self.betterHeimerLabel.setToolTip("by ALW1EZ")
        mainLayout.addWidget(self.betterHeimerLabel)

        self.networkInputLabel = QLabel("Network range to scan, e.g., x.x.0.0/16")
        scanLayout.addWidget(self.networkInputLabel)

        self.networkInput = QLineEdit()
        scanLayout.addWidget(self.networkInput)

        self.onlyWithPlayersCheckbox = QCheckBox("Only with players")
        scanLayout.addWidget(self.onlyWithPlayersCheckbox)

        self.onlyIfVersionContainsCheckbox = QCheckBox(
            "Only if version contains this text:"
        )
        self.onlyIfVersionContainsCheckbox.stateChanged.connect(
            self.enableVersionContainsText
        )
        self.versionContainsText = QLineEdit()
        self.versionContainsText.setEnabled(False)

        versionsLayout = QHBoxLayout()
        versionsLayout.addWidget(self.onlyIfVersionContainsCheckbox)
        versionsLayout.addWidget(self.versionContainsText)
        scanLayout.addLayout(versionsLayout)

        self.maxWorkersLabel = QLabel("Max workers: ")
        self.maxWorkersSpinBox = QSpinBox()
        self.maxWorkersSpinBox.setMaximum(100000)
        self.maxWorkersSpinBox.setMinimum(1)
        self.maxWorkersSpinBox.setValue(500)

        workersLayout = QHBoxLayout()
        workersLayout.addWidget(self.maxWorkersLabel)
        workersLayout.addWidget(self.maxWorkersSpinBox)
        scanLayout.addLayout(workersLayout)

        self.scanAll = QPushButton("Scan all servers")
        self.scanAll.clicked.connect(self.startScanAll)
        scanLayout.addWidget(self.scanAll)

        self.searchLabel = QLabel("Search:")
        scanLayout.addWidget(self.searchLabel)

        self.searchInput = QLineEdit()
        self.searchInput.textChanged.connect(self.filterRows)
        scanLayout.addWidget(self.searchInput)

        self.output = QTableWidget()
        self.output.setColumnCount(5)
        self.output.setHorizontalHeaderLabels(
            ["IP Address", "Version", "MOTD", "Players Online", "Players"]
        )
        self.output.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.output.wordWrap = True
        self.output.setSortingEnabled(False)
        scanLayout.addWidget(self.output)
        self.output.setContextMenuPolicy(Qt.CustomContextMenu)
        self.output.customContextMenuRequested.connect(self.showContextMenu)

        self.progressBar = QProgressBar()
        scanLayout.addWidget(self.progressBar)

        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.cancelJob)
        scanLayout.addWidget(self.cancelButton)

        scanTab.setLayout(scanLayout)
        self.tabWidget.addTab(scanTab, "     Scan     ")

        checkTab = QWidget()
        checkLayout = QVBoxLayout()

        self.ipFileInputLabel = QLabel("Select IP file:")
        checkLayout.addWidget(self.ipFileInputLabel)

        self.ipFileInput = QLineEdit()
        checkLayout.addWidget(self.ipFileInput)

        self.ipFileBrowseButton = QPushButton("Browse")
        self.ipFileBrowseButton.clicked.connect(self.browseForIpFile)
        checkLayout.addWidget(self.ipFileBrowseButton)

        self.checkMaxWorkersLabel = QLabel("Max workers: ")
        self.checkMaxWorkersSpinBox = QSpinBox()
        self.checkMaxWorkersSpinBox.setMaximum(100000)
        self.checkMaxWorkersSpinBox.setMinimum(1)
        self.checkMaxWorkersSpinBox.setValue(10)

        checkWorkersLayout = QHBoxLayout()
        checkWorkersLayout.addWidget(self.checkMaxWorkersLabel)
        checkWorkersLayout.addWidget(self.checkMaxWorkersSpinBox)
        checkLayout.addLayout(checkWorkersLayout)

        self.runCheckButton = QPushButton("Run Check")
        self.runCheckButton.clicked.connect(self.runCheckScript)
        checkLayout.addWidget(self.runCheckButton)

        self.checkOutput = QTableWidget()
        self.checkOutput.setColumnCount(2)
        self.checkOutput.setHorizontalHeaderLabels(["IP Address", "Result"])
        self.checkOutput.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.checkOutput.setContextMenuPolicy(Qt.CustomContextMenu)
        self.checkOutput.customContextMenuRequested.connect(self.showCheckContextMenu)
        checkLayout.addWidget(self.checkOutput)

        checkTab.setLayout(checkLayout)
        self.tabWidget.addTab(checkTab, "     Check     ")

        mainLayout.addWidget(self.tabWidget)
        self.setLayout(mainLayout)

        self.enableButtons(True)

    def browseForIpFile(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select IP File", "", "Text Files (*.txt)"
        )
        if filename:
            self.ipFileInput.setText(filename)

    def runCheckScript(self):
        ip_file_path = self.ipFileInput.text()
        if not ip_file_path:
            QMessageBox.critical(self, "Error", "Please select an IP file.")
            return

        try:
            with open(ip_file_path, "r") as ip_file:
                ips = ip_file.read().splitlines()
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "No such file or directory.")
            return

        self.checkOutput.setRowCount(0)
        def run_check_for_ip(ip):
            try:
                result = subprocess.run(
                    ["node", "check/check.js", ip],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if result.returncode == 0:
                    return (ip, "Success")
                else:
                    return None
            except subprocess.CalledProcessError as e:
                return None

        max_workers = self.checkMaxWorkersSpinBox.value()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_check_for_ip, ip) for ip in ips]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    row_position = self.checkOutput.rowCount()
                    self.checkOutput.insertRow(row_position)
                    ip, status = result
                    self.checkOutput.setItem(row_position, 0, QTableWidgetItem(ip))
                    self.checkOutput.setItem(row_position, 1, QTableWidgetItem(status))

    def startScanAll(self):
        self.prepareForScan()
        if not self.networkInput.text():
            QMessageBox.critical(self, "Error", "Network range cannot be empty.")
            self.scanFinished()
            return
        self.worker = Worker(
            self.networkInput.text(),
            self.onlyWithPlayersCheckbox.isChecked(),
            (
                self.versionContainsText.text()
                if self.onlyIfVersionContainsCheckbox.isChecked()
                else None
            ),
            self.maxWorkersSpinBox.value(),
        )
        self.setupWorker()

    def showContextMenu(self, position):
        contextMenu = QMenu(self)
        saveIpsAction = QAction("Save IPs", self)
        saveIpsAction.triggered.connect(self.saveScanIPs)
        saveIpsWithInfoAction = QAction("Save IPs with Info", self)
        saveIpsWithInfoAction.triggered.connect(self.saveScanIPsWithInfo)
        sortByVersionAction = QAction("Sort by version", self)
        sortByVersionAction.triggered.connect(self.sortOutputByVersion)
        contextMenu.addAction(sortByVersionAction)
        contextMenu.addAction(saveIpsAction)
        contextMenu.addAction(saveIpsWithInfoAction)
        contextMenu.exec_(self.output.viewport().mapToGlobal(position))

    def showCheckContextMenu(self, position):
        contextMenu = QMenu(self)
        saveIpsAction = QAction("Save IPs", self)
        saveIpsAction.triggered.connect(self.saveCheckIPs)
        contextMenu.addAction(saveIpsAction)
        contextMenu.exec_(self.checkOutput.viewport().mapToGlobal(position))

    def saveCheckIPs(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "", "*.txt")
        if filename:
            with open(filename, "w") as f:
                for row in range(self.checkOutput.rowCount()):
                    ip = self.checkOutput.item(row, 0).text()
                    f.write(f"{ip}\n")

    def saveScanIPs(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "", "*.txt")
        if filename:
            with open(filename, "w") as f:
                for row in range(self.output.rowCount()):
                    ip = self.output.item(row, 0).text()
                    f.write(f"{ip}\n")

    def saveScanIPsWithInfo(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "", "*.txt")
        if filename:
            with open(filename, "w") as f:
                for row in range(self.output.rowCount()):
                    data = [
                        self.output.item(row, col).text()
                        for col in range(self.output.columnCount())
                    ]
                    f.write(",".join(data) + "\n")

    def sortOutputByVersion(self):
        self.output.sortItems(1, Qt.SortOrder.DescendingOrder)

    def setupWorker(self):
        self.worker.update_signal.connect(self.updateOutput)
        self.worker.finished_signal.connect(self.scanFinished)
        self.worker.start()

    def prepareForScan(self):
        self.output.setRowCount(0)
        self.progressBar.setRange(0, 0)
        self.enableButtons(False)

    def scanFinished(self):
        self.enableButtons(True)
        self.progressBar.setRange(0, 1)
        self.progressBar.setValue(1)

    def enableButtons(self, enable):
        self.onlyWithPlayersCheckbox.setEnabled(enable)
        self.onlyIfVersionContainsCheckbox.setEnabled(enable)
        self.scanAll.setEnabled(enable)
        self.searchInput.setEnabled(enable)
        self.networkInput.setEnabled(enable)
        self.cancelButton.setEnabled(not enable)
        self.maxWorkersSpinBox.setEnabled(enable)

    def cancelJob(self):
        self.worker.stop()
        self.scanFinished()

    def updateOutput(self, info_line):
        row_position = self.output.rowCount()
        self.output.insertRow(row_position)
        for i, item in enumerate(info_line):
            self.output.setItem(row_position, i, QTableWidgetItem(item))

    def enableVersionContainsText(self):
        self.versionContainsText.setEnabled(
            self.onlyIfVersionContainsCheckbox.isChecked()
        )

    def filterRows(self):
        search_text = self.searchInput.text().lower()
        for row in range(self.output.rowCount()):
            row_visible = False
            for column in range(self.output.columnCount()):
                item = self.output.item(row, column)
                if search_text in item.text().lower():
                    row_visible = True
                    break
            self.output.setRowHidden(row, not row_visible)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
