import sys
import os
import sqlite3
import pandas as pd
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton, QLineEdit, QLabel, QGridLayout, QMenuBar, QTableWidget, QTableWidgetItem, QAction, QMessageBox, QFileDialog, QTextEdit
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from capture import capture_packets
from analyze import analyze_packets
from create_db import create_db
from data_analyze import load_ip_stats, load_layer_sequence, load_protocol_usage, load_tcp_flags, analyze_ip_stats, analyze_layer_sequence, analyze_protocol_usage, analyze_tcp_flags

class Worker(QThread):
    finished = pyqtSignal(list)  # 发送处理完的数据

    def __init__(self, interface):
        super(Worker, self).__init__()
        self.interface = interface

    def run(self):
        packets = capture_packets(self.interface, 10)  # 假设这是捕获函数
        analyzed_data = analyze_packets(packets)  # 假设这是分析函数
        self.save_results_to_db(analyzed_data)  # 确保数据被保存到数据库
        formatted_data = self.format_data(analyzed_data)  # 格式化数据
        self.finished.emit(formatted_data)  # 确保发送的是格式化后的字符串

    def save_results_to_db(self, data):
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()

        # 假设我们已经有了合适的表来存储数据
        for protocol, count in data.get('protocols', {}).items():
            cursor.execute("INSERT INTO ProtocolUsage (protocol, count) VALUES (?, ?)", (protocol, count))
        for ip, count in data.get('ip_src', {}).items():
            cursor.execute("INSERT INTO IPStats (ip_address, count, type) VALUES (?, ?, 'source')", (ip, count))
        for ip, count in data.get('ip_dst', {}).items():
            cursor.execute("INSERT INTO IPStats (ip_address, count, type) VALUES (?, ?, 'destination')", (ip, count))
        for flag, count in data.get('tcp_flags', {}).items():
            cursor.execute("INSERT INTO TCPFlags (flag, count) VALUES (?, ?)", (str(flag), count))
        for layers, count in data.get('protocol_layers', {}).items():
            sequence = ' -> '.join(layers)
            cursor.execute("INSERT INTO LayerSequence (sequence, count) VALUES (?, ?)", (sequence, count))

        conn.commit()
        conn.close()

    def format_data(self, data):
        """将字典格式化为字符串"""
        result = []
        result.append(("Summary", "Count", "Details"))
        result.extend([
            ("Protocols Usage", "", ""),
            *[(key, value, "Protocol layer") for key, value in data.get('protocols', {}).items()],
            ("Protocol Layers", "", ""),
            *[(key, count, "Layer sequence") for key, count in data.get('protocol_layers', {}).items()],
            ("Source IP Usage", "", ""),
            *[(key, value, "Source IPs") for key, value in data.get('ip_src', {}).items()],
            ("Destination IP Usage", "", ""),
            *[(key, value, "Destination IPs") for key, value in data.get('ip_dst', {}).items()],
            ("TCP Flags Usage", "", ""),
            *[(key, value, "TCP Flags") for key, value in data.get('tcp_flags', {}).items()]
        ])
        return result

class WindowsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        create_db()  # 确保数据库已创建

    def initUI(self):
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle('Network Monitor')
        vbox = QVBoxLayout(self)
        self.__addmenubar()
        self.__setHboxURL()
        self.__setHboxTab()
        self.__setHboxRes()
        self.__setAnalysisResultsArea()  # 添加新的函数来设置结果展示区域
        vbox.addLayout(self.layout)
        vbox.addLayout(self.hboxURL)
        vbox.addLayout(self.hboxTab)
        vbox.addLayout(self.hboxRes)
        vbox.addWidget(self.textResults)

    def __addmenubar(self):
        menubar = QMenuBar()
        self.layout = QGridLayout()
        self.layout.addWidget(menubar, 0, 0)
        actionFun = menubar.addMenu("功能")
        actionFun.addAction("开始分析")
        actionFun.addAction("停止分析")
        actionFun.addSeparator()
        exportCSVAction = QAction("导出成CSV", self)
        exportCSVAction.triggered.connect(self.exportResultsToCSV)
        actionFun.addAction(exportCSVAction)
        exportDBAction = QAction("导出到数据库", self)
        exportDBAction.triggered.connect(self.exportResultsToDB)
        actionFun.addAction(exportDBAction)
        actionView = menubar.addMenu("视图")
        actionView.addAction("全屏")
        actionView.addAction("窗口大小")
        actionHelp = menubar.addMenu("帮助")
        actionHelp.addAction("关于")

    def __setHboxURL(self):
        self.hboxURL = QHBoxLayout()
        label = QLabel("选择接口:")
        self.interfaceEdit = QLineEdit()
        self.interfaceEdit.setPlaceholderText("例如：eth0")
        self.startButton = QPushButton("开始监控")
        self.startButton.clicked.connect(self.startMonitoring)
        self.hboxURL.addWidget(label)
        self.hboxURL.addWidget(self.interfaceEdit)
        self.hboxURL.addWidget(self.startButton)

    def __setHboxTab(self):
        self.hboxTab = QHBoxLayout()
        self.tabWidget = QTabWidget()
        tabWidget = QTabWidget()
        tabConfig = QWidget()
        tabConfigLayout = QHBoxLayout(tabConfig)
        tabConfigLayout.addWidget(QLabel('配置路径'))
        configLineEdit = QLineEdit()
        configLineEdit.setText("./config/settings.ini")
        tabConfigLayout.addWidget(configLineEdit)
        self.tabWidget.addTab(tabConfig, "配置")

        # 添加新的分析标签
        tabAnalyze = QWidget()
        tabAnalyzeLayout = QVBoxLayout(tabAnalyze)  # 使用垂直布局

        # 为每个数据表添加分析按钮
        btnProtocolUsage = QPushButton("分析协议使用")
        btnProtocolUsage.clicked.connect(self.analyzeProtocolUsage)
        tabAnalyzeLayout.addWidget(btnProtocolUsage)

        btnIPStats = QPushButton("分析IP统计")
        btnIPStats.clicked.connect(self.analyzeIPStats)
        tabAnalyzeLayout.addWidget(btnIPStats)

        btnTCPFlags = QPushButton("分析TCP标志")
        btnTCPFlags.clicked.connect(self.analyzeTCPFlags)
        tabAnalyzeLayout.addWidget(btnTCPFlags)

        btnLayerSequence = QPushButton("分析层序列")
        btnLayerSequence.clicked.connect(self.analyzeLayerSequence)
        tabAnalyzeLayout.addWidget(btnLayerSequence)

        tabWidget.addTab(tabAnalyze, "分析数据")
        self.hboxTab.addWidget(tabWidget)

        self.hboxTab.addWidget(self.tabWidget)

    def __setHboxRes(self):
        self.hboxRes = QHBoxLayout()
        self.resultBox = QTableWidget(self)  # 初始化 QTableWidget
        self.resultBox.setColumnCount(3)  # 设置三列
        self.resultBox.setHorizontalHeaderLabels(["Category", "Data", "Description"])
        self.resultBox.setRowCount(10)  # 预设行数，可以根据需要调整或在运行时动态设置
        self.hboxRes.addWidget(self.resultBox)

    def displayAnalysisResults(self, results):
        # 在这里实现结果的显示，例如更新表格、文本框等
        pass

    def startMonitoring(self):
        interface = self.interfaceEdit.text()
        if not interface:
            QMessageBox.warning(self, "Warning", "请先输入网络接口名称")
            return
        self.worker = Worker(interface)
        self.worker.finished.connect(self.updateUI)
        self.worker.start()

    def updateUI(self, results):
        self.resultBox.setRowCount(len(results))
        for row_index, (category, data, description) in enumerate(results):
            self.resultBox.setItem(row_index, 0, QTableWidgetItem(str(category)))
            self.resultBox.setItem(row_index, 1, QTableWidgetItem(str(data)))
            self.resultBox.setItem(row_index, 2, QTableWidgetItem(str(description)))
        self.resultBox.resizeColumnsToContents()  # 调整列宽以适应内容

    def analyzeProtocolUsage(self):
        df = load_protocol_usage()
        results = analyze_protocol_usage(df)
        self.displayResults(results)

    def analyzeIPStats(self):
        df = load_ip_stats()
        src_counts, dst_counts = analyze_ip_stats(df)
        self.displayResults(src_counts)
        self.displayResults(dst_counts)

    def analyzeTCPFlags(self):
        df = load_tcp_flags()
        results = analyze_tcp_flags(df)
        self.displayResults(results)

    def analyzeLayerSequence(self):
        df = load_layer_sequence()
        results = analyze_layer_sequence(df)
        self.displayResults(results)

    def displayResults(self, results):
        # 清除当前文本框内容
        self.textResults.clear()

        if isinstance(results, pd.DataFrame):
            # 将DataFrame转换为字符串形式显示
            text_data = results.to_string(index=False)
            self.textResults.setPlainText(text_data)  # 使用setPlainText来显示纯文本
        else:
            # 直接显示文本结果
            self.textResults.setPlainText(str(results))

        # 重新设置文本框可见，以确保用户能够看到最新的结果
        self.textResults.setVisible(True)

    def __setAnalysisResultsArea(self):
        self.textResults = QTextEdit(self)  # 创建一个新的表格
        self.textResults.setReadOnly(True)  # 设置为只读，不允许用户修改内容
        layout = QVBoxLayout()  # 创建一个垂直布局
        layout.addWidget(self.textResults)  # 将文本编辑框添加到布局中
        # self.setLayout(layout)  # 设置窗口的主布局

        # # 添加标签页
        # self.resultsTab.addTab(self.textResults, "文本结果")
        # self.resultsTab.addTab(self.tableResults, "表格结果")
        
        # # 将标签页容器添加到主布局
        # self.layout.addWidget(self.resultsTab)

    def exportResultsToCSV(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as file:
                headers = ["Category", "Data", "Description"]
                file.write(','.join(headers) + '\n')
                for row in range(self.resultBox.rowCount()):
                    row_data = [self.resultBox.item(row, col).text() if self.resultBox.item(row, col) else '' for col in range(self.resultBox.columnCount())]
                    file.write(','.join(row_data) + '\n')
            QMessageBox.information(self, "Export Successful", "Data has been exported successfully to " + path)

    def exportResultsToDB(self):
        QMessageBox.information(self, "提示", "数据已经保存在数据库中。")

if __name__ == '__main__':
    correct_path = "D:\\文档\\毕业论文（设计）表格\\item\\venv\\Lib\\site-packages\\PyQt5\\Qt5\\plugins"
    os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = correct_path
    app = QApplication(sys.argv)
    ex = WindowsView()
    ex.show()
    sys.exit(app.exec_())