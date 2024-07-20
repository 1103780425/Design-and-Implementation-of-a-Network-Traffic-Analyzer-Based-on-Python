import sys
import os
import sqlite3
import pandas as pd
import wmi
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QTabWidget, QPushButton, QLineEdit, QLabel, 
                             QGridLayout, QMenuBar, QTableWidget, QTableWidgetItem, 
                             QAction, QMessageBox, QFileDialog, QTextEdit,
                             QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from capture import capture_packets
from analyze import analyze_packets
from create_db import create_db
from data_analyze import (load_ip_stats, load_layer_sequence, load_protocol_usage, 
                          load_tcp_flags, analyze_ip_stats, analyze_layer_sequence, 
                          analyze_protocol_usage, analyze_tcp_flags, format_analysis_results)

class Worker(QThread):
    finished = pyqtSignal(list)  # 发送处理完的数据
    error = pyqtSignal(str)
    all_data_captured = pyqtSignal(object)  # 用于发送所有捕获数据的信号

    def __init__(self, interface):
        super(Worker, self).__init__()
        self.interface = interface
        self.running = False
        self.all_packets = []  # 存储所有捕获的数据包

    def run(self):
        self.running = True
        while self.running:
            packets = capture_packets(self.interface, 10)  # 捕获数据包
            if packets:
                self.all_packets.extend(packets)  # 添加到列表中
            else:
                self.error.emit("No packets captured.")
                break
        # 循环结束后处理所有数据包
        if self.all_packets:
            try:
                analyzed_data = analyze_packets(self.all_packets)  # 分析所有数据包
                self.save_results_to_db(analyzed_data)
                formatted_data = self.format_data(analyzed_data)
                self.all_data_captured.emit(formatted_data)
            except Exception as e:
                self.error.emit(str(e))
            # finally:
            #     self.running = False

    def stop(self):
        self.running = False # 设置标志以停止线程运行

    def save_results_to_db(self, data):
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()
        try:
        
            # 假设我们已经有了合适的表来存储数据
            for protocol, count in data.get('protocols', {}).items():
                self.update_or_insert(cursor, "ProtocolUsage", 'protocol', protocol, count)

            for ip, count in data.get('ip_src', {}).items():
                self.update_or_insert(cursor, "IPStats", 'ip_address', ip, count, 'source')

            for ip, count in data.get('ip_dst', {}).items():
                self.update_or_insert(cursor, "IPStats", 'ip_address', ip, count, 'destination')

            for flag, count in data.get('tcp_flags', {}).items():
                print(f"Flag: {flag}, Type: {type(flag)}, Count: {count}")
                self.update_or_insert(cursor, "TCPFlags", 'flag', str(flag), count)

            for layers, count in data.get('protocol_layers', {}).items():
                sequence = ' -> '.join(layers)
                self.update_or_insert(cursor, "LayerSequence", 'sequence', sequence, count)
        # for protocol, count in data.get('protocols', {}).items():
        #     cursor.execute("INSERT INTO ProtocolUsage (protocol, count) VALUES (?, ?)", (protocol, count))
        # for ip, count in data.get('ip_src', {}).items():
        #     cursor.execute("INSERT INTO IPStats (ip_address, count, type) VALUES (?, ?, 'source')", (ip, count))
        # for ip, count in data.get('ip_dst', {}).items():
        #     cursor.execute("INSERT INTO IPStats (ip_address, count, type) VALUES (?, ?, 'destination')", (ip, count))
        # for flag, count in data.get('tcp_flags', {}).items():
        #     cursor.execute("INSERT INTO TCPFlags (flag, count) VALUES (?, ?)", (str(flag), count))
        # for layers, count in data.get('protocol_layers', {}).items():
        #     sequence = ' -> '.join(layers)
        #     cursor.execute("INSERT INTO LayerSequence (sequence, count) VALUES (?, ?)", (sequence, count))

            conn.commit()
        except Exception as e:
            self.error.emit(str(e))
        finally:
            conn.close()

    def update_or_insert(self, cursor, table, column_name, value, count, type=None):
        # if type:
        #     cursor.execute(f"SELECT id, count FROM {table} WHERE {column_name} = ? AND type = ?", (value, type))
        # else:
        #     cursor.execute(f"SELECT id, count FROM {table} WHERE {column_name} = ?", (value,))
        # row = cursor.fetchone()
        # if row:
        #     new_count = row[1] + count
        #     cursor.execute(f"UPDATE {table} SET count = ? WHERE id = ?", (new_count, row[0]))
        # else:
        #     if type:
        #         cursor.execute(f"INSERT INTO {table} ({column_name}, type, count) VALUES (?, ?, ?)", (value, type, count))
        #     else:
                # cursor.execute(f"INSERT INTO {table} ({column_name}, count) VALUES (?, ?)", (value, count))
        # if isinstance(value, bytes):
        #     value = value.decode('utf-8')  # 假设编码为 UTF-8
        
        try:
            value = str(value)  # 确保所有值都转换为字符串，避免类型问题
            if type:
                cursor.execute(f"SELECT id, count FROM {table} WHERE {column_name} = ? AND type = ?", (value, type))
            else:
                cursor.execute(f"SELECT id, count FROM {table} WHERE {column_name} = ?", (value,))
            row = cursor.fetchone()
            if row:
                new_count = row[1] + count
                cursor.execute(f"UPDATE {table} SET count = ? WHERE id = ?", (new_count, row[0]))
            else:
                if type:
                    cursor.execute(f"INSERT INTO {table} ({column_name}, type, count) VALUES (?, ?, ?)", (value, type, count))
                else:
                    cursor.execute(f"INSERT INTO {table} ({column_name}, count) VALUES (?, ?)", (value, count))
            print(f"Data inserted/updated in {table} for {value} with count {count}")
        except Exception as e:
            self.error.emit(f"Failed to update/insert in {table} with value {value}: {str(e)}")
            # print(f"Failed to execute query with value: {value}")
            # print(f"Error: {e}")
            # raise


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

    def startMonitoring(self):
        interface = self.interfaceEdit.currentText()
        if not interface:
            QMessageBox.warning(self, "Warning", "请选择一个网络接口。")
            return
        if not hasattr(self, 'worker') or not self.worker.isRunning():
            self.worker = Worker(interface)
            self.worker.all_data_captured.connect(self.updateUI)  # 处理所有数据的更新
            self.worker.error.connect(lambda e: QMessageBox.critical(self, "Error", f"Error: {e}"))
            self.worker.start()

    def stopMonitoring(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.stop()


    def __addmenubar(self):
        menubar = QMenuBar()
        self.layout = QGridLayout()
        self.layout.addWidget(menubar, 0, 0)
        actionFun = menubar.addMenu("功能")
        startAction = QAction("开始监听", self)
        startAction.triggered.connect(self.startMonitoring)
        actionFun.addAction(startAction)
        stopAction = QAction("停止监听", self)
        stopAction.triggered.connect(self.stopMonitoring)
        actionFun.addAction(stopAction)
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
        # self.interfaceEdit = QLineEdit()
        # self.interfaceEdit.setPlaceholderText("例如：eth0")
        self.interfaceEdit = QComboBox()
        self.interfaceEdit.addItems(self.get_network_adapter_descriptions())
        self.startButton = QPushButton("开始监控")
        self.startButton.clicked.connect(self.startMonitoring)
        self.hboxURL.addWidget(label)
        self.hboxURL.addWidget(self.interfaceEdit)
        self.hboxURL.addWidget(self.startButton)

    def get_network_adapter_descriptions(self):
        """使用 WMI 库获取网络接口描述"""
        c = wmi.WMI()
        adapters = c.Win32_NetworkAdapterConfiguration(IPEnabled=True)
        return [adapter.Description for adapter in adapters]

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
        interface = self.interfaceEdit.currentText()
        if not interface:
            QMessageBox.warning(self, "Warning", "请先输入网络接口名称")
            return
        self.worker = Worker(interface)
        self.worker.finished.connect(self.updateUI)
        self.worker.start()

    def updateUI(self, results):
        # 清空当前表格内容
        self.resultBox.setRowCount(0)
        self.resultBox.setRowCount(len(results))
        # 将数据填充到表格中
        for row_index, (category, data, description) in enumerate(results):
            self.resultBox.setItem(row_index, 0, QTableWidgetItem(str(category)))
            self.resultBox.setItem(row_index, 1, QTableWidgetItem(str(data)))
            self.resultBox.setItem(row_index, 2, QTableWidgetItem(str(description)))
        self.resultBox.resizeColumnsToContents()  # 调整列宽以适应内容
        QMessageBox.information(self, "分析完成", "数据分析已完成，并已更新至表格。")    

    def analyzeProtocolUsage(self):
        df = load_protocol_usage()
        results = analyze_protocol_usage(df)
        formatted_text = format_analysis_results("协议使用", results)  # 格式化输出
        self.displayResults(formatted_text)

    # def analyzeIPStats(self):
    #     df = load_ip_stats()
    #     src_counts, dst_counts = analyze_ip_stats(df)
    #     formatted_src = format_analysis_results("源 IP 统计", src_counts)
    #     formatted_dst = format_analysis_results("目标 IP 统计", dst_counts)
    #     combined_results = formatted_src + "\n" + formatted_dst  # 将结果合并，如果需要分别显示也可以分开处理
    #     self.displayResults(combined_results)
    #     # self.displayResults(src_counts)
    #     # self.displayResults(dst_counts)
    def analyzeIPStats(self):
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address, SUM(count), type FROM IPStats GROUP BY ip_address, type")
        rows = cursor.fetchall()
        src_counts = {}
        dst_counts = {}
        for ip_address, count, type in rows:
            if type == 'source':
                src_counts[ip_address] = count
            elif type == 'destination':
                dst_counts[ip_address] = count
        formatted_src = format_analysis_results("源 IP 统计", src_counts)
        formatted_dst = format_analysis_results("目标 IP 统计", dst_counts)
        combined_results = formatted_src + "\n" + formatted_dst
        self.displayResults(combined_results)
        conn.close()

    def analyzeTCPFlags(self):
        df = load_tcp_flags()
        results = analyze_tcp_flags(df)
        formatted_text = format_analysis_results("TCP 标志统计", results)
        self.displayResults(formatted_text)
        # self.displayResults(results)

    def analyzeLayerSequence(self):
        df = load_layer_sequence()
        results = df.set_index('sequence')['count']  # 这样会得到一个pd.Series，索引是序列，值是计数
        print("检查提取的数据:")
        print(results)
        # results = analyze_layer_sequence(df)
        formatted_text = format_analysis_results("层序列分析", results)
        print(formatted_text)
        self.displayResults(formatted_text)
        # self.displayResults(results)

    def displayResults(self, results):
        # 清除当前文本框内容
        self.textResults.clear()
        # self.textResults.setPlainText(text)  # 显示新结果
        if isinstance(results, pd.DataFrame):
            # 将DataFrame转换为字符串形式显示
            text_data = results.to_string(index=False)
            self.textResults.setPlainText(text_data)  # 使用setPlainText来显示纯文本
        elif isinstance(results, str):
            # 如果已经是字符串，直接显示
            self.textResults.setPlainText(results)
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

# def add_test_data():
#     conn = sqlite3.connect('network_data.db')
#     cursor = conn.cursor()
#     cursor.execute("INSERT INTO IPStats (ip_address, type, count) VALUES ('192.168.1.1', 'source', 5)")
#     cursor.execute("INSERT INTO IPStats (ip_address, type, count) VALUES ('192.168.1.2', 'destination', 3)")
#     conn.commit()
#     conn.close()

if __name__ == '__main__':
    # correct_path = "D:\\文档\\毕业论文（设计）表格\\item\\venv\\Lib\\site-packages\\PyQt5\\Qt5\\plugins"
    # os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = correct_path
    
    # add_test_data()  # 添加测试数据
    
    app = QApplication(sys.argv)
    ex = WindowsView()
    ex.show()
    sys.exit(app.exec_())