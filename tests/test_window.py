import wx
from capture import capture_packets
from analyze import analyze_packets
from traffic_monitor import TrafficMonitor

class MainFrame(wx.Frame):
    def __init__(self, parent, title):
        super(MainFrame, self).__init__(parent, title=title, size=(800,600))
        self.interface = 'Intel(R) Ethernet Connection (12) I219-V'  # 默认接口
        self.init_ui()
        self.monitor = TrafficMonitor(window_size=10, threshold=50)  # 初始化监控类
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.update_data, self.timer)
        self.timer.Start(1000)  # 设置定时器每1000毫秒触发一次
        self.Centre()
        self.Show()

    def init_ui(self):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.createMenuBar()

        self.data_label = wx.StaticText(panel, label="Waiting for data...", style=wx.ALIGN_CENTER)
        vbox.Add(self.data_label, proportion=1, flag=wx.EXPAND|wx.ALL, border=10)
        
        self.status_label = wx.StaticText(panel, label="Monitoring...", style=wx.ALIGN_CENTER)
        vbox.Add(self.status_label, proportion=1, flag=wx.EXPAND|wx.ALL, border=10)
        
        self.log_text_ctrl = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(self.log_text_ctrl, proportion=3, flag=wx.EXPAND|wx.ALL, border=10)

        self.toggle_button = wx.Button(panel, label="Stop Monitoring")
        self.toggle_button.Bind(wx.EVT_BUTTON, self.on_toggle_monitoring)
        vbox.Add(self.toggle_button, proportion=0, flag=wx.EXPAND|wx.ALL, border=10)
        
        panel.SetSizer(vbox)

    def createMenuBar(self):
        menubar = wx.MenuBar()
        functionMenu = wx.Menu()
        functionMenu.Append(wx.ID_EXIT, 'Exit', 'Exit application')
        menubar.Append(functionMenu, 'Function')
        self.SetMenuBar(menubar)
        self.Bind(wx.EVT_MENU, self.onQuit, id=wx.ID_EXIT)

    def onQuit(self, event):
        self.Close()

    def update_data(self, event):
        if not self.timer.IsRunning():
            return  # 如果定时器停止，不执行任何操作
        try:
            packets = capture_packets(interface=self.interface, count=10)
            if packets:
                stats = analyze_packets(packets)  # 分析数据包
                self.data_label.SetLabel(f"Packet Stats: {stats}")
                
                # 更新监控器状态
                for packet in packets:
                    self.monitor.process_packet(packet)
                    self.log_text_ctrl.AppendText(str(packet) + '\n')  # 显示详细的包信息
                if self.monitor.detect_anomaly():
                    self.status_label.SetLabel("Anomaly Detected!")
                else:
                    self.status_label.SetLabel("Monitoring...")
            else:
                self.data_label.SetLabel("No packets captured")
        except Exception as e:
            self.data_label.SetLabel("Error capturing packets")
            self.status_label.SetLabel("Error: " + str(e))

    def on_toggle_monitoring(self, event):
        if self.timer.IsRunning():
            self.timer.Stop()
            self.toggle_button.SetLabel("Start Monitoring")
            self.status_label.SetLabel("Monitoring stopped.")
            self.monitor.reset()
        else:
            self.timer.Start(1000)
            self.toggle_button.SetLabel("Stop Monitoring")
            self.status_label.SetLabel("Monitoring...")

class App(wx.App):
    def OnInit(self):
        frame = MainFrame(None, title="Network Monitor")
        frame.Show()
        return True

if __name__ == '__main__':
    app = App()
    app.MainLoop()
