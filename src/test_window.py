import wx
from capture import capture_packets
from analyze import analyze_packets
from traffic_monitor import TrafficMonitor

class MainFrame(wx.Frame):
    def __init__(self, parent, title):
        super(MainFrame, self).__init__(parent, title=title, size=(800,600))
        self.interface = 'Intel(R) Ethernet Connection (12) I219-V'  # 默认网络接口
        self.init_ui()
        self.monitor = TrafficMonitor(window_size=10, threshold=50)  # 初始化监控类
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.update_data, self.timer)
        self.timer.Start(1000)  # 设置定时器每1000毫秒触发一次
        self.Centre()
        self.Show()

    def init_ui(self):
        self.panel = wx.Panel(self)
        self.vbox = wx.BoxSizer(wx.VERTICAL)

        self.createMenuBar()
        self.setupStatusBox()
        self.setupControlBox()

        self.panel.SetSizer(self.vbox)

    def createMenuBar(self):
        menubar = wx.MenuBar()
        functionMenu = wx.Menu()
        startItem = functionMenu.Append(wx.ID_ANY, '开始监控', '开始网络流量监控')
        stopItem = functionMenu.Append(wx.ID_ANY, '停止监控', '停止网络流量监控')
        functionMenu.AppendSeparator()
        exitItem = functionMenu.Append(wx.ID_EXIT, '退出', '退出应用程序')
        
        menubar.Append(functionMenu, '功能')
        self.SetMenuBar(menubar)
        
        self.Bind(wx.EVT_MENU, self.onToggleMonitoring, startItem)
        self.Bind(wx.EVT_MENU, self.onToggleMonitoring, stopItem)
        self.Bind(wx.EVT_MENU, self.onQuit, exitItem)

    def setupStatusBox(self):
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.status_label = wx.StaticText(self.panel, label="等待数据...", style=wx.ALIGN_CENTER)
        hbox.Add(self.status_label, proportion=1, flag=wx.EXPAND|wx.ALL, border=10)
        self.vbox.Add(hbox, proportion=0, flag=wx.EXPAND|wx.ALL, border=10)

    def setupControlBox(self):
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.log_text_ctrl = wx.TextCtrl(self.panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        hbox.Add(self.log_text_ctrl, proportion=1, flag=wx.EXPAND|wx.ALL, border=10)
        self.vbox.Add(hbox, proportion=1, flag=wx.EXPAND|wx.ALL, border=10)

    def update_data(self, event):
        if not self.timer.IsRunning():
            return  # 如果定时器停止，不执行任何操作
        packets = capture_packets(interface=self.interface, count=10)
        if packets:
            stats = analyze_packets(packets)
            self.log_text_ctrl.AppendText(f"捕获数据包: {stats}\n")
        else:
            self.log_text_ctrl.AppendText("未捕获到数据包。\n")

    def onToggleMonitoring(self, event):
        if self.timer.IsRunning():
            self.timer.Stop()
            self.status_label.SetLabel("监控已停止。")
        else:
            self.timer.Start(1000)
            self.status_label.SetLabel("监控中...")
        
    def onQuit(self, event):
        self.Close()

class App(wx.App):
    def OnInit(self):
        frame = MainFrame(None, title="Network Monitor")
        frame.Show()
        return True

if __name__ == '__main__':
    app = App()
    app.MainLoop()
