from scapy.all import *
import tkinter as tk
from tkinter import messagebox
import socket
import os
import struct
from ctypes import *
import time
import datetime as dt

my_packages = []

def start():
    var2 = packageCnt.get()
    try:
        if type(eval(var2)) is not int:
            tk.messagebox.showerror(title='错误', message='抓包数量必须为整数！')
            return
    except:
        tk.messagebox.showerror(title='错误', message='抓包数量必须为整数！')
        return
    try:
        packages = sniff( count=eval(var2))
    except:
        tk.messagebox.showerror(title='错误', message='网卡不存在')
        return
    for i in range(eval(var2)):
        t.insert("end ", "------------------------------------- {} --------------------------------------\n".format(i+1))
        t.insert("end", packages[i].show(1))
        my_packages.append(packages[i])


class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_ulong),
        ('dst', c_ulong),
        ("src_port", c_ushort),
        ("dst_port", c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)




def model2():


    def start():
        var = e.get()
        socket_protocol = socket.IPPROTO_IP

        global sniffer

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        try:
            sniffer.bind((var, 0))
        except:
            tk.messagebox.showerror(title='error!', message='无法连接')

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        show_th = threading.Thread(target=show)
        show_th.setDaemon(True)
        show_th.start()

    def show():
        window2.title('正在抓包...')  # 更改界面标题
        while True:
            # 读取数据包
            raw_buffer = sniffer.recvfrom(65535)[0]  # 获取数据包，接收最大字节数为65565
            # 读取前20字节
            ip_header = IP(raw_buffer[0:24])
            # 输出协议和双方通信的IP地址
            now_time = dt.datetime.now().strftime('%T')  # 获取系统当前时间
            result = '协议: ' + str(ip_header.protocol) + ' ' + str(ip_header.src_address) + ' : ' + str(
                ip_header.src_port) + ' -> ' + str(ip_header.dst_address) + ' : ' + str(
                ip_header.dst_port) + '  size:' + str(ip_header.len) + ' 时间:' + str(now_time) + '\n'  # 设置输出的字符串
            t.insert('end', result)  # 将每条输出插入到界面
            time.sleep(0.1)


    def stop():
        window2.title('抓包已停止')
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()

    window2 = tk.Tk()
    window2["bg"] = "blue"
    window2.geometry('800x600')
    # 本地监听
    l = tk.Label(window2, text='网卡ip：')
    l.place(x=150, y=65)
    e = tk.Entry(window2, show=None)
    e.place(x=250, y=65)
    var = tk.StringVar()
    b_1 = tk.Button(window2, text='开始抓包', width=15, height=2, command=start).place(x=450, y=20)
    b_2 = tk.Button(window2, text='停止抓包', width=15, height=2, command=stop).place(x=450, y=80)
    t = tk.Text(window2, width=100)
    t.place(x=50, y=200)
    window2.mainloop()


window = tk.Tk()
window.geometry('1442x1150')
window["bg"] = "yellow"


tip2 = tk.Label(window, text='抓包数量：',bg="lightblue")
tip2.place(x=20,y=30)
packageCnt = tk.Entry(window, show=None)
packageCnt.place(x=100, y=30)



b_1 = tk.Button(window, text='开始抓包', width=15, height=2,command=start).place(x=25, y=100)

b_4 = tk.Button(window, text='持续监听', width=15, height=2,command=model2).place(x= 25,y=150)


yscrollbar = tk.Scrollbar(window)
yscrollbar.pack(side="right", fill="y")
xscrollbar = tk.Scrollbar(window,orient="horizontal")
xscrollbar.pack(side="bottom", fill="x")


t = tk.Text(window, wrap="none", height=80, width=160,foreground='red',yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
t.pack(expand='yes',fill='both')
t.place(x=260, y=20)
yscrollbar.config(command=t.yview)
xscrollbar.config(command=t.xview)

window.mainloop()
