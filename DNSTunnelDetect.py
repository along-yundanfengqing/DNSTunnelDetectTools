#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
DNS隧道通信检测工具
作者:陈然
版本：V1.0.1
联系：WeChat-Number -> cr1914518025
"""


#脚本信息配置:
_author  = "隐私保护"
_nicky   = "挖洞的土拨鼠"
_version = "v1.0.1"
_version_string = """\033[0;32m
            DNS隧道通信检测工具
            作者:陈然
            版本：V1.0.1
            联系：WeChat-Number -> cr1914518025
            操作系统：支持Linux、Unix、MacOS X、Windows
\033[0m"""

#引入依赖的库文见、包
import os
import sys
import time
import pcap
import dpkt
import urllib
import logging
import platform
import datetime
from optparse import OptionParser


#配置全局设置
reload(sys)
sys.setdefaultencoding("utf-8")
logging.basicConfig(filename="./dnstunneldetect.running.log",level=logging.INFO,filemode='a',format='%(asctime)s-%(levelname)s:%(message)s')


#定义全局函数
def dns_request_analyst(string,sport):
    """解DNS请求报文"""
    logging.info("分析报文请求")
    dnsdata = dpkt.dns.DNS(string)
    ret = repr(string)#.replace("\\x03",".").replace("\\x05",".").replace("\\x12",".")
    domain = str(ret[41:-21])[3:]#.replace("")
    rtype = ret.replace("\\x","")[-9:][0:4]
    #print type(domain)
    domain = domain.replace("\\x",".")
    domainlist = domain.split(".")
    domain = domainlist[0]+"."
    for dstr in domainlist[1:]:
        dstr = dstr[2:]
        domain += str(dstr)+"."
    domain = domain[0:-1]
    score = float(len(domain) - 52) * 0.5
    for item in list(str(domain)):
        if item not in list("01234567890-abcdefghijklmnopqrstuvwxyz."):
            score *= 2
            break
    if rtype == '0010':
        pass
    else:
        score = score * 0.4
    pid = None
    if platform.platform().lower().find("windows") >= 0:
        pid = os.popen("netstat -ano | findstr %s"%sport).read().split("\n")[0].split(" ")[-1]
    elif platform.platform().lower().find("linux") >= 0:
        pid = os.popen("netstat -anop | grep %s | awk '{print $7}'"%sport).read().split("/")[0]
    elif platform.platform().lower().find("darwin") >= 0:
        pid = os.popen("lsof -nP | grep :%s | awk '{print $2}'"%sport).read().split("\n")
        for i in pid:
            if i != "['']":
                pid = i
                break
    else:
        pass
    flag = False
    if score > 4
    return True,domain,score,pid

#定义DNS嗅探解析报文获取类
class Packet_Sniffer_Filter:
    """嗅探并过滤报文"""
    def __init__(self,iterfacename):
        """创建报文嗅探器"""
        logging.info("创建嗅探器")
        self.name = iterfacename#本机的嗅探网卡名称
        self.sniffer = pcap.pcap(name=self.name,immediate=True)#设置嗅探器嗅探指定网卡
        self.sniffer.setfilter("udp port 53")#初步过滤
    def run(self):
        logging.info("嗅探器线程开始运行")
        for packet_time,packet_data in self.sniffer:
            packet = dpkt.ethernet.Ethernet(packet_data)#使用dpkt解pcap格式报文
            dip = tuple(map(ord,list(packet.data.dst)))#获取目的IP地址
            dip = str(dip).replace(",",".").replace(" ","")[1:-1]
            sport = packet.data.data.sport
            dport = packet.data.data.dport
            if dport != 53:
                continue
            result_flag,domain,score,processid = dns_request_analyst(packet.data.data.data,sport)#加入待分析队列
            if result_flag:
                print """\033[0;31m
                [*] 疑似DNS隧道通信
                    [-] 通信域名: %s
                    [-] 来源端口: %s
                    [-] 危险评分: %s
                    [-] 对端地址: %s
                    [-] 本地进程: %s
                \033[0m"""%(domain[3:],sport,score,dip,processid)



if __name__ == "__main__":
    logging.info("程序启动")
    parser = OptionParser()
    parser.add_option("-i","--ifname",dest="name",help="Interface Name!")
    parser.add_option("-v","--version",dest="version",action="store_true",help="Show Version!")
    parser.add_option("-d","--docs",dest="docs",action="store_true",help="Show Documents!")
    parser.add_option("-r","--requirments",dest="reqr",action="store_true",help="Show Requriments!")
    (options, arges) = parser.parse_args()
    if options.version:
        print _version_string
        exit(0)
    if options.docs:
        print """\033[0;32m
            使用手册--使用于V1.0.1版本
            [1] python DNSTunnelDetect.py -i eth1
        \033[0"""
        exit(0)
    if options.reqr:
        print """\033[0;32m
            [+] sudo pip install pypcap
            [+] sudo pip install dpkt
        \033[0"""
        exit(0)
    if options.name in ["",None]:
        logging.info("程序缺乏网卡参数，退出运行!")
        print "\033[0;31m[-] 请指定网卡\033[0m"
        exit(0)
    logging.info("程序初始化")
    PacketSniffer = Packet_Sniffer_Filter(options.name)
    PacketSniffer.run()
