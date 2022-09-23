import re
import time
import openpyxl
import sys
import os
import os.path
import csv
from openpyxl.styles import Font


def OpenFile(input_filepath, input_filename):
    
    # filepath, filename = getInput()
    filepath = input_filepath
    filename = input_filename

    datalist = []
    datastr = ''

    with open(f"{filepath}\\{filename}", encoding='utf-8-sig') as f:
        for i in f.readlines():
            datalist.append(i.strip())

    with open(f"{filepath}\\{filename}", encoding='utf-8-sig') as f:
        datastr = f.read()

    return datalist, datastr


#输出存活端口
def OpenPort(datalist, filepath):
    rows=[]
    for i in datalist:
        p = re.findall(r'^\d[^\s]+', i)
        if len(p) != 0:
            p1 = list(p)
            #print(p1)
            for u in p1:
                ip = re.findall(r"\d+\.\d+\.\d+\.\d+", u)
                port = u.replace(ip[0], '').strip(':')
                ip.append(port)
                rows.append(tuple(ip))    
    with open(filepath + "\\OpenPort\\" + f"fscan_OpenPort_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['ip','port']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)


#输出exp漏洞列表
def Bug_ExpList(datalist, filepath):
    rows=[]
    for i in datalist:
        p = re.findall(r"\[\+]\s\d+\.\d+\.\d+\.\d+.*", i)

        # print(p)

        if len(p) != 0:
            p1 = list(p)
            for u in p1:
                ip = re.findall(r"\d+\.\d+\.\d+\.\d+", u)
                bug = u.replace(ip[0], '').replace("[+]", "").replace('\t', '').strip()
                ip.append(bug)
                rows.append(ip)

    with open(filepath + "\\Bug_ExpList\\" + f"fscan_BugExpList_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['ip', 'bug_exp']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)


#输出poc漏洞列表
def Bug_PocList(datalist, filepath):
    rows=[]
    for i in datalist:
        p = re.findall(r"\[\+]\shttp[^\s].*", i)
        # print(p)

        if len(p) != 0:
            p1 = list(p)
            for u in p1:
                url = re.findall(r"http[^\s].*?\ ", u)
                bug = u.replace(url[0], '').replace("[+]", "").replace('\t', '').strip()
                url.append(bug)
                rows.append(url)
    with open(filepath + "\\Bug_PocList\\" + f"fscan_BugPocList_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['ip', 'bug_poc']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)   


#输出识别到的系统
def OsList(datalist, filepath):
    rows=[]
    replaceList = ["[*]", '\t', "\x01", '\x02']
    for t in datalist:
        p = re.findall(r"\[\*]\s\d+\.\d+\.\d+\.\d+.*", t)

        if len(p) != 0:
            p1 = list(p)

            for u in p1:
                ip = re.findall(r"\d+\.\d+\.\d+\.\d+", u)
                #删除无用字符
                for q in replaceList:
                    u = u.replace(q, "")

                ip.append(u.replace(ip[0], '').strip())
                rows.append(ip)
    with open(filepath + "\\OsList\\" + f"fscan_OsList_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['ip', 'os']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)


#输出title
def GetTitle(datalist, filepath):
    rows=[]
    for i in datalist:
        p = re.findall(r'\[\*]\sWebTitle.*', i)

        if len(p) != 0:
            p1 = list(p)
            for u in p1:
                url = re.findall(r"http[^\s].*?\ ", u)
                code = re.findall(r'(?<=code:)[^\s].*?\ ', u)
                len1 = re.findall(r'(?<=len:)[^\s].*?\ +', u)
                title = re.findall(r'(?<=title:).*', u)
                # print(title)
                url.append(str(code).strip("['").strip("']'"))
                url.append(str(len1).strip("['").strip("']'"))
                url.append(str(title).strip("['").strip("']'"))
                #print(url)
                rows.append(tuple(url))    
    with open(filepath + "\\Title\\" + f"fscan_Title_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['url', 'code', 'len', 'title']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)    


#输出弱口令
def GetPassword(datalist, filepath):
    rows=[]
    for i in datalist:
        p = re.findall(r'((ftp|mysql|mssql|SMB|RDP|Postgres|SSH|Mongodb|oracle|redis|Memcached)(:|\s).*)', i, re.I)

        if len(p) != 0:
            p1 = list(p)
            passwd = p1[0][0]
            server = p1[0][1]
            # print(passwd)
            ip = re.findall(r"\d+\.\d+\.\d+\.\d+\:\d+", passwd)
            ip.append(server)
            ip.append(passwd)
            rows.append(ip)
    with open(filepath + "\\Weakpasswd\\" + f"fscan_WeakPasswd_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['ip', 'server','passwd']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)
    
#输出指纹信息
def FingerOut(datalist, filepath):
    rows=[]
    for i in datalist:
        p = re.findall(r'.*InfoScan.*', i)
        # print(p)

        if len(p) != 0:
            p1 = list(p)
            for u in p1:
                url = re.findall(r'http[^\s]+', u)
                finger = u.split(url[0])[-1].strip()
                url.append(finger)
                # ws4.append(url)
                rows.append(tuple(url))
    with open(filepath + "\\Finger\\" + f"fscan_Finger_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.csv",'w', newline='') as csvfile:
        fieldnames = ['url', 'finger']
        writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
        writer.writeheader()
        writer = csv.writer(csvfile)
        writer.writerows(rows)
