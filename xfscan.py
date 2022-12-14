# -*- coding: utf-8 -*-
# Author: zhanglong@μredteam, yankai@μredteam

# from asyncore import file_dispatcher
import os
import shutil
from sys import stderr, stdout
import time
import asyncio
from aiomultiprocess import Pool
import logging

from fscanOutput2Csv import OpenFile, OpenPort


'''
===== Global Variable Start =====
'''

ip_1_list = [
    "10.10.0.1/19",
    "10.20.0.1/25"
]

ip_2_list = [
    "10.3.0.1/24",
    "10.3.2.1/24",
    "10.3.4.1/24",
    "10.3.11.1/24",
]

# all ip segments that ready to scan
ip_list = ip_1_list + ip_2_list


# fscan
basicPath = os.getcwd()
fs_exe = basicPath+"\\fscan.exe"

# scan result path
scanResult_path = basicPath + "\\scanResult"
# every fscan process output the temp scan result to this directory
scanResult_tmp_path = scanResult_path + "\\tmp"




banner = r"""
__  __ ____  ____  ____   ____   __  _ 
\ \/ /| ===|(_ (_`/ (__` / () \ |  \| |
/_/\_\|__| .__)__)\____)/__/\__\|_|\__|

        zhanglong@μredteam, yankai@μredteam


Built upon fscan/fscanoutput project.
        shadow1ng@fscan [https://github.com/shadow1ng/fscan]
        ZororoZ@fscanoutput [https://github.com/ZororoZ/fscanOutput]

"""

"""
===== Global Variable End =====
"""



def mkdir(path):
    """
    input:
        path: directory name

    func: make directory.

    output: 
    """

    folder_exist = os.path.exists(path)

    if not folder_exist:
        os.makedirs(path)
        print(f"[+] Now we get folder: {path}")

    return


def init_dir():
    """
    input:

    func: invoke mkdir() to init directories which are defined in "styleList".

    output: 
    """

    styleList = [
        "\\Bug_ExpList",
        "\\Bug_PocList",
        "\\Finger",
        "\\OpenPort",
        "\\OsList",
        "\\Title",
        "\\WeakPasswd",
        "\\ScanLogs"
    ]

    mkdir(scanResult_path)
    mkdir(scanResult_tmp_path)

    for i in styleList:
        mkdir(scanResult_path + i)

    return


def handle_ip4Scan(ips):
    """
    input:
        ips: ip lists that contain various netmask.

    func: Process the incoming IP lists. If the mask is less than 24, it will be divided into multiple C segments for scanning. If it is equal to 24, it will be scanned directly.

    output:
        ip_to_scan: an ip list that all netmasks are /24.
    """

    ip_to_scan = []

    for i in ips:

        netmask = int(i.split('/')[1])

        if netmask < 24:

            ip_prefix = f"{i.split('.')[0]}.{i.split('.')[1]}"
            ip_var = int(i.split('.')[2])
            # print(ip_prefix)

            c_num = pow(2, (32 - netmask))//256
            for a in range(0, c_num):
                # get new IP/24
                ip_to_scan.append(f"{ip_prefix}.{ip_var + a}.1/24")
                # print(f"{ip_prefix}.{ip_var + a}.1/24")

        elif netmask > 24:
            ip_to_scan.append(i)
            # print("[+] it can scan directly")

        else:
            ip_to_scan.append(i)
            # print("[+] it is normal")

    print(
        f"[+] Now we get \033[31;1m{len(ip_to_scan)}\033[0m network segments to scan.")
    
    
    # print(ip_to_scan)
    # for i in ip_to_scan:
    #     print(i)

    return ip_to_scan


async def run_fs(ips):
    """
    input:
        ips: ip lists that netmasks all are /24.

    func: main function that invoke fscan, using asyncio.

    output:
    """

    ips = ips.strip()
    # print(ips)

    
    if ips == "10.75.0.1/24":
        print(f"[!] Damn, it is printer ip segments: {ips} , we need ignore it...")
    else:
    
        # res = asyncio.subprocess.create_subprocess_exec()

        # you can customize the command here.
        # scan_cmd = "ping" + f" -w 1 -n 1 {ips.replace('/24','')} | findstr /i 'ttl='"

        scan_cmd = fs_exe + f" -np -nobr -h {ips} -o {scanResult_tmp_path}\\{ips.split('/')[0].replace('.','_')}_24.txt"

        # scan_cmd = fs_exe + \
        #     f" -np -nopoc -nobr -p 22,135,445,5985,80,443,8443,8080,3389 -h {ips} -o {scanResult_tmp_path}\\{ips.split('/')[0].replace('.','_')}_24.txt"

        
        scan_start_time = time.time()
        proc = await asyncio.subprocess.create_subprocess_shell(
            scan_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if not stdout:
            print(f"[-] No stdout, check the fscan process, task_id is {ips}")
            return

        if stdout:
            
            try:
            
                resultList = []
                # print(f"[!] Now {ips}")
                singleResult = str(stdout.decode())

                for i in singleResult.split("\n"):
                    resultList.append(i)

                # print(f"[+] Task {ips} is completely: {resultList[-3]}")
                print(f"{resultList[-1]} ==> \033[31;1m{ips}\033[0m ==> Count: \033[31;1m{resultList[-2]}\033[0m")

                # logging.info(f"{resultList[-1]} ==> {ips} ==> Count: {resultList[-2]}")
                loginfo = f"{resultList[-1]} ==> {ips} ==> Count: {resultList[-2]}"
                return loginfo
                
                
                # pass
                # print(str(stdout))

            # except Exception as e:
            #     print(e)
            
            except UnicodeDecodeError as u:
                scan_end_time = time.time()
                scan_costs_time = scan_end_time - scan_start_time
                
                # print(f"[-] Decoding error on \033[31;1m{ips}\033[0m, but scan works and it costs \033[31;1m{scan_costs_time}\033[0m")

                print(f"[*] 扫描结束,耗时: {round(scan_costs_time, 7)}s ==> \033[31;1m{ips}\033[0m ==> Count: Decode error!")

                # logging.info(f"[*] 扫描结束,耗时: {round(scan_costs_time, 7)}s ==> {ips} ==> Count: Decode error!")
                loginfo2 = f"[*] 扫描结束,耗时: {round(scan_costs_time, 7)}s ==> {ips} ==> Count: Decode error!"
                return loginfo2
                
                # print(u)
                pass

        if stderr:
            pass
        

        # scan_end_time = time.time()
        # scan_costs_time = scan_end_time - scan_start_time
        
        # print(f"[+] Task \033[31;1m{ips}\033[0m is completely, it costs \033[31;1m{scan_costs_time}s\033[0m")

    return



def merge_result2csv():
    """
    input:

    func: merge all result files in tmp

    output:
    """
    

    txtName = f"fscan_result_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}.txt"
    
    txtList = os.listdir(scanResult_tmp_path)


    with open(f"{scanResult_path}\\{txtName}", 'w', encoding='utf-8-sig', errors='ignore') as f:

        for i in txtList:
            txtPath = f"{scanResult_tmp_path}\\{i}"
            for line in open(txtPath, encoding='utf-8-sig', errors='ignore'):
                f.writelines(line)
    
    # os.system(
    #     f"python {os.getcwd()}\\fscanOutput2Csv.py {scanResult_path}\\{txtName}")

    #os.remove(f"{scanResult_path}\\{txtName}")
    #shutil.rmtree(scanResult_tmp_path)

    return txtName


def outputCsv(csv_savepath, scan_result):
    """
    input:
        csv_savepath: the directory that output the csv report.
        scan_result: scan result that merge all ip segments.

    func: output csv scan report.

    output:
    """
    
    import fscanOutput2Csv

    list1, str1 = fscanOutput2Csv.OpenFile(csv_savepath, scan_result)
    filepath = csv_savepath

    fscanOutput2Csv.OpenPort(list1, filepath)
    fscanOutput2Csv.Bug_ExpList(list1, filepath)
    fscanOutput2Csv.Bug_PocList(list1, filepath)
    fscanOutput2Csv.OsList(list1, filepath)
    fscanOutput2Csv.GetTitle(list1, filepath)
    fscanOutput2Csv.GetPassword(list1, filepath)
    fscanOutput2Csv.FingerOut(list1, filepath)

    print(f"[+] Now we get final scan result, check it in \033[31;1m{scanResult_path}\033[0m.")

    return


async def entry(ips):
    
    async with Pool(os.cpu_count()) as pool:

        result = await pool.map(run_fs, ips)

    if result:
        for i in result:
            logging.info(i)
        
        # print("[+] Scan complete.")
        return result



if __name__ == "__main__":

    print(banner)

    # init the directory
    init_dir()

    # logging
    if not os.path.exists(f"{scanResult_path}\\ScanLogs\\info.log"):
        fo = open(f"{scanResult_path}\\ScanLogs\\info.log", "a")
        fo.close()

    logging.basicConfig(
        level = logging.INFO,
        filename = f"{scanResult_path}\\ScanLogs\\info.log",
        filemode = 'a',
        format = '%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'
    )

    logging.info("[+] Now start to scan!")

    # get ip lists that netmask is /24
    iplist = handle_ip4Scan(ip_list)

    # 生成的 iplist_2 是一个嵌套二维数组，里面有 8 个元素，每个元素含 32 个 C 段
    step = 32
    iplist_2 = [iplist[i:i+step] for i in range(0, len(iplist),step)]

    # print(iplist_2[0])
    # print(len(iplist_2[0]))

    # print(os.cpu_count())

    start_time = time.time()

    # task_1 = asyncio.ensure_future(entry(iplist))
    
    for ip_segments_2_scan in iplist_2:
        print(f"[+] Now scan {ip_segments_2_scan}")
        print(f"[+] the segments length is {len(ip_segments_2_scan)} !!!!")
        task_1 = asyncio.ensure_future(entry(ip_segments_2_scan))
        loop = asyncio.get_event_loop()

        loop.run_until_complete(task_1)

    # output the result.
    print("[+] Now output the csv report...")
    logging.info("[+] Now output the csv report...")
    outputCsv(scanResult_path, merge_result2csv())

    end_time = time.time()
    print("[+] Task complete.")
    print(f"[+] All tasks cost \033[31;1m{end_time - start_time}s\033[0m.")
    print(f"[+] It costs \033[31;1m{end_time - start_time}s\033[0m!")
    logging.info(f"[+] All task complete. It costs {end_time - start_time}s!")
