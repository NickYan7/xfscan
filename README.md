
```
__  __ ____  ____  ____   ____   __  _ 
\ \/ /| ===|(_ (_`/ (__` / () \ |  \| |
/_/\_\|__| .__)__)\____)/__/\__\|_|\__|
```

# xfscan
采用 Python 异步协程并发调用 fscan 扫描，测试扫描 38 个 C 段用时 5~7 分钟，网络吞吐量发送 10 Mbps 左右，输出 CSV 结果方便分析和快速打点。

基于以下项目开发：
```
fscan (https://github.com/shadow1ng/fscan)
fscanoutput (https://github.com/ZororoZ/fscanOutput)
```

## 代码主要逻辑

> 
    \_ 首次运行生成模块目录、fscan 扫描结果临时目录，如已生成则跳过；
    \_ 对各网段 IP 列表进行处理，汇总一个待扫描的 IP 列表（掩码全部为 /24）；
    \_ 异步协程并发扫描 C 段，保存每个 C 段的临时扫描结果；
    \_ 合并所有临时扫描结果为一个文件；
    \_ 处理得到 CSV 文件，放置在每个模块目录下，包含时间戳；
    \_ 删除 fscan 扫描临时结果目录；
    \_ ...

## Notice

修改全局变量 `ip_lists` 为待扫描的 IP 段，fscan 扫描命令可自定义变量 `scan_cmd` ，最后 `python3 xfscan.py` 运行。

## Update

1、加入 `logging` 库，将每次扫描的时间、对象均记录在 `\scanResult\ScanLog\info.log` 目录下；

2、对传入的 IP C 段做划分，由 `step` 变量控制，即每次并发扫描 n 个 C 段。