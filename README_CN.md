![QNAT.png](./pic/QNAT.png)

[English](https://github.com/Qihoo360/QNAT/blob/master/README.md) | [中文](https://github.com/Qihoo360/QNAT/blob/master/README_CN.md)

## 项目特色
`QNAT`是基于[DPVS](https://github.com/iqiyi/dpvs)和[DPDK](http://dpdk.org)项目创建一个高性能NAT（Network Address Translation，网络地址转换）项目,主要应用于IDC（数据中心）、中大型办公网出口等场景下，支持NAT44、流量透传、多地址池选择、限定单IP会话数、NAT会话记录等功能。同时我们还增加了命令行界面管理功能，让您能像管理网络设备一样对QNAT进行管理。

## 环境需求
* `Linux Kernel version >= 2.6.34 （需要支持支持UIO和HUGETLBFS）`
* `DPDK version = 17.05.2`
* `GCC version >= 4.8.5`

## 测试环境
* `Linux Distribution: CentOS 7.2`
* `Kernel: 3.10.0-327.36.3.el7.x86_64`
* `CPU: Intel(R) Xeon(R) CPU E5-2630 v2 @ 2.60GHz`
* `NIC: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)`
* `Memory: 64G with two NUMA node`
* `GCC: gcc version 4.8.5 20150623 (Red Hat 4.8.5-4)`
* `DPDK: dpdk-stable-17.05.2`

## 架构
![architecture.png](./pic/architecture.png)

## 安装/配置说明
+ ### 安装依赖包
```bash
$ yum install -y popt-devel.x86_64
$ yum install -y openssl-devel.x86_64
```
+ ### 获取DPDK
```bash
$ wget https://fast.dpdk.org/rel/dpdk-17.05.2.tar.xz
$ tar vxf dpdk-17.05.2.tar.xz
```
+ ### 安装/配置DPDK
```bash
$ cd {path-of-dpdk}
$ make config T=x86_64-native-linuxapp-gcc
$ make -j12
$ echo export RTE_SDK=$PWD >> ~/.bashrc
$ source ~/.bashrc
``` 
+ ### 配置DPDK hugepage
```bash
$ echo 12288 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
$ echo 12288 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
$ mkdir /mnt/huge
$ mount -t hugetlbfs nodev /mnt/huge
```
+ ### 绑定DPDK网卡驱动
```bash
$ modprobe uio
$ insmod build/kmod/igb_uio.ko
$ insmod build/kmod/rte_kni.ko

$ {path-of-dpdk}/usertools/dpdk-devbind.py -s  
#获取需要绑定至DPDK下网卡的uio号，假定将要使用的eth0为0000:84:00.0，eth1为0000:84:00.1

$ ifconfig eth0 down; ifconfig eth1 down
$ {path-of-dpdk}/usertools/dpdk-devbind.py -b igb_uio 0000:84:00.0
$ {path-of-dpdk}/usertools/dpdk-devbind.py -b igb_uio 0000:84:00.1
```
+ ### 获取QNAT
```bash
$ git clone https://github.com/Qihoo360/qnat.git
```
+ ### 安装QNAT
```bash
$ cd QNAT
$ make -j12 
$ make install
```
+ ### 配置QNAT
+ #### 通过命令行进行配置

 >*配置示例（假定服务器eth0配置IP为：10.10.10.3/27；eth1配置IP为：110.110.110.2/28；eth0为dpdk0，eth1为dpdk1）*
 ```bash
 $ qnatsh                                                          #启动qnat命令行工具
  ______    ______    ______          ______   _______    ______
 /      \  /      \  /      \        /      \ |       \  /      \
|  ######\|  ######\|  ######\      |  ######\| #######\|  ######\
 \##__| ##| ##___\##| ###\| ##      | ##  | ##| ##__/ ##| ##___\##
  |     ##| ##    \ | ####\ ##      | ##  | ##| ##    ## \##    \
 __\#####\| #######\| ##\##\##      | ##  | ##| #######  _\######\
|  \__| ##| ##__/ ##| ##_\####      | ##__/ ##| ##      |  \__| ##
 \##    ## \##    ## \##  \###       \##    ##| ##       \##    ##
  \######   \######   \######         \######  \##        \######

 nathost# ip nat start                                             #启动QNAT服务
 nathost# configure terminal                                       #进入配置节点
 nathost(config)# hostname nattest                                 #修改hostname
 nattest(config)#local ip 10.10.10.2/27                            #add ip for intranet
 nattest(config)#ip addr 10.10.10.3/27 dev dpdk0.kni               #add ip for dpdk0.kni
 nattest(config)#ip addr 110.110.110.2/28 dev dpdk1.kni            #add ip for dpdk1.kni
 nattest(config)#ip route 10.10.10.3/32 dev inside kni_host        #add route to kni device
 nattest(config)#ip route 110.110.110.2/32 dev outside kni_host    #add route to kni device
 nattest(config)#ip route 10.0.0.0/8 via 10.10.10.1 dev inside     #add route for back to intranet
 nattest(config)#ip route 0.0.0.0/0 via 110.110.110.1 dev outside  #add defaut route
 nattest(config)# ip nat pool default                              #创建默认nat地址池
 nattest(config-nat-pool)# member ip 110.110.110.5/28              #地址池地址需要与eth1地址处于相同网段
 nattest(config-nat-pool)# exit
 nattest(config)# ip nat source 10.0.0.0 10.255.255.255            #创建nat匹配规则
 nattest(config-nat-service)# dest pool default
 nattest(config-nat-service)# end
 nattest# write file                                               #保存配置
```

+ #### 通过配置文件进行配置
>*配置示例（假定服务器eth0配置IP为：10.10.10.3/27；eth1配置IP为：110.110.110.2/28；eth0为dpdk0，eth1为dpdk1）*
```bash
$ cat /etc/qnatcft.conf
local ip 10.10.10.2/27
ip addr 10.10.10.3/27 dev dpdk0.kni
ip addr 110.110.110.2/28 dev dpdk1.kni
ip route 10.10.10.3/32 dev inside kni_host
ip route 110.110.110.2/32 dev outside kni_host
ip route 10.0.0.0/8 via 10.10.10.1 dev inside
ip route 0.0.0.0/0 via 110.110.110.1 dev outside
hostname nattest
ip nat pool default
    member ip 110.110.110.5/28
exit
ip nat source 10.0.0.0 10.255.255.255
    dest pool default
exit

$ qnatsh                                                           #启动qnat命令行工具
  ______    ______    ______          ______   _______    ______
 /      \  /      \  /      \        /      \ |       \  /      \
|  ######\|  ######\|  ######\      |  ######\| #######\|  ######\
 \##__| ##| ##___\##| ###\| ##      | ##  | ##| ##__/ ##| ##___\##
  |     ##| ##    \ | ####\ ##      | ##  | ##| ##    ## \##    \
 __\#####\| #######\| ##\##\##      | ##  | ##| #######  _\######\
|  \__| ##| ##__/ ##| ##_\####      | ##__/ ##| ##      |  \__| ##
 \##    ## \##    ## \##  \###       \##    ##| ##       \##    ##
  \######   \######   \######         \######  \##        \######

nathost# ip nat start                                              #启动NAT服务
nathost# load config                                               #加载配置文件的配置
nattest# write file                                                #保存配置
```


## QNATSH使用说明
+ ### `QNATSH`概述
`QNATSH` 使用节点层级控制可执行的配置命令，一共分为可用节点（enable node），配置节点（config node），pool节点和service节点。

+ ### 启动`NATSH`
`qnatsh`     （不带参数启动）不启动nat主程序也不读取配置文件，直接进入到命令行界面。
`qnatsh -b`  （带参数启动）自动拉起nat主程序，并读取最后一次配置文件保存的配置进行启动，并进入命令行界面。

+ ### 启动/停止 `QNAT`服务
`ip nat start` 该命令启动nat主程序，不加载配置

`ip nat stop`  停止运行主程序

`load config`  加载最后一次保存的配置

+ ### 命令行界面说明
                                                                                                                                    
|命令格式	                                              |所属节点	    |功能                                                            |
|---------------------------------------------------------|-------------|----------------------------------------------------------------|
|`end`                                                    |所有节点	    |退回enable节点                                                  |
|`exit`	                                                  |所有节点	    |退出当前节点，回到上一节点                                      |
|`write file`	                                          |所有节点	    |保存当前配置                                                    |
|`list`	                                                  |所有节点	    |查看对应节点下可执行的命令                                      |
|`config terminal`	                                      |enable节点	|进入配置节点                                                    |
|`show ip nat pool`	                                      |enable节点	|查看所有地址池配置                                              |
|`show link stats`	                                      |enable节点	|查看nat的链路统计信息                                           |
|`show local-ip`	                                      |enable节点	|查看本地地址，用于管理访问的kni口地址                           |
|`show nat`	                                              |enable节点	|查看nat服务的配置信息                                           |
|`show ospf interface`	                                  |enable节点	|查看本机可以用于ospf协议通信的接口信息                          |
|`show route`                                          	  |enable节点	|查看路由信息，这些是配置进nat的路由                             |
|`show running-config`	                                  |enable节点	|查看NAT当前正在运行使用的配置信息                               |
|`show startup-config`	                                  |enable节点	|查看当前已经保存的配置信息                                      |
|`hostname WORD`	                                      |config节点	|设置主机名称，用于显示命令行提示符的主机名                      |
|`ip addr A.B.C.D/M dev (dpdk0.kni|dpdk1.kni)`	          |config节点	|配置对外访问的IP地址，主要用于响应ospf等路由协议的路由通告等    |
|`ip nat pool NAME`	                                      |config节点	|配置NAT地址池，并进入到地址池节点进行细节配置                   |
|`ip nat source A.B.C.D A.B.C.D`	                      |config节点	|配置NAT服务，并进入到NAT服务节点进行细节配置                    |
|`ip route A.B.C.D/M dev (inside|outside) [kni_host]`	  |config节点	|配置NAT依赖的路由信息                                           |
|`ip route A.B.C.D/M via A.B.C.D dev (inside|outside)`	  |config节点	|配置NAT依赖的路由信息                                           |
|`local ip A.B.C.D/M`	                                  |config节点	|配置本地地址，用于管理访问的kni口地址                           |
|`no hostname`	                                          |config节点	|取消设置主机名称，用于显示命令行提示符的主机名                  |
|`no ip addr A.B.C.D/M dev (dpdk0.kni|dpdk1.kni)`	      |config节点	|取消配置对外访问的IP地址，主要用于响应ospf等路由协议的路由通告等|
|`no ip nat pool NAME`	                                  |config节点	|取消配置NAT地址池，并进入到地址池节点进行细节配置               |
|`no ip nat source A.B.C.D A.B.C.D`	                      |config节点	|取消配置NAT服务，并进入到NAT服务节点进行细节配置                |
|`no ip route A.B.C.D/M dev (inside|outside) [kni_host]`  |config节点	|取消配置NAT依赖的路由信息                                       |
|`no ip route A.B.C.D/M via A.B.C.D dev (inside|outside)` |config节点	|取消配置NAT依赖的路由信息                                       |
|`no local ip A.B.C.D/M`	                              |config节点	|取消配置本地地址，用于管理访问的kni口地址                       |
|`member ip A.B.C.D/M`	                                  |pool节点	    |配置池内单地址成员                                              |
|`member range A.B.C.D A.B.C.D masklen <0-32>`	          |pool节点	    |配置池内一段连续地址成员                                        |
|`no member ip A.B.C.D/M`	                              |pool节点	    |取消配置池内单地址成员                                          |
|`no member range A.B.C.D A.B.C.D`	                      |pool节点	    |取消配置池内一段连续地址成员                                    |
|`dest A.B.C.D/M`	                                      |service节点	|配置NAT服务的地址转换目标（单地址）                             |
|`dest pool NAME`	                                      |service节点	|配置NAT服务的地址转换目标地址池                                 |
|`no dest A.B.C.D/M`	                                  |service节点	|取消配置NAT服务的地址转换目标（单地址）                         |
|`no dest pool NAME`	                                  |service节点	|取消配置NAT服务的地址转换目标地址池                             |

## 测试QNAT
+ ### 测试拓扑图
![top.png](./pic/top.png) 

+ ### 测试条件
  需要通过静态/动态（默认）路由或策略路由（PBR,Policy Based Routing）的方式将需要做NAT的流量导向QNAT服务器的intranet网卡。
  
+ ### 测试结果
+ #### NAT44
进入`QNAT`服务器的intranet网卡的流量根据配置规则，以NAT/流量透传的方式从QNAT服务器转发出去。
+ #### 流量透传
进入`QNAT`服务器的intranet网卡的流量若未匹配任何规则，则直接从QNAT服务器转发出去
+ #### 多地址池选择
进入`QNAT`服务器的intranet网卡的流量根据配置规则，选择相关的地址池进行NAT并转发出去
+ #### 限定单IP会话数
```bash
$ cat /etc/qnat/qnat_blk.conf
255.255.255.255=10000
$ tail -f /var/log/qnat_blk.log
```
默认的255.255.255.255 = 10000 表示所有IP默认最大会话数为10000.可在配置文件中对单IP进行会话数限制配置。
+ #### NAT会话记录
```bash
$ tail -f /var/log/qnat.log
```
由于日志数据量较大，建议在/etc/qnat/qnat.conf调整日志存放路径，并使用logrotate进行归档。


## License
Main code of QNAT is [GNU General Public License, version 2 (GPLv2)](https://www.gnu.org/licenses/gpl-2.0.html) licensed.



## Other Dependencies:


* [DPVS](https://github.com/iqiyi/dpvs)

DPVS is a high performance Layer-4 load balancer based on DPDK. It's derived from Linux Virtual Server LVS and its modification alibaba/LVS.


* [Keepalived](http://www.keepalived.org/)

Keepalived is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

* [LVS/ipvsadm](http://www.linuxvirtualserver.org)

Linux Virtual Server kernel patches and related programs, released under the GNU General Public License (GPL).

* [DPDK](http://dpdk.org)

Main code of DPDK is BSD licensed and Linux kernel related parts are naturally licensed under the GPL.

* [LVS](http://www.linuxvirtualserver.org/)

Linux Virtual Server kernel patches and related programs, released under the GNU General Public License (GPL).

* [Linux Kernel](www.kernel.org)

Linux Kernel is available under GPL, see this [document](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/COPYING) for details.

* [Alibaba/LVS](https://github.com/alibaba/LVS)

Alibaba/LVS is based on LVS kernel components and related programs.

* [quagga](http://www.nongnu.org/quagga/)

Quagga Routing Software Suite, GPL licensed.

* [Consistent hashing](http://www.codeproject.com/Articles/56138/Consistent-hashing)

Consistent hashing library is BSD licensed.



## 联系我们
* QQ群: 914897475

![QQ_group.png](./pic/QQ_group.png)




