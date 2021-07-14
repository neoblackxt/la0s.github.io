---
layout: post
title: 使用Needle绕过iOS越狱检测
key: 20150103
tags: iOS Reverse
excerpt_separator: <!--more-->
---
首先介绍一下Needle这个工具，和Android上的Drozer一样也是iOS安全测试框架，旨在简化对iOS应用程序进行安全评估的整个过程，Needle所涵盖的测试领域的一些示例包括：数据存储，进程间通信，网络通信，静态代码分析，挂钩和二进制保护（复制而来）。里面有很多集成了很多模块能方便的帮我们完成测试工作。<!--more-->  
好了介绍到这，本文主要是针对三款有越狱检测的iOS应用，难度由低到高，这里主要用到了dynamic/detection/script_jailbreak-detection-bypass这个模块（此模块需要添加Darwin CC Tools依赖），关于模块的命令用法见Needle的wiki [Modules-Usage](https://github.com/mwrlabs/needle/wiki/Modules-Usage)，这里就不赘述了  
首先针对第一个APP（v5.1.2）
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.1.png)

通过needle提供的模块script_jailbreak_detection_bypass
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.2.png)

而且我发现send在这里无法输出，所以改用console.log打印，发现是在-[UIDevice isJailbroken]这个类是（后者测试不是），查看此类
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.3.png)

使用了两种方法检测越狱，因为它是直接通过方法的返回值判断是否越狱的，所以可以直接修改此Bool返回值即可绕过
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.4.png)

成功绕过
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.5.png)

这个APP越狱检测函数恰好叫isJailbroken所以能被hook绕过，下面来看Needle无法绕过的两个APP（v6.3.1）
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.6.png)

~~Mac上的IDA7.0搜不出来中文字符（其实在string段里是显示中文的），原因是无法显示_ustring段的字符串，而Windows上是可以的。~~  
中文字符串是存在于**__ustring**段的，建议在IDA的字符串设置里勾选上Unicode类型，就可以正常搜出来了。
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.29.png)
使用Needle的dynamic/detection/script_jailbreak-detection-bypass模块无法绕过，由于在Strings窗口无法显示中文字符串，直接在__cfstring段搜索越狱关键词，找到调用函数
-[AppDelegate application:didFinishLaunchingWithOptions:]
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.7.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.8.png)

关键就在这个stat函数了：通过文件名filename获取文件信息，并保存在buf所指的结构体stat中，执行成功则返回0，失败返回-1。  
虽然Needle有hook这个函数（不得不说Needle考虑的情形比objection和其他工具多多了），但是返回值这么写是有问题的
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.9.png)

所以参考objection的写法，重新改了本地的代码
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.10.png)

成功绕过
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.11.png)

<iframe width="560" height="315" src="https://www.youtube.com/embed/X7BQDjLsCZQ" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
最后不再借助这个框架，把Needle的代码拿出来自己手动写一个js
```javascript
var paths=[
        "/Applications/blackra1n.app",
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSetttings.app",
        "/Applications/WinterBoard.app",
        "/bin/bash",
        "/bin/sh",
        "/bin/su",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/pguntether",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/bin/cycript",
        "/usr/bin/ssh",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/frida-server",
        "/usr/sbin/sshd",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/var/mobile/Media/.evasi0n7_installed",
        "/var/tmp/cydia.log"];


var f = Module.findExportByName("libSystem.B.dylib","stat64");
Interceptor.attach(f, {
    onEnter: function ( args) {
        this.is_common_path = false;
        var arg = Memory.readUtf8String(args[0]);
        for (var path in paths) {
            if (arg.indexOf(paths[path]) > -1) {
                console.log("Hooking native function stat64: " + arg);
                this.is_common_path = true;
                //return -1;
            }
        }
    },
    onLeave: function (retval) {
               if (this.is_common_path){
                   console.log("stat64 Bypass!!!");
                   retval.replace(-1);
               }      
            }
});

var f = Module.findExportByName("libSystem.B.dylib","stat");
Interceptor.attach(f, {
    onEnter: function ( args) {
        this.is_common_path = false;
        var arg = Memory.readUtf8String(args[0]);
        for (var path in paths) {
            if (arg.indexOf(paths[path]) > -1) {
                console.log("Hooking native function stat: " + arg);
                this.is_common_path = true;
                //return -1;
            }
        }
    },
    onLeave: function (retval) {
               if (this.is_common_path){
                   console.log("stat Bypass!!!");
                   retval.replace(-1);
               }          
            }
});
```
spawn并注入
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.12.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.13.png)

最后再看一个APP（v2.1.5），同样是Needle的模块无法绕过，而且这个越狱检测可以说是业界典范了
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.14.png)

在__cfstring段搜索不安全环境
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.15.png)

找到这个弹出提示框的-[AppDelegate showJailBreakDialog]
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.16.png)

接着找调用它的地方，String窗口搜索showJailBreakDialog
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.17.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.18.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.19.png)

同样都是返回bool值，直接hook一下-[BMKSecurityManager jailBreak]就可以绕过了
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.20.png)

在Functions并没有搜到这个方法，猜测是在framework实现了此方法，双击OBJC_CLASS___BMKSecurityManager
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.21.png)

找到包里的BMKit.framework/BMKit，搜索jailBreak
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.22.png)

可以看到了它采用了7个方法检测越狱...
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.23.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.24.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.25.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.26.png)

感兴趣的同学可以自己研究一下。cydia有个屏蔽越狱检测的Liberty Lite插件，上述三个APP都可以用这个tweak绕过，可以用cydownload下载.deb对里面的zzzzzLiberty.dylib逆向一下看看究竟是怎么实现屏蔽的。  
补充一下关于Needle这个框架，bug太多了，而且上次更新还是半年前，作者基本已经不维护了，这里分享一下Needle的两个设置选项，为什么要分享，因为官方wiki没有提供修改的方式，只能本地重新编译仓库源码（之前的objection也是这种方式改的）。一是设置选择进程的时候隐藏iOS自己的APP，二是默认设置APP启动方式是spawn（否则每次都要重新设置），用到了万能的grep命令。
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.27.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190114.28.png)
