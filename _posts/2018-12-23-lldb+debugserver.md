---
layout: post
title: 使用lldb+debugserver动态调试iOS应用
key: 20150103
tags: iOS Reverse
excerpt_separator: <!--more-->
---
本来想拿某个字母车作样本的，结果那个iOS端有反sysctl调试，所以换了个投资APP
首先注册发送验证码抓包<!--more-->
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.1.png)
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.2.png)

看到data是加密的，砸完壳直接将二进制文件拖进IDA，String搜索requestTime，找到调用的函数，
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.3.png)

看到data关键字，分析一下流程大致判断是将json Base64之后AES加密，接下来直接断这两个关键地方
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.4.png)

lldb和debugserver配置这里就不多说了，网上博客和两本iOS逆向书都有  
~~首先开一个终端进行两个端口转发：iproxy 2222 22和iproxy 12345 1234~~  
~~第二个终端输入ssh -p 2222 root@localhost，直接attach上进程：debugserver *:1234 -a "MoneyPlatListedVersion"（ps -A找到进程），为此需要先打开APP~~  
~~第三个终端输入lldb命令连接：process connect connect://localhost:12345~~  
**更新iOS12以上调试步骤：**  
首先开一个终端进行两个端口转发：iproxy 2222 22和iproxy 1234 1111（将iPhone的1111端口映射到Mac的1234端口）  
第二个终端输入ssh -p 2222 root@localhost，直接attach上进程：cd /usr/bin && ./debugserver 127.0.0.1:1111 -a "MoneyPlatListedVersion"（ps -A找到进程），因此需要先打开APP  
第三个终端输入lldb命令连接：process connect connect://localhost:1234  
image list -o -f | grep MoneyPlatListedVersion 找到ASLR的基地址偏移（这里要注意调试的APP必须和IDA分析的是一致的，这样基地址才能对上，我之前因为换了iPhone6 plus的越狱机，而砸壳分析的文件还是老的5s脱出来的被坑了）
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.5.png)

然后断在br s -a 0x0000000000014000+0x00000001000EA360，c运行点击获取验证码触发断点
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.6.png)

先看objc_msgSend函数，receive是x0寄存器，selector是x1寄存器，参数1是x2，参数2是x3，以此类推...调用完成后返回值存在x0寄存器里  
selector是base64EncodedString，接着看receiver：po $x0
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.7.png)

接着ni单步执行此函数，查看返回值po $x0，返回了base64的数据
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.8.png)

同理我们断在-[NSData aes256_encrypt:IV:]的关键函数CCCrypt
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.9.png)
对比
```objective-c
CCCryptorStatus CCCrypt(
    CCOperation op,         /* kCCEncrypt, etc. */
    CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
    CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
    const void *key,
    size_t keyLength,
    const void *iv,         /* optional initialization vector */
    const void *dataIn,     /* optional per op and alg */
    size_t dataInLength,
    void *dataOut,          /* data RETURNED here */
    size_t dataOutAvailable,
    size_t *dataOutMoved)
```
我们分别打印出它的key，len，iv和dataIn的长度
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.10.png)

然后使用memory read $x6 -count 748 -force打印dataIn数据
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.11.png)

综上lldb调试还是非常方便的，和hook相比不用在意那么多参数类型，但是与frida的-f参数相比缺点也很明显，如果程序有反调试检测就得绕过了。

***
**2021.8更新：** 在iOS动态调试强烈推荐使用[voltron](https://github.com/snare/voltron)这个工具，可以打造媲美IDA的调试界面。我一般开command、registers、disasm、memory这四个窗口，调试过程中对于寄存器的变化和内存读写的监控操作都会以高亮显示，极大改善了lldb的调试体验。
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20181223.12.png)

参考  
[lldb使用方法(学习笔记)](https://bbs.pediy.com/thread-212731.htm)  
[实战：干掉高德地图7.2.0版iOS客户端的反动态调试保护](http://www.iosre.com/t/7-2-0-ios/770)  
[iOS逆向工程之Hopper+LLDB调试第三方App](https://www.cnblogs.com/ludashi/p/5730338.html)
