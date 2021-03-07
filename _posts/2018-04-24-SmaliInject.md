---
layout: post
title: smali全局注入探测App流程
key: 20150103
tags: Android Reverse
excerpt_separator: <!--more-->
---
工具转自 [Android应用逆向——分析反编译代码之大神器](http://blog.csdn.net/charlessimonyi/article/details/52027563)  
我个人觉得逆向主要分为两大方面，定位关键函数和分析算法，这也是实际项目和CTF竞赛的区别：前者是因为业务逻辑的复杂程度，导致代码定位逻辑变得复杂，后者则是将算法变形，考验逆向者的算法分析能力。当静态分析无法解决问题的时候，往往需要使用动态手段，本文评测了一下非虫大佬书中几种动态分析方法。栈跟踪法基本和采用AndroidStudio查看调用栈是一致的，基本只能分析局部函数的调用，粒度太粗。methodfiling方法输出简直惨不忍睹，充斥了大量的系统函数。于是有了本文采用smali注入的方法：  
附件smali注入 [链接](https://pan.baidu.com/s/16B_AlaN8luY246S_bQnuwg)  
其中包括了InjectLog.smali注入文件和Inject.py注入脚本  
将要分析的apk解包  java -jar apktool_2.3.2.jar d myapp.apk -o out（最新版apktool）
<!--more-->
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.1.png)

反编译后的目录
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.9.png)

将Inject.py放入要注入的smali文件目录，会自动给当前目录和子集目录smali文件进行注入
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.2.png)

Inject.py：  
这里需要python版本为3.3以上（因为会牵扯到脚本中某些函数的版本问题），执行这个脚本
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.3.png)

可以看到已经注入完毕，打开smali文件验证一下
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.4.png)

接下来将InjectLog.smali文件放入里面，注意目录
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.5.png)

重新打包 java -jar apktool_2.2.3.jar b out -o unsigned.apk，然后使用ApkToolkit工具进行签名即可：  
用Jeb打开patch过的apk,所有的函数都已经被注入了代码
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.6.png)

打开SDK工具下的ddms,在手机运行应用，过滤Tag为InjectLog
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.8.png)

打印日志输出的顺序就是smali文件（APK应用）的执行顺序
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20180424.7.png)

后期可以再配合AS的动态调试，可以帮助梳理局部函数的逻辑  
**说在最后的话**，弊端就是需要重打包，在今天这个APP防护原来越严的时代，此方法基本已经过时了，只能应对一些小型APP，因此有一定的局限性。
