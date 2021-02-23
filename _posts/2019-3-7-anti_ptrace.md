---
layout: post
title: 使用Frida绕过iOS反调试
key: 20150103
tags: iOS Reverse
excerpt_separator: <!--more-->
---
在iOS平台上只要jailbroken了之后基本就可以想干啥干啥了，利用lldb+debugserver可以随便动态调试，所以最常用的保护手段就是反调试了，这里针对某新闻APP（v6.0.4）为例
当我们利用debugserver进行attach的时候，会报错Segmentation fault: 11<!--more-->
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.1.png)

这种情况基本就是APP做了反调试了，参考[干掉高德地图iOS反动态调试保护](http://iosre.com/t/7-2-0-ios/770)，我们利用debugserver -x backboard *:1234 /var/containers/.../XinHuaShe.app/XinHuaShe 启动APP，然后在lldb中下断b ptrace函数，然后使用bt打印堆栈
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.2.png)

将这里的地址转换一下就是0x0000000100000000+hex(333440)=0x100051680，在IDA中找到这个地址
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.3.png)

代码很明显了，一般来说ptrace反调试会写成如下的代码
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.4.png)

所以问题来了，有两种思路，因为sub_100051640只用来做反调试，所以可以replace掉这个sub_100051640函数，先看这种方法，代码如下
```javascript
var baseAddr = Module.findBaseAddress('XinHuaShe');
subAddr = baseAddr.add(0x51640);
console.log("subAddr is " + subAddr.toString(16));

var subAddr = ptr(subAddr);
//var open = new NativeFunction(ptracePtr, 'int', ['int', 'int','int', 'int']);
Interceptor.replace(subAddr, new NativeCallback(function (argc, argv) {
    console.log("Hook sub_ptrace Bypass!!!");
    return 0;
}, 'int', ['int', 'pointer']));
```
代码中最好确认subAddr地址是不是内存中的sub_100051640函数，使用frida spawn并注入
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.5.png)

可以成功attach。  
但是有时候调用ptrace的函数不一定只用来反调试，也有可能做了一些初始化的东西，就不能随随便便replace，否则程序会运行错误的。所以这里介绍另一种更通用的办法——直接replace掉ptrace函数，因为ptrace地址一般是由ptrace_ptr = dlsym(handle, "ptrace")返回的，所以首先要得到这个地址
```javascript
var f = Module.findExportByName('dyld',"dlsym");
Interceptor.attach(f, {
    onEnter: function (args) {
        this.is_common_path = false;
        var arg = Memory.readUtf8String(args[1]);
            if (arg.indexOf("ptrace") > -1) {
                this.is_common_path = true;
                //return -1;
            }
    },
    onLeave: function (retval) {
               if (this.is_common_path){
                   console.log("ptrace str: " + retval); //打印返回的ptrace地址：0x18bad1078
                   //retval.replace();
               }      
            }
});


var ptracePtr = ptr("0x18bad1078"); //ptrace函数地址
var OriginPtrace = new NativeFunction(ptracePtr, 'void', ["pointer", "pointer", "pointer", "pointer"]);
Interceptor.replace(ptracePtr, new NativeCallback(function(arg1, arg2, arg3, arg4) {
    if (arg1 == 31) {
        console.log("Hook ptrace Bypass!!!");
        return 0;
    } 
    else {
        OriginPtrace(arg1, arg2, arg3, arg4);
    }
},'int', ['int', 'pointer']));
```
因为libsystem_kernel.dylib`__ptrace这个地址是固定的，所以硬编码即可，spawn并注入
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.6.png)
之后正常调试
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.7.png)

除了hook之外有没有办法在程序运行前把这些反调试的指令patch掉呢，对于sub_100051640函数，我们只需要在运行之前对函数开头patch两条汇编即可，相当于直接return 0了，机器码可利用Keypatch得到
```javascript
MOV X0, #0      //00 00 80 D2   memory write -s 4 0x00000000006b8000+0x100051640 0xD2800000
RET             //C0 03 5F D6   memory write -s 4 0x00000000006b8000+0x100051640 0xD65F03C0
```
![](https://raw.githubusercontent.com/la0s/la0s.github.io/master/screenshots/20190307.8.png)

另外利用lldb提供的接口是不是可以写成script呢，这样就不用再考虑每次image的偏移，肯定也是可以的。

参考：  
[Disabling SSL pinning by hooking SecTrustEvaluate(...)](https://kov4l3nko.github.io/blog/2018-05-27-sll-pinning-hook-sectrustevaluate/)  
[Bypassing iOS anti-debugging protections](https://sig-switzerland.ch/wp-content/uploads/2017/05/SIGS-TechCon2017_Kudelski-Bypassing_iOS_App.pdf)
