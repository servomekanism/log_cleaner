x64Demo.exe 在64位系统下：请使用Release x64编译生成 


x32Demo.exe 在32位系统下：请使用Release x32编译生成


示例：

![Demo](https://gitee.com/L0yy/log_cleaning/raw/master/example.gif)

### NtQueryInformationThread

获取到线程信息，这里主要是拿到线程的Tag，线程Tag从线程TEB中拿出

x86 PPEB + 0xF60

x64 PPEB + 0x1720 

参考http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB_x64.html

### _I_QueryTagInformation

这里根据tag来获取线程属性，也就是

![image-20200315155137730](https://images.gitee.com/uploads/images/2020/0315/165446_fb860cbd_2347406.png)

参考 https://github.com/QAX-A-Team/EventCleaner