在64位系统下：请使用realse x64编译
在64位系统下：请使用realse x32编译


### NtQueryInformationThread

获取到线程信息，这里主要是拿到线程的Tag，线程Tag从线程TEB中拿出

x86 PPEB + 0xF60

x64 PPEB + 0x1720 



参考http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB_x64.html

### _I_QueryTagInformation

这里根据tag来获取线程属性，也就是

![image-20200315155137730](https://images.gitee.com/uploads/images/2020/0315/165446_fb860cbd_2347406.png)


参考 https://github.com/QAX-A-Team/EventCleaner