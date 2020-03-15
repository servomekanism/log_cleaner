### NtQueryInformationThread

获取到线程信息，这里主要是拿到线程的Tag，线程Tag从线程TEB中拿出

x86 PPEB + 0xF60

x64 PPEB + 0x1720 



参考http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB_x64.html

### _I_QueryTagInformation

这里根据tag来获取线程属性，也就是

![image-20200315155137730](windows清理日志.assets/image-20200315155137730.png)