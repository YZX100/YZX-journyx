# YZX-journyx
Journyx系统soap_cgi.pyc接口存在XML外部实体注入批量检测脚本

![image](https://github.com/user-attachments/assets/9d8970f6-13b9-4024-9427-e38f10733f55)

```shell
检测该漏洞的FOFA语句：
body="Journyx"

使用说明：
如图所示 或 -h
注意：
使用的是python3解析器
检测的URL需要HTTP/HTTPS协议
该漏洞检测工具会将最后存在的URL回显出来
如果想要检测其他XML外部实体注入的命令
可以将源码中的data数据中的file协议更改
```
