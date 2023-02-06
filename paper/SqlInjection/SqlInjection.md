>   漏洞扫描器之 SQL 注入检测

# SQl 注入

提到 SQL 注入，那就离不开一个神器 [sqlmap](https://github.com/sqlmapproject/sqlmap)。 该漏洞模块检测打算从 [sqlmap](https://github.com/sqlmapproject/sqlmap) 中抽离出关于SQL注入检测的部分，使用 go 实现一遍。

# SQLMAP部分源码阅读

sqlmap 首先会对目标进行连接性检测，然后进行 waf 检测(这一块可以作为整体扫描器的一个入口检测)。然后就是我们要关注的核心功能，SQL 注入的检测。

sqlmap 主要有两种检测

-   启发式检测，对目标参数 sql 注入做一个初步的判断
-   注入检测

## 1. 启发式检测



## 2. 注入检测











# 参考

http://wjlshare.com/archives/1733