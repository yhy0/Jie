## 劫(开发中)

https://jie.fireline.fun/

基于浏览器爬虫开发的web漏洞主动 (被动) 扫描器

由于扫描器只是粗暴的调用 xray、nuclei ，不优雅，而且 xray 不开源，不开源的东西我加入自己的扫描器用着不舒服(纯属给自己挖坑，就当给自己加深漏洞理解了，开发中代码很烂勿喷)。于是产生一个想法，将漏扫类项目拆分出来，重新糅合成一个轮子。

目前打算设计成两种模式:

-   一种被动 优先级低
-   一种主动

## 已有功能

- Chrome Headless 爬虫, 爬取中进行指纹识别(katana)
- 指纹识别，根据指纹识别进行漏洞检测(nuclei)
- 基础漏洞扫描 (sql、xss 等) 待优化
- 目录扫描(bbscan规则)
- ~~一些端口弱口令爆破~~(这还要在加上端口扫描，先去除)

## 语言环境识别

防止对 php 的网站调用 java 的扫描插件

## 插件调用(后期看看有没有必要吧)

插件如何调用？ 这里直接放弃，只要代码逻辑写好就行了，后期或者有重构的想法

~~仿照awvs设计了插件类别~~

~~PerFile 对每个文件处理,包括文件后面的参数~~

~~PerFolder 对每个目录处理~~

~~PerScheme 对每个域名处理~~

~~PostScan 对Post请求的处理~~

## 参考

### 爬虫

https://github.com/projectdiscovery/katana

添加了无头浏览器检测绕过 https://bot.sannysoft.com/

![BypassHeadlessDetect.png](https://cdn.jsdelivr.net/gh/yhy0/PicGoImg@master/img/202303062213518.png)

### 被动扫描代理

https://github.com/lqqyt2423/go-mitmproxy

### Xss

https://github.com/hahwul/dalfox 什么玩意，发的包也太多了，后续去掉

https://github.com/ac0d3r/xssfinder

https://github.com/kleiton0x00/ppmap

### SQL 注入  TODO

提取 [sqlmap](https://github.com/sqlmapproject/sqlmap) 中关于检测的代码，提取一部分思想就行了

### poc

通过指纹识别进行对应的漏洞检测

todo 不内置 nuclei 的 yml 文件，改为官方在线下载、更新

https://github.com/projectdiscovery/nuclei

xray poc  中有些写的不规范，导致解析有问题，需要修改
比如：
response.status == 200 && response.headers["content-type"] == "text/css" && response.body.bcontains(b"$_GET['css']")


content-type 应为 Content-Type

但又好像是解析有问题

不使用 xray 的 poc，只使用 nuclei 的 yml 文件
一起使用还要整理，防止重复扫描，nuclei-template 的 poc 已经够了

### 漏扫

https://github.com/wrenchonline/glint 作者设计的我看不懂，自己重来

https://github.com/veo/vscan	

### 一些其他漏洞

### Fastjson

https://github.com/a1phaboy/FastjsonScan