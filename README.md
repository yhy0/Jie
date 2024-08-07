## Jie

> What I have accomplished cannot be reversed

<p align="center">
  <a href="https://github.com/yhy0/Jie/blob/main/LICENSE">
    <img alt="Release" src="https://img.shields.io/github/license/yhy0/Jie"/>
  </a>
  <a href="https://github.com/yhy0/Jie">
    <img alt="Release" src="https://img.shields.io/badge/release-v1.2.0-brightgreen"/>
  </a>
  <a href="https://github.com/yhy0/Jie">
    <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/yhy0/Jie?color=9cf"/>
  </a>
  <a href="https://github.com/yhy0/Jie">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/yhy0/Jie"/>
  </a>
  <a href="https://github.com/yhy0/Jie">
    <img alt="GitHub all release" src="https://img.shields.io/github/downloads/yhy0/Jie/total?color=blueviolet"/>
  </a>
</p>



<p align="center">
  <a href="https://github.com/yhy0/Jie/blob/main/README.md">English</a> •
  <a href="https://github.com/yhy0/Jie/blob/main/README_CN.md">中文</a> •
</p>

`The English documentation was generated by GPT3.5`



Analyze and scan traffic by using [active crawler mode](https://github.com/Qianlitp/crawlergo) or [passive proxy](https://github.com/lqqyt2423/go-mitmproxy).

**Please read the documentation carefully before using**

## Pre-requisites for use
- nmap
- masscan
- chromium

You should check whether the above programs exist on your machine before using them

> If you do not want to install nmap and masscan, you can use-nps to specify that port scanning will not be performed and turn off checking

## Active Mode

Three built-in crawler modes are available:

|                             Mode                             | Corresponding Parameter |
| :----------------------------------------------------------: | ----------------------- |
| [crawlergo](https://github.com/Qianlitp/crawlergo) Crawler (Headless browser mode crawler) | `--craw c`              |
| **Default** [katana](https://github.com/projectdiscovery/katana) Crawler (Standard crawling mode using standard go http library to handle HTTP requests/responses) | `--craw k`              |
| [katana](https://github.com/projectdiscovery/katana) Crawler (Headless browser mode crawler) | `--craw kh`             |

When using headless mode, you can specify `--show` to display the crawling process of the browser.

In active mode, you can enter the **Security Copilot** mode by specifying `--copilot`, which will not exit after scanning, making it convenient to view the web results page.

```bash
./Jie web -t https://public-firing-range.appspot.com/ -p xss -o vulnerability_report.html --copilot
```

If the username and password for the web are not specified, a `yhy/password` will be automatically generated, which can be viewed in the logs. For example, the following is the automatically generated one:

`INFO [cmd:webscan.go(glob):55] Security Copilot web report authorized:yhy/3TxSZw8t8w`

## Passive Mode (Security Copilot)

Passive proxy is implemented through [go-mitmproxy](https://github.com/lqqyt2423/go-mitmproxy/).

### Security Copilot

Why is it called `Security Copilot`? According to my idea, this is not just a vulnerability scanner, but also a comprehensive auxiliary tool.

After hanging the scanner, go through the website once. Even if there are no vulnerabilities, it should tell me the approximate information of this website (fingerprint, cdn, port information, sensitive information, API paths, subdomains, etc.), which helps in further exploration manually, assisting in vulnerability discovery, rather than just finishing the scan and considering it done, requiring manual reevaluation.

### Certificate Download

HTTPS websites under passive proxy require installing certificates. The HTTPS certificate-related logic is compatible with [mitmproxy](https://mitmproxy.org/), 

and The certificate is automatically generated after the command is started for the first time, and the path is ~/.mitmproxy/mitmproxy-ca-cert.pem.

Install the root certificate. Installation steps can be found in the Python mitmproxy documentation: [About Certificates](https://docs.mitmproxy.org/stable/concepts-certificates/).

### Start

```bash
 ./Jie  web --listen :9081 --web 9088 --user yhy --pwd 123 --debug
```

This will listen on port 9081, and the web interface (SecurityCopilot) will be open on port 9088.

Set the browser's proxy to 9081, or integrate with Burp.

![image-20240101121809597](images/image-20240101121809597.png)

![image-20240101121931631](images/image-20240101121931631.png)

![image-20240101121957058](images/image-20240101121957058.png)

## Basic Usage

### Configuration

Some configurations can be modified through [Jie_config.yaml](./Jie_config.yaml), or through the configuration interface of `http://127.0.0.1:9088/` (changes made in the web interface will be updated in the configuration file in real-time).

`./Jie web -h`

```bash
Flags:
      --copilot          Blocking program, go to the default port 9088 to view detailed scan information.
                         In active mode, specify this parameter to block the program. After scanning, the program will not exit, and you can view information on the web port.
  -h, --help             help for web
      --listen string    use proxy resource collector, value is proxy addr, (example: 127.0.0.1:9080).
                         Proxy address listened to in passive mode, default is 127.0.0.1:9080
      --np               not run plugin.
                         Disable all plugins
  -p, --plugin strings   Vulnerable Plugin, (example: --plugin xss,csrf,sql,dir ...)
                         Specify the enabled plugins. Specify 'all' to enable all plugins.
      --poc strings      specify the nuclei poc to run, separated by ','(example: test.yml,./test/*).
                         Custom nuclei vulnerability template address
      --pwd string       Security Copilot web report authorized pwd.
                         Web page login password. If not specified, a random password will be generated.
      --show             specifies whether to show the browser in headless mode.
                         Whether to display the browser in active scanning mode
      --user string      Security Copilot web report authorized user, (example: yhy).]
                         Web page login username, default is yhy (default "yhy")
      --web string       Security Copilot web report port, (example: 9088)].
                         Web page port, default is 9088 (default "9088")

Global Flags:
      --debug           debug
  -f, --file string     target file
  -o, --out string      output report file(eg:vulnerability_report.html)
      --proxy string    proxy, (example: --proxy http://127.0.0.1:8080)
  -t, --target string   target
```

### Download and Compile

Download the corresponding program from [https://github.com/yhy0/Jie/releases/latest](https://github.com/yhy0/Jie/releases/latest). The entire process is built automatically by **Github Action**, so

 feel free to use it.

#### Linux/Mac

Simply execute `make` to compile.

#### Windows

```bash
export CGO_ENABLED=1;go build -ldflags "-s -w" -o Jie main.go
```

### Integration with Burp

#### Passive-scan-client Plugin (Strongly Recommended)

[passive-scan-client](https://github.com/yhy0/passive-scan-client)

![passive-scan-client](images/passive-scan-client.png)

Freely select which scanner to use via three monitoring switches. **Note: JavaScript and CSS should also go through the scanner to collect information.**

#### Setting Upstream Proxy in Burp (Not Recommended)

![image-20231011213912055](images/image-20231011213912055.png)

The traffic of the Upstream Proxy Intruder and Repeater modules will also go through the scanner.

This will cause all traffic from manual testing to go through the scanner, which may not be ideal. This should be done as needed.


## Features

The plugins internally judge whether they have been scanned based on the traffic collected passively or actively (TODO Should the scanning plugin be executed in a certain order?).

### Information Gathering

- Website fingerprint information
- Aggregated display of URLs requested by each website
- Website domain information: cdn/waf/cloud, resolution records
- Jwt automatic blasting (todo generate dictionary automatically based on domain name)
- Sensitive information
- Active path scanning (bbscan rules, added a fingerprint field, when there is a fingerprint, only the corresponding rule will be scanned, for example, php websites will not scan springboot rules)
- Port information
- Collect domain names, IPs, APIs

### Plugins

Some scans will recognize the language environment based on the collected fingerprint information to prevent invoking Java scanning plugins for PHP websites.

#### Directory Structure Scan

The `scan` directory is the scan plugin library, and each directory's plugin handles different situations.

-   PerFile: For each URL, including parameters, etc.
-   PerFolder: For the directory of the URL, the directory will be accessed separately
-   PerServer: For each domain, meaning a target is only scanned once

|        Plugin         |                         Description                          | Default On |                            Scope                             |
| :-------------------: | :----------------------------------------------------------: | :--------: | :----------------------------------------------------------: |
|          xss          | Semantic analysis, prototype pollution, DOM pollution point propagation analysis |    true    |                           PerFile                            |
|          sql          | Currently only implements some simple SQL injection detection |    true    |                           PerFile                            |
|        sqlmap         | Forward traffic to sqlmap via specified sqlmap API for injection detection |   false    |                           PerFile                            |
|         ssrf          |                                                              |    true    |                           PerFile                            |
|         jsonp         |                                                              |    true    |                           PerFile                            |
|          cmd          |                      Command execution                       |    true    |                           PerFile                            |
|          xxe          |                                                              |    true    |                           PerFile                            |
|       fastjson        | When a request is detected as json, it is patched with [@a1phaboy](https://socialify.git.ci/a1phaboy/)'s [FastjsonScan](https://socialify.git.ci/a1phaboy/FastjsonScan) scanner to detect fastjson; jackson is not implemented yet |    true    |                           PerFile                            |
|       bypass403       | [dontgo403](https://github.com/devploit/dontgo403) 403 bypass detection |    true    |                           PerFile                            |
|         crlf          |                        crlf injection                        |    true    |                          PerFolder                           |
|          iis          | iis high version short filename guessing [iis7.5-10.x-ShortNameFuzz]( |   false    |                          PerFolder                           |
| nginx-alias-traversal | Directory traversal due to Nginx misconfiguration [nginx](https://github.com/vulhub/vulhub/blob/6a142caa19620bffa4cda9989697afd5b4136c87/nginx/insecure-configuration/README.md) |    true    |                          PerFolder                           |
|         log4j         | log4j vulnerability detection, currently only tests request headers |    true    |                          PerFolder                           |
|        bbscan         | [bbscan](https://github.com/lijiejie/bbscan) rule directory scan |    true    | PerFolder<br />PerServer (for rules that specify the root directory) |
|       portScan        | Use [naabu](https://github.com/projectdiscovery/naabu) to scan Top 1000 ports, then use [fingerprintx](https://github.com/praetorian-inc/fingerprintx) to identify services |   false    |                          PerServer                           |
|         brute         | If service blasting is enabled, service blasting will be performed after scanning the port service is detected |            |                          PerServer                           |
|        nuclei         | Integrated [nuclei](https://github.com/projectdiscovery/nuclei) |   false    |                          PerServer                           |
|        archive        | Utilize https://web.archive.org/ to obtain historical url links (parameters) and then scan |    true    |                          PerServer                           |
|          poc          | poc module written in Go for detection. The poc module relies on fingerprint recognition, and scanning will only occur when the corresponding fingerprint is recognized. No pluginization anymore |   false    |                          PerServer                           |

### Logical Vulnerabilities TODO

Add multiple user cookies for authorization detection (it seems better to write tests with Burp plugins themselves, so there seems to be no need to write them here).


## Third-party Libraries

```go
package main

import (
    "github.com/logrusorgru/aurora"
    "github.com/yhy0/Jie/SCopilot"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/crawler"
    "github.com/yhy0/Jie/pkg/mode"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/logging"
    "net/url"
)

/**
  @author: yhy
  @since: 2023/12/28
  @desc: //TODO
**/

func lib() {
    logging.Logger = logging.New(conf.GlobalConfig.Debug, "", "Jie", true)
    conf.Init()
    conf.GlobalConfig.Http.Proxy = ""
    conf.Global

Config.WebScan.Craw = "k"
    conf.GlobalConfig.WebScan.Poc = nil
    conf.GlobalConfig.Reverse.Host = "https://dig.pm/"
    conf.GlobalConfig.Passive.WebPort = "9088"
    conf.GlobalConfig.Passive.WebUser = "yhy"
    conf.GlobalConfig.Passive.WebPass = "123456" // Remember to change to a strong password

    // Enable all plugins
    for k := range conf.Plugin {
        // if k == "nuclei" || k == "poc" {
        //     continue
        // }
        conf.Plugin[k] = true
    }

    if conf.GlobalConfig.Passive.WebPort != "" {
        go SCopilot.Init()
    }

    // Initialize crawler
    crawler.NewCrawlergo(false)

    go func() {
        for v := range output.OutChannel {
            // Show in SCopilot
            if conf.GlobalConfig.Passive.WebPort != "" {
                parse, err := url.Parse(v.VulnData.Target)
                if err != nil {
                    logging.Logger.Errorln(err)
                    continue
                }
                msg := output.SCopilotData{
                    Target: v.VulnData.Target,
                }

                if v.Level == "Low" {
                    msg.InfoMsg = []output.PluginMsg{
                        {
                            Url:      v.VulnData.Target,
                            Plugin:   v.Plugin,
                            Result:   []string{v.VulnData.Payload},
                            Request:  v.VulnData.Request,
                            Response: v.VulnData.Response,
                        },
                    }
                } else {
                    msg.VulMessage = append(msg.VulMessage, v)
                }
                output.SCopilot(parse.Host, msg)
                logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
            }
            logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
        }
    }()
    mode.Active("http://testphp.vulnweb.com/", nil)
}
```

## Vulnerability Exploitation (Still in Development, Low Priority)

**Currently under development, even I need to look at the code for help information, detailed documentation will be written once it's done.**

Due to most of the vulnerability exploitation tools being written in Java and supporting different Java versions, setting up the environment is too cumbersome and frustrating, so Jie has been redefined.

Jie: A comprehensive and powerful vulnerability scanning and exploitation tool.

The current version (1.0.0) supports exploitation of the following vulnerabilities

```shell
A Powerful security assessment and utilization tools

Usage:
  Jie [command]

Available Commands:
  apollo      apollo scan && exp
  fastjson    fastjson scan && exp
  help        Help about any command
  log4j       log4j scan && exp
  other       other scan && exp bb:BasicBrute、swagger:Swagger、nat:NginxAliasTraversal、dir:dir)
  s2          Struts2 scan && exp
  shiro       Shiro scan && exp
  web         Run a web scan task
  weblogic    WebLogic scan && exp

Flags:
      --debug           debug
  -f, --file string     target file
  -h, --help            help for Jie
  -o, --out string      output report file(eg:vulnerability_report.html)
      --proxy string    proxy, (example: --proxy http://127.0.0.1:8080)
  -t, --target string   target

Use "Jie [command] --help" for more information about a command.
```

For example, Shiro key vulnerability exploitation:

```bash
# Without specifying -m, it defaults to blasting the key and exploitation chain
Jie shiro -t http://127.0.0.1

# Exploitation
Jie Shiro -t http://127.0.0.1 -m exp -k 213123 -g CCK2 -e spring -km CBC --cmd whoami
```

Where various tools by other researchers have been stitched together, some of which are included in the description of scanning and exploiting vulnerabilities. If anything is missing, you can contact me to add it.
More vulnerability exploitation will be supported later.

https://jie.fireline.fun/

## References

### Crawlers

[crawlergo](https://github.com/Qianlitp/crawlergo)

[katana](https://github.com/projectdiscovery/katana)


### Passive Scan Proxy

https://github.com/lqqyt2423/go-mitmproxy

### Xss

Semantic analysis, prototype pollution, DOM pollution point propagation analysis

https://github.com/w-digital-scanner/w13scan

https://github.com/ac0d3r/xssfinder

https://github.com/kleiton0x00/ppmap

### SQL Injection

Extracted code related to detection from [sqlmap](https://github.com/sqlmapproject/sqlmap)

### POC

Detection through fingerprint recognition

todo Not embedding the nuclei's yml files, changing to download and update online from the official website

https://github.com/projectdiscovery/nuclei

Some of the POCs in xray are written improperly, causing parsing problems, which need to be corrected.
For example:
response.status == 200 && response.headers["content-type"] == "text/css" && response.body.bcontains(b"$_GET['css']")


content-type should be Content-Type

But it seems there is a parsing problem.

Do not use xray's POC, only use nuclei's yml files
Together with the need for organization to prevent duplicate scanning, nuclei-template's POCs are enough.

### Vulnerability Scanners

https://github.com/wrenchonline/glint 

https://github.com/veo/vscan

### Some Other Vulnerabilities

#### Sensitive Information

https://github.com/mazen160/secrets-patterns-db
https://github.com/pingc0y/URLFinder

#### Fastjson

https://github.com/a1phaboy/FastjsonScan


### Fingerprinting

https://github.com/w-digital-scanner/w13scan

https://github.com/SleepingBag945/dddd

## License

This code is distributed under the AGPL-3.0 license. See [LICENSE](https://github.com/yhy0/Jie/blob/main/LICENSE) in this directory.

## Acknowledgments

Thanks to the open source works and blogs of various masters, as well as [JetBrains](https://www.jetbrains.com/)' support for a series of easy-to-use IDEs for this project.

![JetBrains Logo (Main) logo](https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.svg)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yhy0/Jie&type=Date)](https://star-history.com/#yhy0/Jie&Date)