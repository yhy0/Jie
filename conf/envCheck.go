package conf

import (
    "fmt"
    "github.com/go-rod/rod/lib/launcher"
    wappalyzer "github.com/projectdiscovery/wappalyzergo"
    "os"
    "os/exec"
)

/**
  @author: yhy
  @since: 2024/4/12
  @desc: 检查 namp、masscan、chrome 是否已经安装
**/

var ChromePath string

func Preparations() {
    if Wappalyzer == nil {
        // wappalyzergo  中已经处理了 syscall.Dup2(int(devNull.Fd()), int(os.Stderr.Fd())) ,单元测试也是 ok 的，这里为啥还会有
        Wappalyzer, _ = wappalyzer.New()
    }
    
    if !GlobalConfig.NoPortScan { // 不进行端口扫描时，不检查这些
        Plugin["portScan"] = false
        // 检查 nmap 是否已安装
        nmapInstalled := commandExists("nmap")
        if !nmapInstalled {
            fmt.Println("nmap not found, please install")
            os.Exit(1)
        }
        
        // 检查 masscan 是否已安装
        masscanInstalled := commandExists("masscan")
        if !masscanInstalled {
            fmt.Println("masscan not found, please install")
            os.Exit(1)
        }
    }
    
    if GlobalConfig.WebScan.Craw == "c" {
        // 检查 chromium 是否已安装
        if path, exists := launcher.LookPath(); exists {
            ChromePath = path
        } else {
            fmt.Println("chromium does not follow, please install https://www.chromium.org/getting-involved/download-chromium/")
            os.Exit(1)
        }
    }
    
}

// 检查命令是否可执行
func commandExists(cmd string) bool {
    _, err := exec.LookPath(cmd)
    return err == nil
}
