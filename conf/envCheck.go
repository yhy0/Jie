package conf

import (
    "fmt"
    "github.com/go-rod/rod/lib/launcher"
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
    // 检查 nmap 是否已安装
    nmapInstalled := commandExists("nmap")
    if !nmapInstalled {
        fmt.Println("nmap does not follow, please install")
        os.Exit(1)
    }
    
    // 检查 masscan 是否已安装
    masscanInstalled := commandExists("masscan")
    if !masscanInstalled {
        fmt.Println("nmap does not follow, please install")
        os.Exit(1)
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
