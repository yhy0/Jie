package brute

import (
    "github.com/yhy0/Jie/pkg/output"
    hydra2 "github.com/yhy0/Jie/scan/gadget/brute/hydra"
    "strings"
    "time"
)

/**
  @author: yhy
  @since: 2022/7/1
  @desc: //TODO
**/

func Hydra(target, host, service string, port int) {
    var (
        msg string
        err error
    )
    service = strings.ToLower(service)
    
    switch service {
    case "redis":
        msg, err = hydra2.Redis(host, port)
    case "ftp":
        msg, err = hydra2.FTP(host, port)
    case "memcached":
        msg, err = hydra2.Memcached(host, port)
    case "ldap", "rsh-spx", "ssh":
        msg, err = hydra2.SSH(host, port)
    case "mysql":
        msg, err = hydra2.Mysql(host, port)
    case "oracle", "oracle-tns":
        msg, err = hydra2.Oracle(host, port)
    case "mongod", "mongodb":
        msg, err = hydra2.Mongodb(host, port)
    case "postgresql":
        msg, err = hydra2.Postgresql(host, port)
    case "ms-sql-s", "mssql":
        msg, err = hydra2.SQLServer(host, port)
    case "ms-wbt-server", "ssl/ms-wbt-server", "rdp":
        msg, err = hydra2.RDP(host, port)
    case "microsoft-ds", "smb":
        msg, err = hydra2.SMB(host, port)
    }
    
    if err != nil {
        return
    }
    
    output.OutChannel <- output.VulMessage{
        DataType: "web_vul",
        Plugin:   "Hydra",
        VulnData: output.VulnData{
            CreateTime: time.Now().Format("2006-01-02 15:04:05"),
            Target:     target,
            Ip:         host,
            Payload:    msg,
        },
        Level: output.Critical,
    }
}
