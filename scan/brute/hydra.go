package brute

import (
	"fmt"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/scan/brute/hydra"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2022/7/1
  @desc: //TODO
**/

func Hydra(host string, port int, service string) {
	var (
		msg  string
		err  error
		flag bool
	)

	service = strings.ToLower(service)

	switch service {
	case "redis":
		msg, err = hydra.Redis(host, port)
	case "ftp":
		msg, err = hydra.FTP(host, port)
	case "memcached":
		msg, err = hydra.Memcached(host, port)
	case "ldap", "rsh-spx", "ssh":
		msg, err = hydra.SSH(host, port)
	case "mysql":
		msg, err = hydra.Mysql(host, port)
	case "oracle", "oracle-tns":
		msg, err = hydra.Oracle(host, port)
	case "mongod", "mongodb":
		msg, err = hydra.Mongodb(host, port)
	case "postgresql":
		msg, err = hydra.Postgresql(host, port)
	case "ms-sql-s":
		msg, err = hydra.SQLServer(host, port)
	case "ms-wbt-server", "ssl/ms-wbt-server":
		msg, err = hydra.RDP(host, port)
	case "microsoft-ds":
		msg, err = hydra.SMB(host, port)
	default:
		flag = true
	}

	if flag {
		logging.Logger.Debugf("Service mismatch: %s %d", service, port)
		return
	}

	payload := fmt.Sprintf("%s %s %d %s ", service, host, port, msg)
	if err != nil {
		logging.Logger.Debugf("%s %s", payload, err)
		return
	}

	logging.Logger.Infof(payload)

	output.OutChannel <- output.VulMessage{
		DataType: "host_vul",
		Plugin:   "Hydra " + service,
		VulData: output.VulData{
			CreateTime: time.Now().Format("2006-01-02 15:04:05"),
			Target:     host,
			Ip:         host,
			Payload:    payload,
		},
		Level: output.Critical,
	}

	return
}
