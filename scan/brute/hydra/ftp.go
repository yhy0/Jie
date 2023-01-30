package hydra

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/util"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func FTP(host string, port int) (string, error) {
	var err error
	var flag bool

	_, err = FtpConn(host, port, "anonymous", "")

	if err == nil {
		return "Unauthorized", nil
	}

	for _, user := range conf.UserDict["ftp"] {
		for _, pass := range conf.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err = FtpConn(host, port, user, pass)
			if flag == true && err == nil {
				return fmt.Sprintf("[%s:%s]", user, pass), nil
			}

			if util.CheckErrs(err) {
				return "", err
			}
		}
	}

	return "", err
}

func FtpConn(host string, port int, user string, pass string) (bool, error) {
	Host, Port, Username, Password := host, port, user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), 3*time.Second)
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			defer conn.Logout()
			return true, nil

		}
	}
	return false, err
}
