package hydra

import (
	"errors"
	"fmt"
	"github.com/stacktitan/smb/smb"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/util"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2022/7/4
  @desc: //TODO
**/

func SMB(host string, port int) (string, error) {
	var err error
	var flag bool
	for _, user := range conf.UserDict["smb"] {
		for _, pass := range conf.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err = doWithTimeOut(host, port, user, pass)
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

func SmblConn(host string, port int, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	options := smb.Options{
		Host:        host,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}

func doWithTimeOut(host string, port int, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(host, port, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(3 * time.Second):
		return false, errors.New("time out")
	}
}
