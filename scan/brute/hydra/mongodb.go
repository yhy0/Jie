package hydra

import (
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"net"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func Mongodb(host string, port int) (string, error) {
	_, err := MongodbUnauth(host, port)
	if err == nil {
		return "Unauthorized", nil
	}
	return "", err
}

func MongodbUnauth(host string, port int) (flag bool, err error) {
	flag = false
	senddata := []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}
	realhost := fmt.Sprintf("%s:%v", host, port)
	conn, err := net.DialTimeout("tcp", realhost, 3*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return flag, err
	}
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write(senddata)
	if err != nil {
		return flag, err
	}
	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		return flag, err
	}
	text := string(buf[0:count])
	if strings.Contains(text, "totalLinesWritten") {
		flag = true
	}
	return flag, err
}
