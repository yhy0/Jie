package hydra

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
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

func Postgresql(host string, port int) (string, error) {
	var err error
	var flag bool
	for _, user := range conf.UserDict["postgresql"] {
		for _, pass := range conf.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)

			flag, err = PostgresConn(host, port, user, pass)
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

func PostgresConn(host string, port int, user string, pass string) (flag bool, err error) {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", user, pass, host, port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(3 * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			return true, nil
		}
	}
	return false, err
}
