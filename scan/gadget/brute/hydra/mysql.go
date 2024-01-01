package hydra

import (
    "database/sql"
    "fmt"
    _ "github.com/go-sql-driver/mysql"
    "strings"
    "time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func Mysql(host string, port int) (string, error) {
    var err error
    var flag bool
    for _, user := range UserDict["mysql"] {
        for _, pass := range Passwords {
            pass = strings.Replace(pass, "{user}", user, -1)
            flag, err = MysqlConn(host, port, user, pass)
            if flag == true && err == nil {
                return fmt.Sprintf("[%s:%s]", user, pass), nil
            }
            if CheckErrs(err) {
                return "", err
            }
        }
    }
    return "", err
}

func MysqlConn(host string, port int, user string, pass string) (flag bool, err error) {
    dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", user, pass, host, port, 3*time.Second)
    db, err := sql.Open("mysql", dataSourceName)
    defer db.Close()
    if err == nil {
        db.SetConnMaxLifetime(3 * time.Second)
        db.SetConnMaxIdleTime(3 * time.Second)
        db.SetMaxIdleConns(0)
        err = db.Ping()
        if err == nil {
            return true, nil
        }
    }
    return false, err
}
