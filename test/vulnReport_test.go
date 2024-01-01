package test

import (
    "github.com/yhy0/Jie/pkg/output"
    "testing"
    "time"
)

/**
   @author yhy
   @since 2023/10/9
   @desc //TODO
**/

func TestVulnReport(t *testing.T) {

    go output.GenerateVulnReport("vulnerability_report.html")

    output.ReportMessageChan <- output.VulMessage{
        DataType: "Vulnerability",
        VulnData: output.VulnData{
            CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
            VulnType:    "SQL Injection",
            Target:      "https://example.com/login",
            Ip:          "192.168.1.1",
            Method:      "POST",
            Param:       "username",
            Payload:     "admin' OR '1'='1",
            CURLCommand: "curl -X POST https://example.com/login -d \"username=admin' OR '1'='1\"",
            Description: "The login page is vulnerable to SQL injection (iteration 1).",
            Request:     "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1",
            Header:      "HTTP/1.1 200 OK\nContent-Type: text/html",
            Response:    "Welcome, admin!",
        },
        Plugin: "SQLiScanner",
        Level:  "Low",
    }

    time.Sleep(1 * time.Second)
    output.ReportMessageChan <- output.VulMessage{
        DataType: "Vulnerability",
        VulnData: output.VulnData{
            CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
            VulnType:    "SQL Injection",
            Target:      "https://example.com/login",
            Ip:          "192.168.1.1",
            Method:      "POST",
            Param:       "username",
            Payload:     "admin' OR '1'='1",
            CURLCommand: "curl -X POST https://example.com/login -d \"username=admin' OR '1'='1\"",
            Description: "The login page is vulnerable to SQL injection (iteration 2).",
            Request:     "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1",
            Header:      "HTTP/1.1 200 OK\nContent-Type: text/html",
            Response:    "Welcome, admin!",
        },
        Plugin: "SQLiScanner",
        Level:  "Medium",
    }
    time.Sleep(1 * time.Second)
    output.ReportMessageChan <- output.VulMessage{
        DataType: "Vulnerability",
        VulnData: output.VulnData{
            CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
            VulnType:    "SQL Injection",
            Target:      "https://example.com/login",
            Ip:          "192.168.1.1",
            Method:      "POST",
            Param:       "username",
            Payload:     "admin' OR '1'='1",
            CURLCommand: "curl -X POST https://example.com/login -d \"username=admin' OR '1'='1\"",
            Description: "The login page is vulnerable to SQL injection (iteration 3).",
            Request:     "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1",
            Header:      "HTTP/1.1 200 OK\nContent-Type: text/html",
            Response:    "Welcome, admin!",
        },
        Plugin: "SQLiScanner",
        Level:  "High",
    }
    time.Sleep(1 * time.Second)
    output.ReportMessageChan <- output.VulMessage{
        DataType: "Vulnerability",
        VulnData: output.VulnData{
            CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
            VulnType:    "SQL Injection",
            Target:      "https://example.com/login",
            Ip:          "192.168.1.1",
            Method:      "POST",
            Param:       "username",
            Payload:     "admin' OR '1'='1",
            CURLCommand: "curl -X POST https://example.com/login -d \"username=admin' OR '1'='1\"",
            Description: "The login page is vulnerable to SQL injection (iteration 4).",
            Request:     "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1",
            Header:      "HTTP/1.1 200 OK\nContent-Type: text/html",
            Response:    "Welcome, admin!",
        },
        Plugin: "SQLiScanner",
        Level:  "Critical",
    }

    time.Sleep(1 * time.Second)
    close(output.ReportMessageChan)
}
