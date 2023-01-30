package pocs_go

import (
	"fmt"
	"github.com/yhy0/Jie/pkg/output"
	brute2 "github.com/yhy0/Jie/scan/brute"
	"github.com/yhy0/Jie/scan/pocs_go/ThinkPHP"
	"github.com/yhy0/Jie/scan/pocs_go/jboss"
	jenkins2 "github.com/yhy0/Jie/scan/pocs_go/jenkins"
	"github.com/yhy0/Jie/scan/pocs_go/phpunit"
	seeyon2 "github.com/yhy0/Jie/scan/pocs_go/seeyon"
	"github.com/yhy0/Jie/scan/pocs_go/shiro"
	tomcat2 "github.com/yhy0/Jie/scan/pocs_go/tomcat"
	weblogic2 "github.com/yhy0/Jie/scan/pocs_go/weblogic"
	"github.com/yhy0/Jie/scan/pocs_go/yongyou/nc"
	"net/url"
	"time"
)

func PocCheck(technologies []string, target string, finalURL string, ip string) {
	vulnerability := false
	var (
		plugin  string
		payload string
	)

	for _, wt := range technologies {
		tech := wt[2 : len(wt)-2]
		switch tech {
		case "Shiro":
			key := shiro.CVE_2016_4437(finalURL)
			if key != "" {
				vulnerability = true
				plugin = "Shiro"
				payload = key
			}
		case "Apache Tomcat":
			username, password := brute2.TomcatBrute(target)
			if username != "" {
				vulnerability = true
				plugin = "Apache Tomcat"
				payload = fmt.Sprintf("brute-Tomcat|%s:%s", username, password)
			}
			var HOST string
			if host, err := url.Parse(target); err == nil {
				HOST = host.Host
			}

			if tomcat2.CVE_2020_1938(HOST) {
				vulnerability = true
				plugin = "Apache Tomcat"
				payload += "exp-Tomcat|CVE_2020_1938 \n"
			}
			if tomcat2.CVE_2017_12615(target) {
				vulnerability = true
				plugin = "Apache Tomcat"
				payload += "exp-Tomcat|CVE_2017_12615 \n"

			}
		case "Basic": // todo 这里还没有匹配到
			username, password, _ := brute2.Basic_brute(target)
			if username != "" {
				vulnerability = true
				plugin = "Basic"
				payload = fmt.Sprintf("brute-basic|%s:%s", username, password)
			}
		case "Weblogic":
			username, password := brute2.WeblogicBrute(target)
			if username != "" {
				vulnerability = true
				plugin = "Weblogic"
				payload = fmt.Sprintf("brute-Weblogic|%s:%s \n", username, password)
			}
			if weblogic2.CVE_2014_4210(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2014_4210 \n"
			}
			if weblogic2.CVE_2017_3506(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2017_3506 \n"
			}
			if weblogic2.CVE_2017_10271(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2017_10271 \n"
			}
			if weblogic2.CVE_2018_2894(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2018_2894 \n"
			}
			if weblogic2.CVE_2019_2725(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2019_2725 \n"
			}
			if weblogic2.CVE_2019_2729(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2019_2729 \n"
			}
			if weblogic2.CVE_2020_2883(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2020_2883 \n"
			}
			if weblogic2.CVE_2020_14882(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2020_14882 \n"
			}
			if weblogic2.CVE_2020_14883(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2020_14883 \n"
			}
			if weblogic2.CVE_2021_2109(target) {
				vulnerability = true
				plugin = "Weblogic"
				payload += "exp-Weblogic|CVE_2021_2109\n"
			}
		case "Jboss", "Jboss application server 7", "Jboss-as", "Jboss-eap", "Jboss web", "Jboss application server":
			if jboss.CVE_2017_12149(target) {
				vulnerability = true
				plugin = "Jboss"
				payload += "exp-Jboss|CVE_2017_12149| \n"
			}
			username, password := brute2.JbossBrute(target)
			if username != "" {
				vulnerability = true
				plugin = "Jboss"
				payload += fmt.Sprintf("brute-Jboss|%s:%s", username, password)
			}
		//case "json":
		//	fastjsonRceType := fastjson.Check(target, finalURL)
		//	if fastjsonRceType != "" {
		//		technologies = append(technologies, fmt.Sprintf("exp-FastJson|%s", fastjsonRceType))
		//	}
		case "Jenkins":
			if jenkins2.Unauthorized(target) {
				vulnerability = true
				plugin = "Jenkins"
				payload += "exp-Jenkins|Unauthorized script \n"
			}
			if jenkins2.CVE_2018_1000110(target) {
				vulnerability = true
				plugin = "Jenkins"
				payload += "exp-Jenkins|CVE_2018_1000110 \n"
			}
			if jenkins2.CVE_2018_1000861(target) {
				vulnerability = true
				plugin = "Jenkins"
				payload += "exp-Jenkins|CVE_2018_1000861 \n"
			}
			if jenkins2.CVE_2019_10003000(target) {
				vulnerability = true
				plugin = "Jenkins"
				payload += "exp-Jenkins|CVE_2019_10003000 \n"
			}
		case "ThinkPHP", "ThinkPHP-yfcmf":
			if ThinkPHP.RCE(target) {
				vulnerability = true
				plugin = "ThinkPHP"
				payload = "exp-ThinkPHP \n"
			}
		case "phpunit":
			if phpunit.CVE_2017_9841(target) {
				vulnerability = true
				plugin = "phpunit"
				payload = "exp-phpunit|CVE_2017_9841 \n"
			}
		case "seeyon":
			if seeyon2.SeeyonFastjson(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|SeeyonFastjson \n"
			}
			if seeyon2.SessionUpload(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|SessionUpload \n"
			}
			if seeyon2.CNVD_2019_19299(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|CNVD_2019_19299 \n"
			}
			if seeyon2.CNVD_2020_62422(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|CNVD_2020_62422 \n"
			}
			if seeyon2.CNVD_2021_01627(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|CNVD_2021_01627 \n"
			}
			if seeyon2.CreateMysql(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|CreateMysql \n"
			}
			if seeyon2.DownExcelBeanServlet(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|DownExcelBeanServlet \n"
			}
			if seeyon2.GetSessionList(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|GetSessionList \n"
			}
			if seeyon2.InitDataAssess(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|InitDataAssess \n"
			}
			if seeyon2.ManagementStatus(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|ManagementStatus \n"
			}
			if seeyon2.BackdoorScan(target) {
				vulnerability = true
				plugin = "seeyon"
				payload += "exp-seeyon|Backdoor \n"
			}
		case "loginpage":
			username, password, loginurl := brute2.Admin_brute(finalURL)
			if loginurl != "" {
				vulnerability = true
				plugin = "LoginPage"
				payload += fmt.Sprintf("brute-admin|%s:%s", username, password)
			}
		case "用友NC":
			if nc.Scan(target) {
				vulnerability = true
				plugin = "用友 NC"
				payload = "用友 NC|反序列化"
			}
			//case "sunlogin":
			//	if sunlogin.SunloginRCE(target) {
			//		technologies = append(technologies, "exp-Sunlogin|RCE")
			//	}
			//case "zabbixsaml":
			//	if zabbix.CVE_2022_23131(target) {
			//		technologies = append(technologies, "exp-ZabbixSAML|bypass-login")
			//	}
			//case "spring", "spring env", "spring-boot", "spring-framework", "spring-boot-admin":
			//	if Springboot.CVE_2022_22965(finalURL) {
			//		technologies = append(technologies, "exp-Spring4Shell|CVE_2022_22965")
			//	}
			//case "springgateway":
			//	if Springboot.CVE_2022_22947(target) {
			//		technologies = append(technologies, "exp-SpringGateway|CVE_2022_22947")
			//	}
			//case "gitLab":
			//	if gitlab.CVE_2021_22205(target) {
			//		technologies = append(technologies, "exp-gitlab|CVE_2021_22205")
			//	}
		}
		//if checklog4j {
		//	if log4j.Check(target, finalURL) {
		//		technologies = append(technologies, "exp-log4j|JNDI RCE")
		//	}
		//}
	}

	if vulnerability {

		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   plugin,
			VulData: output.VulData{
				CreateTime: time.Now().Format("2006-01-02 15:04:05"),
				Target:     target,
				Ip:         ip,
				Payload:    payload,
			},
			Level: output.Critical,
		}
	}
}
