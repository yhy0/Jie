package nuclei

import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/pkg/util"
)

/**
  @author: yhy
  @since: 2023/2/2
  @desc: //TODO
**/
// 当识别不到具体指纹时，使用的默认模板
var defaultTemplates = []string{
	"cnvd/",
	"cves/",
	"default-logins/",
	"dns/azure-takeover-detection.yaml",
	"dns/elasticbeantalk-takeover.yaml",
	"exposed-panels/",
	"exposures/",
	"file/keys/",
	"file/logs/django-framework-exceptions.yaml",
	"file/logs/python-app-sql-exceptions.yaml",
	"file/logs/ruby-on-rails-framework-exceptions.yaml",
	"file/logs/spring-framework-exceptions.yaml",
	"file/logs/suspicious-sql-error-messages.yaml",
	"file/perl/",
	"file/php/",
	"file/python/",
	"file/xss/",
	"fuzzing/adminer-panel-fuzz.yaml",
	"fuzzing/linux-lfi-fuzzing.yaml",
	"fuzzing/mdb-database-file.yaml",
	"fuzzing/wordpress-weak-credentials.yaml",
	"iot/brother-unauthorized-access.yaml",
	"iot/iotawatt-app-exposure.yaml",
	"iot/lutron-iot-default-login.yaml",
	"iot/qvisdvr-deserialization-rce.yaml",
	"iot/stem-audio-table-private-keys.yaml",
	"iot/targa-camera-lfi.yaml",
	"iot/targa-camera-ssrf.yaml",
	"miscellaneous/aws-ecs-container-agent-tasks.yaml",
	"miscellaneous/dir-listing.yaml",
	"miscellaneous/htaccess-config.yaml",
	"miscellaneous/ntlm-directories.yaml",
	"miscellaneous/xml-schema-detect.yaml",
	"network/clickhouse-unauth.yaml",
	"network/exposed-adb.yaml",
	"network/exposed-redis.yaml",
	"network/exposed-zookeeper.yaml",
	"network/ftp-weak-credentials.yaml",
	"network/mongodb-unauth.yaml",
	"network/sap-router-info-leak.yaml",
	"network/tidb-unauth.yaml",
	"takeovers/",
	"vulnerabilities/",
}

// 公共模板，每个都会扫
var publiTemplates = []string{
	"dns/azure-takeover-detection.yaml",
	"dns/elasticbeantalk-takeover.yaml",
	"exposed-panels/", // 一些服务的默认登录页面
	"exposures/",
	"file/electron/node-integration-enabled.yaml",
	"file/keys/",
	"file/xss/",
	"fuzzing/adminer-panel-fuzz.yaml",
	"fuzzing/linux-lfi-fuzzing.yaml",
	"fuzzing/mdb-database-file.yaml",
	"fuzzing/wordpress-weak-credentials.yaml",
	"iot/brother-unauthorized-access.yaml",
	"iot/iotawatt-app-exposure.yaml",
	"iot/lutron-iot-default-login.yaml",
	"iot/qvisdvr-deserialization-rce.yaml",
	"iot/stem-audio-table-private-keys.yaml",
	"iot/targa-camera-lfi.yaml",
	"iot/targa-camera-ssrf.yaml",

	"miscellaneous/aws-ecs-container-agent-tasks.yaml",
	"miscellaneous/dir-listing.yaml",
	"miscellaneous/htaccess-config.yaml",
	"miscellaneous/ntlm-directories.yaml",
	"miscellaneous/xml-schema-detect.yaml",

	"network/clickhouse-unauth.yaml",
	"network/exposed-adb.yaml",
	"network/exposed-redis.yaml",
	"network/exposed-zookeeper.yaml",
	"network/ftp-weak-credentials.yaml",
	"network/mongodb-unauth.yaml",
	"network/sap-router-info-leak.yaml",
	"network/tidb-unauth.yaml",
	"takeovers/",
}

// 根据指纹来进行选择模板  todo 还需要细化
func generateTemplates(fingerprints []string) (templates []string, tags []string) {
	for _, fingerprint := range fingerprints {
		if util.Contains(fingerprint, "struts") {
			tags = append(tags, "struts")
		} else if util.Contains(fingerprint, "apache") {
			tags = append(tags, "apache")
		} else if util.Contains(fingerprint, "airflow") {
			tags = append(tags, "airflow")
		} else if util.Contains(fingerprint, "oracle") {
			tags = append(tags, "oracle")
		} else if util.Contains(fingerprint, "activemq") {
			tags = append(tags, "activemq")
		} else if util.Contains(fingerprint, "avantfax") {
			tags = append(tags, "avantfax")
		} else if util.Contains(fingerprint, "bigip") {
			tags = append(tags, "bigip")
		} else if util.Contains(fingerprint, "bitrix") {
			tags = append(tags, "bitrix")
		} else if util.Contains(fingerprint, "bomgar") {
			tags = append(tags, "bomgar")
		} else if util.Contains(fingerprint, "cacti") {
			tags = append(tags, "cacti")
		} else if util.Contains(fingerprint, "cisco") {
			tags = append(tags, "cisco")
		} else if util.Contains(fingerprint, "coldfusion") {
			tags = append(tags, "coldfusion")
		} else if util.Contains(fingerprint, "confluence") {
			tags = append(tags, "confluence")
		} else if util.Contains(fingerprint, "dedecms") {
			tags = append(tags, "dedecms")
		} else if util.Contains(fingerprint, "dell") {
			tags = append(tags, "dell")
		} else if util.Contains(fingerprint, "drupal") {
			tags = append(tags, "drupal")
		} else if util.Contains(fingerprint, "fortinet") {
			tags = append(tags, "fortinet")
		} else if util.Contains(fingerprint, "gitlab") {
			tags = append(tags, "gitlab")
		} else if util.Contains(fingerprint, "glpi") {
			tags = append(tags, "glpi")
		} else if util.Contains(fingerprint, "gocd") {
			tags = append(tags, "gocd")
		} else if util.Contains(fingerprint, "grafana") {
			tags = append(tags, "grafana")
		} else if util.Contains(fingerprint, "grav") {
			tags = append(tags, "grav")
		} else if util.Contains(fingerprint, "hikvision") {
			tags = append(tags, "hikvision")
		} else if util.Contains(fingerprint, "itop") {
			tags = append(tags, "itop")
		} else if util.Contains(fingerprint, "jboss") {
			tags = append(tags, "jboss")
		} else if util.Contains(fingerprint, "jenkins") {
			tags = append(tags, "jenkins")
		} else if util.Contains(fingerprint, "jetty") {
			tags = append(tags, "jetty")
		} else if util.Contains(fingerprint, "jira") {
			tags = append(tags, "jira")
		} else if util.Contains(fingerprint, "joomla") {
			tags = append(tags, "joomla")
		} else if util.Contains(fingerprint, "keycloak") {
			tags = append(tags, "keycloak")
		} else if util.Contains(fingerprint, "kibana") {
			tags = append(tags, "kibana")
		} else if util.Contains(fingerprint, "lansweeper") {
			tags = append(tags, "lansweeper")
		} else if util.Contains(fingerprint, "laravel") {
			tags = append(tags, "laravel")
		} else if util.Contains(fingerprint, "liferay") {
			tags = append(tags, "liferay")
		} else if util.Contains(fingerprint, "lotus") {
			tags = append(tags, "lotus")
			templates = append(templates, "cves/2005/CVE-2005-2428.yaml")
		} else if util.Contains(fingerprint, "magento") {
			tags = append(tags, "magento")
		} else if util.Contains(fingerprint, "magmi") {
			tags = append(tags, "magmi")
		} else if util.Contains(fingerprint, "metabase") {
			tags = append(tags, "metabase")
		} else if util.Contains(fingerprint, "Micro-Focus") {
			templates = append(templates, "default-logins/UCMDB/")
			templates = append(templates, "cves/2020/CVE-2020-11853.yaml")
			templates = append(templates, "cves/2020/CVE-2020-11854.yaml")
		} else if util.Contains(fingerprint, "exchange") {
			tags = append(tags, "exchange")
		} else if util.Contains(fingerprint, "moodle") {
			tags = append(tags, "moodle")
		} else if util.Contains(fingerprint, "movable") {
			tags = append(tags, "movable")
		} else if util.Contains(fingerprint, "netgear") {
			tags = append(tags, "netgear")
		} else if util.Contains(fingerprint, "netsweeper") {
			tags = append(tags, "netsweeper")
		} else if util.Contains(fingerprint, "ofbiz") {
			tags = append(tags, "ofbiz")
		} else if util.Contains(fingerprint, "openam") {
			tags = append(tags, "openam")
		} else if util.Contains(fingerprint, "openemr") {
			tags = append(tags, "openemr")
		} else if util.Contains(fingerprint, "opensis") {
			tags = append(tags, "opensis")
		} else if util.Contains(fingerprint, "pentaho") {
			tags = append(tags, "pentaho")
		} else if util.Contains(fingerprint, "phpmyadmin") {
			tags = append(tags, "phpmyadmin")
		} else if util.Contains(fingerprint, "prometheus") {
			tags = append(tags, "prometheus")
		} else if util.Contains(fingerprint, "rseenet") {
			tags = append(tags, "rseenet")
		} else if util.Contains(fingerprint, "rabbitmq") {
			templates = append(templates, "default-logins/rabbitmq/")
		} else if util.Contains(fingerprint, "rconfig") {
			tags = append(tags, "rconfig")
		} else if util.Contains(fingerprint, "ruijie") {
			templates = append(templates, "cnvd/CNVD-2021-17369.yaml")
			templates = append(templates, "vulnerabilities/other/ruijie-networks-lfi.yaml")
			templates = append(templates, "vulnerabilities/other/ruijie-networks-rce.yaml")
			templates = append(templates, "exposures/configs/ruijie-information-disclosure.yaml")
			templates = append(templates, "cnvd/CNVD-2020-56167.yaml")
			templates = append(templates, "exposures/configs/ruijie-phpinfo.yaml")
		} else if util.Contains(fingerprint, "samsung") {
			templates = append(templates, "default-logins/samsung/")
			templates = append(templates, "vulnerabilities/samsung/")
		} else if util.Contains(fingerprint, "sap") {
			templates = append(templates, "cves/2020/CVE-2020-6287.yaml")
			templates = append(templates, "cves/2017/CVE-2017-12637.yaml")
			templates = append(templates, "cves/2020/CVE-2020-6308.yaml")
			templates = append(templates, "exposed-panels/fiorilaunchpad-logon.yaml")
			templates = append(templates, "exposed-panels/hmc-hybris-panel.yaml")
			templates = append(templates, "exposed-panels/sap-netweaver-portal.yaml")
			templates = append(templates, "exposed-panels/sap-hana-xsengine-panel.yaml")
			templates = append(templates, "misconfiguration/sap/")
			templates = append(templates, "network/sap-router.yaml")
			templates = append(templates, "network/sap-router-info-leak.yaml")
		} else if util.Contains(fingerprint, "sitecore") {
			templates = append(templates, "exposed-panels/sitecore-login.yaml")
			templates = append(templates, "vulnerabilities/sitecore-pre-auth-rce.yaml")
			templates = append(templates, "misconfiguration/sitecore-debug-page.yaml")
		} else if util.Contains(fingerprint, "solarwinds") {
			templates = append(templates, "cves/2018/CVE-2018-19386.yaml")
			templates = append(templates, "cves/2020/CVE-2020-10148.yaml")
			templates = append(templates, "default-logins/solarwinds/")
		} else if util.Contains(fingerprint, "solr") {
			tags = append(tags, "solr")
		} else if util.Contains(fingerprint, "springboot") {
			tags = append(tags, "springboot")
		} else if util.Contains(fingerprint, "squirrelmail") {
			tags = append(tags, "squirrelmail")
		} else if util.Contains(fingerprint, "symfony") {
			tags = append(tags, "symfony")
		} else if util.Contains(fingerprint, "terramaster") {
			tags = append(tags, "terramaster")
		} else if util.Contains(fingerprint, "thinfinity") {
			tags = append(tags, "thinfinity")
		} else if util.Contains(fingerprint, "tikiwiki") {
			tags = append(tags, "tikiwiki")
		} else if util.Contains(fingerprint, "tomcat") {
			tags = append(tags, "tomcat")
		} else if util.Contains(fingerprint, "vbulletin") {
			templates = append(templates, "cves/2019/CVE-2019-16759.yaml")
			templates = append(templates, "cves/2020/CVE-2020-12720.yaml")
		} else if util.Contains(fingerprint, "vmware") {
			tags = append(tags, "vmware")
		} else if util.Contains(fingerprint, "weblogic") {
			tags = append(tags, "weblogic")
		} else if util.Contains(fingerprint, "tomcat") {
			tags = append(tags, "tomcat")
		} else if util.Contains(fingerprint, "wordpress") {
			tags = append(tags, "wordpress")
		} else if util.Contains(fingerprint, "yii") {
			tags = append(tags, "yii")
		} else if util.Contains(fingerprint, "zabbix") {
			tags = append(tags, "zabbix")
		} else if util.Contains(fingerprint, "zimbra") {
			tags = append(tags, "zimbra")
		} else if util.Contains(fingerprint, "oracle") {
			tags = append(tags, "oracle")
		} else if util.Contains(fingerprint, "thinkphp") {
			tags = append(tags, "thinkphp")
		} else if util.Contains(fingerprint, "tongda") {
			tags = append(tags, "tongda")
		} else if util.Contains(fingerprint, "php") {
			templates = append(templates, "file/php/")
		} else if util.Contains(fingerprint, "perl") {
			templates = append(templates, "file/perl/")
		} else if util.Contains(fingerprint, "python") {
			templates = append(templates, "file/python/")
		}

	}

	if len(tags) == 0 && len(templates) == 0 {
		templates = defaultTemplates
	} else {
		templates = funk.UniqString(append(templates, publiTemplates...))
	}

	return

}
