package structs

import (
	xray_structs "github.com/yhy0/Jie/scan/pocs_yml/xray/structs"
	"net/http"
	"strings"
)

var (
	CeyeApi                  string
	CeyeDomain               string
	ReversePlatformType      xray_structs.ReverseType
	DnslogCNGetDomainRequest *http.Request
	DnslogCNGetRecordRequest *http.Request
)

func InitReversePlatform(domain, api string) {
	if api != "" && domain != "" && strings.HasSuffix(domain, ".ceye.io") {
		CeyeApi = api
		CeyeDomain = domain
		ReversePlatformType = xray_structs.ReverseType_Ceye
	} else {
		ReversePlatformType = xray_structs.ReverseType_DnslogCN
		// 设置请求相关参数
		DnslogCNGetDomainRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getdomain.php", nil)
		DnslogCNGetRecordRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getrecords.php", nil)

	}
}
