package reverse

import (
	"encoding/json"
	"fmt"
	"github.com/yhy0/Jie/pkg/protocols/http"
	"net/url"
	"time"
)

type Reverse struct {
	Domain             string
	Token              string
	Url                string
	Flag               string
	Ip                 string
	IsDomainNameServer bool
}

// New use ceye api
func New(domain string, flag string) *Reverse {
	if domain == "" {
		domain = "fkuior.ceye.io" //修改过的，建议重新写
	}
	urlStr := fmt.Sprintf("http://%s.%s", flag, domain)
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Flag:               flag,
		Url:                u.String(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func Check(reverse *Reverse, timeout int64) bool {
	if reverse.Token == "" {
		return false
	}
	// 延迟 x 秒获取结果
	time.Sleep(time.Second * time.Duration(timeout))
	// http://api.ceye.io/v1/records?token=0e43a818cb3cd0d1326ae6fb147b96b0&type=dns&filter=123456
	//check dns
	verifyUrl := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", reverse.Token, reverse.Flag)
	if GetReverseResp(verifyUrl) {
		return true
	} else {
		//	check request
		verifyUrl = fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=http&filter=%s", reverse.Token, reverse.Flag)
		if GetReverseResp(verifyUrl) {
			return true
		}
	}
	return false
}

type Meta1 struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type ReverseBody struct {
	Meta Meta1 `json:"meta"`
	Data []interface{}
}

func GetReverseResp(verifyUrl string) bool {
	res, err := http.Request(verifyUrl, "GET", "", false, nil)
	if err != nil {
		return false
	}
	rev := ReverseBody{}
	json.Unmarshal([]byte(res.Body), &rev)
	if len(rev.Data) > 0 {
		return true
	}
	return false
}
