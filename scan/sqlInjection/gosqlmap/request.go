package gosqlmap

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
)

type ReqConf struct {
	Url      string
	Method   string
	Data     string
	Headers  map[string]string
	BaseData SinglePageBaseData
}

type SinglePageBaseData struct {
	BaseBody       []byte
	BaseBodyLength int
	BaseStatusCode int
}

var UPPER_RATIO_BOUND = 0.98
var LOWER_RATIO_BOUND = 0.02
var DIFF_TOLERANCE = 0.05

// httpDoTimeout 提供http 请求，返回 响应码 body 和 错误
func httpDoTimeout(conf *ReqConf) (int, []byte, error, string, string) {
	res, err := http.Request(conf.Url, conf.Method, conf.Data, false, conf.Headers)
	if err != nil {
		return 0, nil, err, "", ""
	}
	return res.StatusCode, []byte(res.Body), nil, res.RequestDump, res.ResponseDump
}
