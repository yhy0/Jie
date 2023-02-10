package sqlmap

import (
	"fmt"
	"github.com/yhy0/Jie/logging"
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"regexp"
	"strconv"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/8
  @desc: 基于报错注入
**/

func (sql *Sqlmap) checkErrorBased(pos int) {
	// 匹配参数的值为整形的情况
	regex := regexp.MustCompile(`^[0-9]+$`)

	for index, p := range sql.Variations.Params {
		if index == pos {
			var payload string
			if regex.MatchString(p.Value) {
				payload = sql.Variations.SetPayloadByindex(p.Index, sql.Url, util.RandLetters(4)+getErrorBasedPreCheckPayload(), sql.Method)
			} else {
				payload = sql.Variations.SetPayloadByindex(p.Index, sql.Url, strconv.Itoa(util.RandNumber(99999, 9999999))+getErrorBasedPreCheckPayload(), sql.Method)
			}
			sql.checkError(payload, p)
		}
	}
}

func (sql *Sqlmap) checkError(payload string, param httpx.Param) {
	res, err := httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)

	if err != nil {
		logging.Logger.Debugln("尝试检测 Error-Based SQL Injection Payload 失败")
		return
	}

	for DBMS, regexps := range DbmsErrors {
		if util.MatchAnyOfRegexp(regexps, res.ResponseDump) {
			logging.Logger.Debugf("检测到数据库报错信息")

			JieOutput.OutChannel <- JieOutput.VulMessage{
				DataType: "web_vul",
				Plugin:   "SQL Injection",
				VulData: JieOutput.VulData{
					CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
					Target:      sql.Url,
					Ip:          "",
					Param:       param.Name,
					Request:     res.RequestDump,
					Response:    res.ResponseDump,
					Payload:     payload,
					Description: fmt.Sprintf("ERROR-Based SQL Injection: [%v:%v] Guess DBMS: %v", param.Name, param.Value, DBMS),
				},
				Level: JieOutput.Critical,
			}

			// todo 考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入

			logging.Logger.Debugln("参数: " + param.Name + " 存在报错注入")
			return
		}
	}
	logging.Logger.Debugln("参数: " + param.Name + " 不存在报错注入")
}
