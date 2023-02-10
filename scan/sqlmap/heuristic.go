package sqlmap

import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"regexp"
	"strconv"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/7
  @desc: 提取自 Yakit 插件: 启发式SQL注入检测
	 todo 应该获取全部参数，比如有的 post 请求，但 url 中也有参数
**/

// HeuristicCheckSqlInjection 启发式检测 sql 注入, 先过滤出有效参数，即不存在转型的参数, 之后在进行闭合检测
func (sql *Sqlmap) HeuristicCheckSqlInjection() {
	if sql.Method != "GET" && sql.Method != "POST" {
		logging.Logger.Debugln("请求方法不支持检测")
		return
	}

	// 检测返回包中是否存在转型错误, 存在的话，表明当前参数被强制转型，这也意味着这个参数无法被注入，没必要在进行后续检测。放在前面减少无用的请求
	for _, value := range FormatExceptionStrings {
		if funk.Contains(sql.TemplateBody, value) {
			logging.Logger.Debugln("模板请求参数存在转型错误，请提供正常的请求参数")
			return
		}
	}

	// 避免POST请求出现参数重名，记录参数位置

	var injectableParamsPos []int
	randomTestString := getErrorBasedPreCheckPayload()
	randString := util.RandFromChoices(4, randomTestString)
	cast := false

	variations, err := httpx.ParseUri(sql.Url, []byte(sql.Resp.Body), sql.Method, sql.ContentType, sql.Headers)
	if err != nil {
		return
	}

	// todo 这里不对, variations 值是不断变换的，这应该会导致参数的 payload 出现异常，应该吧？
	// todo 还有就是  sql.Variations.SetPayloadByindex(param.Index, sql.Url, positivePayload, sql.Method) 这返回的是个什么？
	sql.Variations = variations

	logging.Logger.Debugf("总共测试参数共%d个", len(variations.Params))

	// 匹配参数的值为整形的情况
	regex := regexp.MustCompile(`^[0-9]+$`)

	for pos, p := range sql.Variations.Params {
		var payload string
		if funk.Any(regex.FindAllString(p.Value, -1)) {
			payload = sql.Variations.SetPayloadByindex(p.Index, sql.Url, randomTestString+randString, sql.Method)
		} else {
			payload = sql.Variations.SetPayloadByindex(p.Index, sql.Url, randomTestString+strconv.Itoa(util.RandNumber(0, 9999)), sql.Method)
		}

		res, err := httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)
		time.Sleep(0.5)

		if err != nil {
			logging.Logger.Debugf("checkIfInjectable Fuzz请求出错")
			continue
		}

		for _, value := range FormatExceptionStrings {
			if funk.Contains(res.Body, value) {
				cast = true
				logging.Logger.Debugf(sql.Url + " 参数: " + p.Name + " 因数值转型无法注入")
				break
			}
		}

		if cast {
			cast = false
			continue
		}

		injectableParamsPos = append(injectableParamsPos, pos)
		logging.Logger.Debugf(sql.Url + " 参数: " + p.Name + " 未检测到转型")
	}

	if len(injectableParamsPos) == 0 {
		logging.Logger.Debugf("无可注入参数")
		return
	}

	for _, pos := range injectableParamsPos {
		sql.checkSqlInjection(pos)
	}
}

func (sql *Sqlmap) checkSqlInjection(pos int) {
	sql.checkErrorBased(pos)

	closeType, lineBreak := sql.checkCloseType(pos)
	if closeType == -1 {
		for index, param := range sql.Variations.Params {
			if index == pos {
				logging.Logger.Debugf("参数:%v未检测到闭合边界", param.Name)
				return
			}

		}
	}

	sql.checkTimeBasedBlind(pos, closeType, lineBreak)

	//checkBoolBased(pos, freq) //TODO:bool based
	sql.checkUnionBased(pos, closeType, lineBreak)
	//checkStackedInjection
}
