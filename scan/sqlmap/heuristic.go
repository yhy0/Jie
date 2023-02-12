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

	// 匹配参数的值为整形的情况
	regex := regexp.MustCompile(`^[0-9]+$`)

	var err error
	var flag bool

	if len(sql.DynamicPara) == 0 {
		flag = true
	}
	// 检测是否存咋转型的参数 	转型参数代表无法注入
	for pos, p := range sql.Variations.Params {
		// 如果检测动态参数结果为空，则进行暴力检测，每个参数都检测;若不为空，则只对动态参数进行检测
		if !flag && funk.Contains(sql.DynamicPara, p.Name) {
			flag = true
		}

		if flag {
			var payload string
			if regex.MatchString(p.Value) {
				payload = sql.Variations.SetPayloadByIndex(p.Index, sql.Url, randomTestString+randString, sql.Method)
			} else {
				payload = sql.Variations.SetPayloadByIndex(p.Index, sql.Url, randomTestString+strconv.Itoa(util.RandNumber(0, 9999)), sql.Method)
			}

			logging.Logger.Debugln(payload)

			var res *httpx.Response
			if sql.Method == "GET" {
				res, err = httpx.Request(payload, sql.Method, "", false, sql.Headers)
			} else {
				res, err = httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)
			}

			time.Sleep(time.Millisecond * 500)

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
