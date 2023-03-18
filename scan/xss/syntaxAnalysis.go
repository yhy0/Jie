package xss

import (
	"fmt"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/ast"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/logging"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2023/3/14
  @desc: 语法分析	https://github.com/w-digital-scanner/w13scan/blob/HEAD/W13SCAN/scanners/PerFile/xss.py
	//TODO 使用无头浏览器进一步发送 payload 进行 弹窗 确认 漏洞存在
**/

func Audit(in *input.CrawlResult) {
	// katanna 爬虫中已经解析过参数了，这里应该没必要再次解析了？等把爬虫中的参数传过来就没必要了，现在爬虫不会传参数(现在传的只是从 url?xx 获取的)
	params := ast.GetParamsFromHtml(&in.Resp.Body)

	logging.Logger.Debugln(in.Url, params)
	// html 解析 中发现的参数、爬虫发现的参数、自定义高危参数
	params = funk.UniqString(append(params, in.Param...))

	var uri string
	payloads := make(map[string]string)

	for _, param := range params {
		value := util.RandString(6)
		payloads[param] = value
		uri += fmt.Sprintf("%s=%s&", param, value)
	}

	xssUrl := in.Url
	if in.Method == "GET" {
		xssUrl = strings.Split(in.Url, "?")[0] + "?" + strings.TrimRight(uri, "&")
	} else {
		in.RequestBody = strings.TrimRight(uri, "&")
	}

	res, err := httpx.Request(xssUrl, in.Method, in.RequestBody, false, in.Headers)

	// // 限制xss的content-type
	//html_type := strings.ToLower(in.Resp.Header.Get("Content-Type"))
	//
	//if funk.Contains("html", html_type) {
	//	return
	//}

	if err != nil {
		logging.Logger.Errorln(err)
		return
	}

	// 确定回显参数
	var iterdatas = make(map[string]int)

	// 格式化请求
	variations, err := httpx.ParseUri(xssUrl, []byte(in.RequestBody), in.Method, in.ContentType, in.Headers)
	if err != nil {
		logging.Logger.Errorln(err)
		return
	}

	for index, param := range variations.Params {
		if funk.Contains(res.Body, param.Value) {
			iterdatas[param.Name] = index
		}
	}

	for param, index := range iterdatas {
		// 确定回显位置
		locations := ast.SearchInputInResponse(payloads[param], res.Body)

		if len(locations) == 0 {
			return
		}

		// 检测 xss
		for _, item := range locations {
			//logging.Logger.Debugln(util.StructToJsonString(item))
			if item.Type == "html" {
				if item.Details.Value.Tagname == "style" {
					payload := fmt.Sprintf("expression(a(%s))", util.RandLetters(6))
					resp, tpayload := request(payload, index, xssUrl, in, variations)

					if resp != nil {
						_locations := ast.SearchInputInResponse(payload, resp.Body)
						for _, _item := range _locations {
							if funk.Contains(_item.Details.Value.Content, payload) && _item.Details.Value.Tagname == "style" {
								output.OutChannel <- output.VulMessage{
									DataType: "web_vul",
									Plugin:   "XSS",
									VulnData: output.VulnData{
										CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
										Target:      in.Url,
										Method:      in.Method,
										Param:       param,
										Response:    resp.Body,
										Payload:     tpayload,
										Description: "IE下可执行的表达式 expression(alert(1))",
									},
									Level: output.Medium,
								}
								break
							}
						}
					}
				}

				flag := util.RandString(7)

				// 闭合标签测试
				payload := fmt.Sprintf("</%s><%s>", util.RandomUpper(item.Details.Value.Tagname), flag)

				// 真实可能触发 xss 的 payload (没发送)
				truepayload := fmt.Sprintf("</%s><%s>", util.RandomUpper(item.Details.Value.Tagname), "<svg onload=alert`1`>")

				resp, tpayload := request(payload, index, xssUrl, in, variations)

				if resp != nil {
					_locations := ast.SearchInputInResponse(flag, resp.Body)
					for _, _item := range _locations {
						if _item.Details.Value.Tagname == flag {
							output.OutChannel <- output.VulMessage{
								DataType: "web_vul",
								Plugin:   "XSS",
								VulnData: output.VulnData{
									CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
									Target:      in.Url,
									Method:      in.Method,
									Param:       param,
									Response:    resp.Body,
									Payload:     tpayload,
									Description: fmt.Sprintf("html标签可被闭合, <%s>可被闭合,可使用%s进行攻击测试", item.Details.Value.Tagname, truepayload),
								},
								Level: output.Medium,
							}
							break
						}
					}
				}

			} else if item.Type == "attibute" {
				if item.Details.Value.Content == "key" {
					// test html
					flag := util.RandString(7)
					payload := fmt.Sprintf("><%s ", flag)
					truepayload := "><svg onload=alert`1`>"

					resp, tpayload := request(payload, index, xssUrl, in, variations)

					if resp != nil {
						_locations := ast.SearchInputInResponse(flag, resp.Body)
						for _, _item := range _locations {
							if _item.Details.Value.Tagname == flag {
								output.OutChannel <- output.VulMessage{
									DataType: "web_vul",
									Plugin:   "XSS",
									VulnData: output.VulnData{
										CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
										Target:      in.Url,
										Method:      in.Method,
										Param:       param,
										Response:    resp.Body,
										Payload:     tpayload,
										Description: fmt.Sprintf("html标签可被闭合, <%s>可被闭合,可使用%s进行攻击测试", item.Details.Value.Tagname, truepayload),
									},
									Level: output.Medium,
								}
								break
							}
						}
					}

					// test attibutes
					flag = util.RandString(5)
					payload = flag + "="
					resp, tpayload = request(payload, index, xssUrl, in, variations)

					if resp != nil {
						_locations := ast.SearchInputInResponse(flag, resp.Body)
						for _, _item := range _locations {
							for _, v := range _item.Details.Value.Attributes {
								if v.Key == flag {
									output.OutChannel <- output.VulMessage{
										DataType: "web_vul",
										Plugin:   "XSS",
										VulnData: output.VulnData{
											CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
											Target:      in.Url,
											Method:      in.Method,
											Param:       param,
											Response:    resp.Body,
											Payload:     payload,
											Description: "可以自定义类似 'onmouseover=prompt(1)'的标签事件",
										},
										Level: output.Medium,
									}
									break
								}
							}

						}
					}

				} else {
					// test attibutes
					flag := util.RandString(5)
					for _, _payload := range []string{"'", "\"", " "} {
						payload := _payload + flag + "=" + _payload
						truepayload := fmt.Sprintf("%s onmouseover=prompt(1)%s", _payload, _payload)

						resp, tpayload := request(payload, index, xssUrl, in, variations)

						if resp != nil {
							_locations := ast.SearchInputInResponse(flag, resp.Body)
							for _, _item := range _locations {
								for _, v := range _item.Details.Value.Attributes {
									if v.Key == flag {
										output.OutChannel <- output.VulMessage{
											DataType: "web_vul",
											Plugin:   "XSS",
											VulnData: output.VulnData{
												CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
												Target:      in.Url,
												Method:      in.Method,
												Param:       param,
												Response:    resp.Body,
												Payload:     tpayload,
												Description: fmt.Sprintf("引号可被闭合,可使用其他事件造成xss, 可使用 %s 进行攻击测试", truepayload),
											},
											Level: output.Medium,
										}
										break
									}
								}

							}
						}

					}

					// test html
					flag = util.RandString(7)
					for _, _payload := range []string{"'><%s>", "\"><%s>", "><%s>"} {
						payload := fmt.Sprintf(_payload, flag)
						resp, tpayload := request(payload, index, xssUrl, in, variations)

						if resp != nil {
							_locations := ast.SearchInputInResponse(flag, resp.Body)
							for _, _item := range _locations {
								if _item.Details.Value.Tagname == flag {
									output.OutChannel <- output.VulMessage{
										DataType: "web_vul",
										Plugin:   "XSS",
										VulnData: output.VulnData{
											CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
											Target:      in.Url,
											Method:      in.Method,
											Param:       param,
											Response:    resp.Body,
											Payload:     tpayload,
											Description: fmt.Sprintf("html标签可被闭合,可使用 %s 进行攻击测试", fmt.Sprintf(_payload, "svg onload=alert`1`")),
										},
										Level: output.Medium,
									}
									break
								}

							}
						}

					}

					// 针对特殊属性进行处理
					specialAttributes := []string{"srcdoc", "src", "action", "data", "href"} //特殊处理属性

					keyname := item.Details.Value.Attributes[0].Key

					if funk.Contains(specialAttributes, keyname) {
						flag = util.RandString(7)
						resp, tpayload := request(flag, index, xssUrl, in, variations)

						if resp != nil {
							_locations := ast.SearchInputInResponse(flag, resp.Body)
							for _, _item := range _locations {
								if len(_item.Details.Value.Attributes) > 0 && _item.Details.Value.Attributes[0].Key == keyname && _item.Details.Value.Attributes[0].Val == flag {
									truepayload := flag

									if funk.Contains(specialAttributes, _item.Details.Value.Attributes[0].Key) {
										truepayload = "javascript:alert(1)"
									}

									output.OutChannel <- output.VulMessage{
										DataType: "web_vul",
										Plugin:   "XSS",
										VulnData: output.VulnData{
											CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
											Target:      in.Url,
											Method:      in.Method,
											Param:       param,
											Response:    resp.Body,
											Payload:     tpayload,
											Description: fmt.Sprintf("值可控,%s的值可控，可能被恶意攻击,payload:%s", keyname, truepayload),
										},
										Level: output.Medium,
									}
									break
								}

							}
						}

					} else if keyname == "style" {
						payload := fmt.Sprintf("expression(a(%s))", util.RandLetters(6))
						resp, tpayload := request(payload, index, xssUrl, in, variations)

						if resp != nil {
							_locations := ast.SearchInputInResponse(payload, resp.Body)
							for _, _item := range _locations {
								if funk.Contains(util.StructToJsonString(_item.Details), payload) && len(_item.Details.Value.Attributes) > 0 && _item.Details.Value.Attributes[0].Key == keyname {
									output.OutChannel <- output.VulMessage{
										DataType: "web_vul",
										Plugin:   "XSS",
										VulnData: output.VulnData{
											CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
											Target:      in.Url,
											Method:      in.Method,
											Param:       param,
											Response:    resp.Body,
											Payload:     tpayload,
											Description: "IE下可执行的表达式 payload:expression(alert(1))",
										},
										Level: output.Medium,
									}
									break
								}
							}
						}
					} else if funk.Contains(conf.XssEvalAttitudes, strings.ToLower(keyname)) {
						// 在任何可执行的属性中
						payload := util.RandString(6)
						resp, tpayload := request(payload, index, xssUrl, in, variations)
						if resp != nil {
							_locations := ast.SearchInputInResponse(payload, resp.Body)
							for _, _item := range _locations {
								if len(_item.Details.Value.Attributes) > 0 && _item.Details.Value.Attributes[0].Val == payload && strings.ToLower(_item.Details.Value.Attributes[0].Key) == strings.ToLower(keyname) {
									output.OutChannel <- output.VulMessage{
										DataType: "web_vul",
										Plugin:   "XSS",
										VulnData: output.VulnData{
											CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
											Target:      in.Url,
											Method:      in.Method,
											Param:       param,
											Response:    resp.Body,
											Payload:     tpayload,
											Description: fmt.Sprintf("事件的值可控, %s的值可控，可能被恶意攻击", keyname),
										},
										Level: output.Medium,
									}
									break
								}
							}
						}
					}
				}

			} else if item.Type == "comment" {
				flag := util.RandString(7)

				for _, _payload := range []string{"-->", "--!>"} {
					payload := fmt.Sprintf("%s<%s>", _payload, flag)
					truepayload := fmt.Sprintf("%s<%s>", _payload, "svg onload=alert`1`")

					resp, tpayload := request(payload, index, xssUrl, in, variations)
					if resp != nil {
						_locations := ast.SearchInputInResponse(flag, resp.Body)
						for _, _item := range _locations {
							if _item.Details.Value.Tagname == flag {
								output.OutChannel <- output.VulMessage{
									DataType: "web_vul",
									Plugin:   "XSS",
									VulnData: output.VulnData{
										CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
										Target:      in.Url,
										Method:      in.Method,
										Param:       param,
										Response:    resp.Body,
										Payload:     tpayload,
										Description: fmt.Sprintf("html注释可被闭合 测试payload: %s", truepayload),
									},
									Level: output.Medium,
								}
								break
							}
						}
					}
				}

			} else if item.Type == "script" {
				// test html
				flag := util.RandString(7)
				script_tag := util.RandomUpper(item.Details.Value.Tagname)

				payload := fmt.Sprintf("</%s><%s>%s</%s>", script_tag, script_tag, flag, script_tag)
				truepayload := fmt.Sprintf("</%s><%s>%s</%s>", script_tag, script_tag, "prompt(1)", script_tag)

				resp, tpayload := request(payload, index, xssUrl, in, variations)
				if resp != nil {
					_locations := ast.SearchInputInResponse(flag, resp.Body)
					for _, _item := range _locations {
						if _item.Details.Value.Content == flag && strings.ToLower(_item.Details.Value.Tagname) == strings.ToLower(script_tag) {
							output.OutChannel <- output.VulMessage{
								DataType: "web_vul",
								Plugin:   "XSS",
								VulnData: output.VulnData{
									CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
									Target:      in.Url,
									Method:      in.Method,
									Param:       param,
									Response:    resp.Body,
									Payload:     tpayload,
									Description: fmt.Sprintf("可以新建script标签执行任意代码 测试payload: %s", truepayload),
								},
								Level: output.Medium,
							}
							break
						}
					}
				}

				// js 语法树分析反射

				source := item.Details.Value.Content
				_locations := ast.SearchInputInResponse(payloads[param], source)

				for _, _item := range _locations {
					if _item.Type == "InlineComment" {
						flag = util.RandString(5)
						payload = fmt.Sprintf("\n;%s;//", flag)
						truepayload = fmt.Sprintf("\n;%s;//", "prompt(1)")
						resp, tpayload = request(payload, index, xssUrl, in, variations)
						if resp != nil {
							__locations := ast.SearchInputInResponse(flag, resp.Body)
							for _, __item := range __locations {
								if __item.Details.Value.Tagname != "script" {
									continue
								}
								occurence := ast.SearchInputInResponse(flag, __item.Details.Value.Content)
								for _, _output := range occurence {
									if funk.Contains(_output.Details.Value.Content, flag) && _output.Type == "ScriptIdentifier" {
										output.OutChannel <- output.VulMessage{
											DataType: "web_vul",
											Plugin:   "XSS",
											VulnData: output.VulnData{
												CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
												Target:      in.Url,
												Method:      in.Method,
												Param:       param,
												Response:    resp.Body,
												Payload:     tpayload,
												Description: fmt.Sprintf("js单行注释可被\\n bypass, 测试payload: %s", truepayload),
											},
											Level: output.Medium,
										}
										break
									}
								}

							}
						}
					} else if _item.Type == "BlockComment" {
						flag = util.RandFromChoices(4, "abcdef123456")
						payload = fmt.Sprintf("*/%s;/*", flag)
						truepayload = fmt.Sprintf("*/%s;/*", "prompt(1)")
						resp, tpayload = request(payload, index, xssUrl, in, variations)
						if resp != nil {
							__locations := ast.SearchInputInResponse(flag, resp.Body)
							for _, __item := range __locations {
								if __item.Details.Value.Tagname != "script" {
									continue
								}
								occurence := ast.SearchInputInResponse(flag, __item.Details.Value.Content)
								for _, _output := range occurence {
									if funk.Contains(_output.Details.Value.Content, flag) && _output.Type == "ScriptIdentifier" {
										output.OutChannel <- output.VulMessage{
											DataType: "web_vul",
											Plugin:   "XSS",
											VulnData: output.VulnData{
												CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
												Target:      in.Url,
												Method:      in.Method,
												Param:       param,
												Response:    resp.Body,
												Payload:     tpayload,
												Description: fmt.Sprintf("js单行注释可被*/ bypass, 测试payload: %s", truepayload),
											},
											Level: output.Medium,
										}
										break
									}
								}
							}
						}
					} else if _item.Type == "ScriptIdentifier" {
						output.OutChannel <- output.VulMessage{
							DataType: "web_vul",
							Plugin:   "XSS",
							VulnData: output.VulnData{
								CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
								Target:      in.Url,
								Method:      in.Method,
								Param:       param,
								Response:    resp.Body,
								Payload:     tpayload,
								Description: "可直接执行任意js命令, ScriptIdentifier类型 测试payloadL: prompt(1);//",
							},
							Level: output.Medium,
						}
					} else if _item.Type == "ScriptLiteral" {
						quote := string(_item.Details.Value.Content[0])
						flag = util.RandString(6)
						if quote == "'" || quote == "\"" {
							payload = fmt.Sprintf("%s-%s-%s", quote, flag, quote)
							truepayload = fmt.Sprintf("%s-%s-%s", quote, "prompt(1)", quote)
						} else {
							flag = util.RandFromChoices(4, "abcdef123456")
							payload = flag
							truepayload = "prompt(1)"
						}
						resp, tpayload = request(payload, index, xssUrl, in, variations)
						resp2 := ""
						if resp != nil {
							__locations := ast.SearchInputInResponse(payload, resp.Body)
							for _, __item := range __locations {
								if funk.Contains(__item.Details.Value.Content, payload) && __item.Type == "script" {
									resp2 = __item.Details.Value.Content
								}

							}
						}

						if resp2 == "" {
							continue
						}

						occurence := ast.SearchInputInResponse(flag, resp2)
						for _, _output := range occurence {
							if funk.Contains(_output.Details.Value.Content, flag) && _output.Type == "ScriptIdentifier" {
								output.OutChannel <- output.VulMessage{
									DataType: "web_vul",
									Plugin:   "XSS",
									VulnData: output.VulnData{
										CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
										Target:      in.Url,
										Method:      in.Method,
										Param:       param,
										Response:    resp.Body,
										Payload:     tpayload,
										Description: fmt.Sprintf("script脚本内容可被任意设置, 测试payload: %s", truepayload),
									},
									Level: output.Medium,
								}
								break
							}
						}

					}
				}

			}

		}
	}

}

// 设置对应参数的值为 payload, http 请求测试
func request(payload string, index int, target string, in *input.CrawlResult, variations *httpx.Variations) (*httpx.Response, string) {
	payload = variations.SetPayloadByIndex(index, target, payload, in.Method)

	var resp *httpx.Response
	var err error
	if in.Method == "GET" {
		resp, err = httpx.Request(payload, in.Method, "", false, in.Headers)
	} else {
		resp, err = httpx.Request(target, in.Method, payload, false, in.Headers)
	}

	if err != nil {
		logging.Logger.Debugln(err)
		return nil, ""
	}
	return resp, payload
}
