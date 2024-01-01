package xss

import (
    "fmt"
    "github.com/thoas/go-funk"
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
  @desc: 语法分析    https://github.com/w-digital-scanner/w13scan/blob/HEAD/W13SCAN/scanners/PerFile/xss.py
**/

// 默认检查的TOP参数 https://github.com/s0md3v/XSStrike/blob/f29278760453996c713af908376d6dab24e61692/core/config.py#L84C1-L91C68
var blindParams = []string{"callback", "p", "redirect", "redir", "url", "link", "goto", "debug", "_debug", "test", "get", "index", "src", "source", "file", "frame", "config", "new", "old", "var", "rurl", "return_to", "_return", "returl", "last", "text", "load", "email", "mail", "user", "username", "password", "pass", "passwd", "first_name", "last_name", "back", "href", "ref", "data", "input", "out", "net", "host", "address", "code", "auth", "userid", "auth_token", "token", "error", "keyword", "key", "q", "query", "aid", "bid", "cid", "did", "eid", "fid", "gid", "hid", "iid", "jid", "kid", "lid", "mid", "nid", "oid", "pid", "qid", "rid", "sid", "tid", "uid", "vid", "wid", "xid", "yid", "zid", "cal", "country", "x", "y", "topic", "title", "head", "higher", "lower", "width", "height", "add", "result", "log", "demo", "example", "message"}

// xssEvalAttitudes xxs 可执行的属性
var xssEvalAttitudes = []string{"onbeforeonload", "onsubmit", "ondragdrop", "oncommand", "onbeforeeditfocus", "onkeypress", "onoverflow", "ontimeupdate", "onreset", "ondragstart", "onpagehide", "onunhandledrejection", "oncopy", "onwaiting", "onselectstart", "onplay", "onpageshow", "ontoggle", "oncontextmenu", "oncanplay", "onbeforepaste", "ongesturestart", "onafterupdate", "onsearch", "onseeking", "onanimationiteration", "onbroadcast", "oncellchange", "onoffline", "ondraggesture", "onbeforeprint", "onactivate", "onbeforedeactivate", "onhelp", "ondrop", "onrowenter", "onpointercancel", "onabort", "onmouseup", "onbeforeupdate", "onchange", "ondatasetcomplete", "onanimationend", "onpointerdown", "onlostpointercapture", "onanimationcancel", "onreadystatechange", "ontouchleave", "onloadstart", "ondrag", "ontransitioncancel", "ondragleave", "onbeforecut", "onpopuphiding", "onprogress", "ongotpointercapture", "onfocusout", "ontouchend", "onresize", "ononline", "onclick", "ondataavailable", "onformchange", "onredo", "ondragend", "onfocusin", "onundo", "onrowexit", "onstalled", "oninput", "onmousewheel", "onforminput", "onselect", "onpointerleave", "onstop", "ontouchenter", "onsuspend", "onoverflowchanged", "onunload", "onmouseleave", "onanimationstart", "onstorage", "onpopstate", "onmouseout", "ontransitionrun", "onauxclick", "onpointerenter", "onkeydown", "onseeked", "onemptied", "onpointerup", "onpaste", "ongestureend", "oninvalid", "ondragenter", "onfinish", "oncut", "onhashchange", "ontouchcancel", "onbeforeactivate", "onafterprint", "oncanplaythrough", "onhaschange", "onscroll", "onended", "onloadedmetadata", "ontouchmove", "onmouseover", "onbeforeunload", "onloadend", "ondragover", "onkeyup", "onmessage", "onpopuphidden", "onbeforecopy", "onclose", "onvolumechange", "onpropertychange", "ondblclick", "onmousedown", "onrowinserted", "onpopupshowing", "oncommandupdate", "onerrorupdate", "onpopupshown", "ondurationchange", "onbounce", "onerror", "onend", "onblur", "onfilterchange", "onload", "onstart", "onunderflow", "ondragexit", "ontransitionend", "ondeactivate", "ontouchstart", "onpointerout", "onpointermove", "onwheel", "onpointerover", "onloadeddata", "onpause", "onrepeat", "onmouseenter", "ondatasetchanged", "onbegin", "onmousemove", "onratechange", "ongesturechange", "onlosecapture", "onplaying", "onfocus", "onrowsdelete"}

func Audit(in *input.CrawlResult, client *httpx.Client) {
    // 限制 xss 的content-type, 不是网页的不检查
    if funk.Contains("html", strings.ToLower(in.Resp.Header.Get("Content-Type"))) {
        return
    }

    // TODO 主动模式下 crawlergo 爬虫中爬到的参数也需要给过了
    params := ast.GetParamsFromHtml(&in.Resp.Body, in.Url)

    // html 解析 中发现的参数、爬虫发现的参数、自定义高危参数
    params = append(params, util.ExtractParameters(in.Url, in.Method, in.RequestBody, in.Headers)...)
    params = funk.UniqString(append(params, blindParams...))

    var uri string
    payloads := make(map[string]string)

    for _, param := range params {
        if util.SliceInCaseFold(param, util.ParamFilter) {
            continue
        }
        value := util.RandomLetters(6)
        payloads[param] = value
        uri += fmt.Sprintf("%s=%s&", param, value)
    }

    xssUrl := in.Url
    requestBody := in.RequestBody // 不能改变传入 in 的值，防止影响到其他插件
    if in.Method == "GET" {
        xssUrl = strings.Split(in.Url, "?")[0] + "?" + strings.TrimRight(uri, "&")
    } else {
        requestBody = strings.TrimRight(uri, "&")
    }

    res, err := client.Request(xssUrl, in.Method, requestBody, in.Headers)

    if err != nil {
        logging.Logger.Errorln(err)
        return
    }

    // 确定回显参数
    var echoParams = make(map[string]int)

    // 格式化请求
    variations, err := httpx.ParseUri(xssUrl, []byte(requestBody), in.Method, in.ContentType, in.Headers)
    if err != nil {
        if strings.Contains(err.Error(), "data is empty") {
            logging.Logger.Debugln(err.Error())
        } else {
            logging.Logger.Errorln(err.Error())
        }
        return
    }

    for index, param := range variations.Params {
        // 判断是否为不可更改的参数名，TODO 有没有更好的实现方式，不然每次都要手动写个判断 ，目前不能再 ParseUri 函数中写，不然发包时，参数会少
        if util.SliceInCaseFold(param.Name, util.ParamFilter) {
            continue
        }
        if funk.Contains(res.Body, param.Value) {
            echoParams[param.Name] = index
        }
    }

    // 有的会把输入的全部返回，这里判断一下，如果超过 20 回显参数，不测试了
    if len(echoParams) > 20 {
        return
    }

    for param, index := range echoParams {
        // 确定回显位置
        locations := ast.SearchInputInResponse(payloads[param], res.Body)

        if len(locations) == 0 {
            return
        }

        // 检测 xss
        for _, item := range locations {
            // logging.Logger.Debugln(util.StructToJsonString(item))
            if item.Type == "html" {
                if item.Details.Value.TagName == "style" {
                    payload := fmt.Sprintf("expression(a(%s))", util.RandomLetters(6))
                    resp, tpayload := request(payload, index, xssUrl, in, variations, client)

                    if resp != nil {
                        _locations := ast.SearchInputInResponse(payload, resp.Body)
                        for _, _item := range _locations {
                            if funk.Contains(_item.Details.Value.Content, payload) && _item.Details.Value.TagName == "style" {
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

                flag := util.RandomLetters(7)

                // 闭合标签测试
                payload := fmt.Sprintf("</%s><%s>", util.RandomUpper(item.Details.Value.TagName), flag)

                // 真实可能触发 xss 的 payload (没发送)
                truepayload := fmt.Sprintf("</%s><%s>", util.RandomUpper(item.Details.Value.TagName), "<svg onload=alert`1`>")

                resp, tpayload := request(payload, index, xssUrl, in, variations, client)

                if resp != nil {
                    _locations := ast.SearchInputInResponse(flag, resp.Body)
                    for _, _item := range _locations {
                        if _item.Details.Value.TagName == flag {
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
                                    Description: fmt.Sprintf("html标签可被闭合, <%s>可被闭合,可使用%s进行攻击测试", item.Details.Value.TagName, truepayload),
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
                    flag := util.RandomLetters(7)
                    payload := fmt.Sprintf("><%s ", flag)
                    truepayload := "><svg onload=alert`1`>"

                    resp, tpayload := request(payload, index, xssUrl, in, variations, client)

                    if resp != nil {
                        _locations := ast.SearchInputInResponse(flag, resp.Body)
                        for _, _item := range _locations {
                            if _item.Details.Value.TagName == flag {
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
                                        Description: fmt.Sprintf("html标签可被闭合, <%s>可被闭合,可使用%s进行攻击测试", item.Details.Value.TagName, truepayload),
                                    },
                                    Level: output.Medium,
                                }
                                break
                            }
                        }
                    }

                    // test attibutes
                    flag = util.RandomLetters(5)
                    payload = flag + "="
                    resp, tpayload = request(payload, index, xssUrl, in, variations, client)

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
                    flag := util.RandomLetters(5)
                    for _, _payload := range []string{"'", "\"", " "} {
                        payload := _payload + flag + "=" + _payload
                        truepayload := fmt.Sprintf("%s onmouseover=prompt(1)%s", _payload, _payload)

                        resp, tpayload := request(payload, index, xssUrl, in, variations, client)

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
                    flag = util.RandomLetters(7)
                    for _, _payload := range []string{"'><%s>", "\"><%s>", "><%s>"} {
                        payload := fmt.Sprintf(_payload, flag)
                        resp, tpayload := request(payload, index, xssUrl, in, variations, client)

                        if resp != nil {
                            _locations := ast.SearchInputInResponse(flag, resp.Body)
                            for _, _item := range _locations {
                                if _item.Details.Value.TagName == flag {
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
                    specialAttributes := []string{"srcdoc", "src", "action", "data", "href"} // 特殊处理属性

                    keyname := item.Details.Value.Attributes[0].Key

                    if funk.Contains(specialAttributes, keyname) {
                        flag = util.RandomLetters(7)
                        resp, tpayload := request(flag, index, xssUrl, in, variations, client)

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
                        payload := fmt.Sprintf("expression(a(%s))", util.RandomLetters(6))
                        resp, tpayload := request(payload, index, xssUrl, in, variations, client)

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
                    } else if funk.Contains(xssEvalAttitudes, strings.ToLower(keyname)) {
                        // 在任何可执行的属性中
                        payload := util.RandomLetters(6)
                        resp, tpayload := request(payload, index, xssUrl, in, variations, client)
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
                flag := util.RandomLetters(7)

                for _, _payload := range []string{"-->", "--!>"} {
                    payload := fmt.Sprintf("%s<%s>", _payload, flag)
                    truepayload := fmt.Sprintf("%s<%s>", _payload, "svg onload=alert`1`")

                    resp, tpayload := request(payload, index, xssUrl, in, variations, client)
                    if resp != nil {
                        _locations := ast.SearchInputInResponse(flag, resp.Body)
                        for _, _item := range _locations {
                            if _item.Details.Value.TagName == flag {
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
                flag := util.RandomLetters(7)
                script_tag := util.RandomUpper(item.Details.Value.TagName)

                payload := fmt.Sprintf("</%s><%s>%s</%s>", script_tag, script_tag, flag, script_tag)
                truepayload := fmt.Sprintf("</%s><%s>%s</%s>", script_tag, script_tag, "prompt(1)", script_tag)

                resp, tpayload := request(payload, index, xssUrl, in, variations, client)
                if resp != nil {
                    _locations := ast.SearchInputInResponse(flag, resp.Body)
                    for _, _item := range _locations {
                        if _item.Details.Value.Content == flag && strings.ToLower(_item.Details.Value.TagName) == strings.ToLower(script_tag) {
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
                _locations := ast.SearchInputInScript(payloads[param], source)

                for _, _item := range _locations {
                    if _item.Type == "InlineComment" {
                        flag = util.RandomLetters(5)
                        payload = fmt.Sprintf("\n;%s;//", flag)
                        truepayload = fmt.Sprintf("\n;%s;//", "prompt(1)")
                        resp, tpayload = request(payload, index, xssUrl, in, variations, client)
                        if resp != nil {
                            __locations := ast.SearchInputInResponse(flag, resp.Body)
                            for _, __item := range __locations {
                                if __item.Details.Value.TagName != "script" {
                                    continue
                                }
                                occurence := ast.SearchInputInScript(flag, __item.Details.Value.Content)
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
                        flag = util.RandomFromChoices(4, "abcdef123456")
                        payload = fmt.Sprintf("*/%s;/*", flag)
                        truepayload = fmt.Sprintf("*/%s;/*", "prompt(1)")
                        resp, tpayload = request(payload, index, xssUrl, in, variations, client)
                        if resp != nil {
                            __locations := ast.SearchInputInResponse(flag, resp.Body)
                            for _, __item := range __locations {
                                if __item.Details.Value.TagName != "script" {
                                    continue
                                }
                                occurence := ast.SearchInputInScript(flag, __item.Details.Value.Content)
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
                        flag = util.RandomLetters(6)
                        if quote == "'" || quote == "\"" {
                            payload = fmt.Sprintf("%s-%s-%s", quote, flag, quote)
                            truepayload = fmt.Sprintf("%s-%s-%s", quote, "prompt(1)", quote)
                        } else {
                            flag = util.RandomFromChoices(4, "abcdef123456")
                            payload = flag
                            truepayload = "prompt(1)"
                        }
                        resp, tpayload = request(payload, index, xssUrl, in, variations, client)
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
func request(payload string, index int, target string, in *input.CrawlResult, variations *httpx.Variations, client *httpx.Client) (*httpx.Response, string) {
    payload = variations.SetPayloadByIndex(index, target, payload, in.Method)
    var resp *httpx.Response
    var err error
    if in.Method == "GET" {
        resp, err = client.Request(payload, in.Method, "", in.Headers)
    } else {
        resp, err = client.Request(target, in.Method, payload, in.Headers)
    }

    if err != nil {
        logging.Logger.Debugln(err)
        return nil, ""
    }
    return resp, payload
}
