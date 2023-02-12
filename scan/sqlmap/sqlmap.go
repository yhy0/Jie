package sqlmap

import (
	_ "embed"
	"github.com/antlabs/strsim"
	"github.com/beevik/etree"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"strconv"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/6
  @desc: //TODO
**/

//go:embed xml/errors.xml
var errorsXml string

var (
	SimilarityRatio = 0.9  // 页面相似度
	UpperRatioBound = 0.98 // 上边界
	LowerRatioBound = 0.02 // 下边界

	DiffTolerance = 0.05 // 容差

	CloseType = map[int]string{0: `'`, 1: `"`, 2: ``, 3: `')`, 4: `")`}

	// FormatExceptionStrings 用于检测格式错误的字符串
	FormatExceptionStrings = []string{
		"Type mismatch", "Error converting", "Please enter a", "Conversion failed",
		"String or binary data would be truncated", "Failed to convert", "unable to interpret text value",
		"Input string was not in a correct format", "System.FormatException", "java.lang.NumberFormatException",
		"ValueError: invalid literal", "TypeMismatchException", "CF_SQL_INTEGER", "CF_SQL_NUMERIC",
		"for CFSQLTYPE ", "cfqueryparam cfsqltype", "InvalidParamTypeException",
		"Invalid parameter type", "Attribute validation error for tag", "is not of type numeric",
		"<cfif Not IsNumeric(", "invalid input syntax for integer", "invalid input syntax for type",
		"invalid number", "character to number conversion error", "unable to interpret text value",
		"String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ",
		"InvalidDataException", "Arguments are of the wrong type",
	}

	// HeuristicCheckAlphabet 用于启发式检查的字母表
	HeuristicCheckAlphabet = []string{`"`, `'`, `)`, `(`, `,`, `.`}

	// DbmsErrors 用于报错检查的字典
	DbmsErrors = map[string][]string{}
)

type Sqlmap struct {
	OriginalBody string // 原始请求页面
	TemplateBody string // 经过处理去除动态部分的模板页面
	TemplateCode int
	DynamicPara  []string // 动态参数
	Method       string
	Url          string
	RequestBody  string
	Headers      map[string]string
	ContentType  string
	Variations   *httpx.Variations
}

func init() {
	// error based 生成字典
	DbmsErrors = make(map[string][]string)
	doc := etree.NewDocument()

	if err := doc.ReadFromString(errorsXml); err != nil {
		logging.Logger.Errorln(err)
	} else {
		root := doc.SelectElement("root")
		for _, dbms := range root.SelectElements("dbms") {
			for _, dbName := range dbms.Attr {
				for _, e := range dbms.SelectElements("error") {
					for _, errWord := range e.Attr {
						DbmsErrors[errWord.Value] = append(DbmsErrors[errWord.Value], dbName.Value)
					}
				}
			}
		}

	}
}

func Scan(c *input.CrawlResult) {
	//waf 只判断作为提示信息 不做进一步操作 如果检出存在注入 则可以考虑附加信息
	if len(c.Waf) > 0 {
		logging.Logger.Warnf("heuristics detected that the target is protected by some kind of WAF/IPS(%+v)", c.Waf)
	}

	//做一些前置检查 避免无意义的后续检测
	if c.Resp.StatusCode == 404 {
		logging.Logger.Warnln(c.Target, " 原始请求资源不存在(404) ")
		return
	}

	if len(c.Param) == 0 {
		logging.Logger.Warnln(c.Target, " 无可供注入参数")
		return
	}

	// todo 参数预处理， 动态参数检测，模板页面

	//开始启发式sql注入检测
	sql := &Sqlmap{
		Url:          c.Url,
		OriginalBody: c.Resp.Body,
		Method:       c.Method,
		Headers:      c.Headers,
		ContentType:  c.ContentType,
		RequestBody:  c.RequestBody,
	}

	sql.TemplateCode = c.Resp.StatusCode

	variations, err := httpx.ParseUri(sql.Url, []byte(sql.RequestBody), sql.Method, sql.ContentType, sql.Headers)
	if err != nil {
		logging.Logger.Debugln(err)
		return
	}
	sql.Variations = variations

	logging.Logger.Debugf("总共测试参数共%d个 %+v", len(variations.Params), variations.Params)

	if !sql.check() {
		logging.Logger.Infoln(c.Target, " 动态页面检测失败")
		return
	}

	sql.HeuristicCheckSqlInjection()

}

// check 检测动态参数
func (sql *Sqlmap) check() bool {
	res, err := httpx.Request(sql.Url, sql.Method, sql.RequestBody, false, sql.Headers)

	if err != nil {
		return false
	}

	// todo 这种方式感觉不太好，有待优化
	if strsim.Compare(res.Body, sql.OriginalBody) < SimilarityRatio {
		logging.Logger.Debugln("检测到动态页面 ")
		d1, d2 := funk.Difference(strings.Split(res.Body, " "), strings.Split(sql.OriginalBody, " "))
		// 去除动态部分
		for _, v := range d1.([]string) {
			sql.TemplateBody = strings.ReplaceAll(sql.OriginalBody, v, "")
		}

		for _, v := range d2.([]string) {
			sql.TemplateBody = strings.ReplaceAll(sql.OriginalBody, v, "")
		}
	}

	for _, p := range sql.Variations.Params {
		payload := sql.Variations.SetPayloadByIndex(p.Index, sql.Url, strconv.Itoa(util.RandNumber(0, 9999)), sql.Method)

		logging.Logger.Debugln(payload)

		if sql.Method == "GET" {
			res, err = httpx.Request(payload, sql.Method, "", false, sql.Headers)
		} else {
			res, err = httpx.Request(sql.Url, sql.Method, payload, false, sql.Headers)
		}

		if err != nil {
			continue
		}

		if strsim.Compare(res.Body, sql.OriginalBody) < SimilarityRatio {
			sql.DynamicPara = append(sql.DynamicPara, p.Name)
			logging.Logger.Debugln("检测到动态参数 ", p.Name)
		}
		time.Sleep(time.Millisecond * 500)
	}

	return true
}
