package gosqlmap

import (
	_ "embed"
	"fmt"
	"github.com/beevik/etree"
	"github.com/yhy0/Jie/logging"
	"net/url"
	"regexp"
	"strings"
)

var dbmsErrorKeyword map[string]string

//go:embed xml/errors.xml
var errorsXml string

type SQLInfo struct {
	Payload  string
	Resquest string
	Response string
}

func init() {
	// error based 生成字典
	dbmsErrorKeyword = make(map[string]string)
	doc := etree.NewDocument()

	if err := doc.ReadFromString(errorsXml); err != nil {
		logging.Logger.Errorln(err)

	} else {
		root := doc.SelectElement("root")
		for _, dbms := range root.SelectElements("dbms") {
			for _, dbName := range dbms.Attr {
				for _, e := range dbms.SelectElements("error") {
					for _, errWord := range e.Attr {
						dbmsErrorKeyword[errWord.Value] = dbName.Value
					}
				}
			}
		}

	}
}

// todo 对 json 进行检测

// HeuristicCheckSqlInjection 启发式检测sql注入:发包尝试让Web应用报错,目的为探测该参数点是否是动态的、是否为可能的注入点
func HeuristicCheckSqlInjection(conf *ReqConf) (SQLInfo, error) {
	dynamicParams, err := checkParamIsDynamic(conf)
	if err != nil {
		return SQLInfo{}, err
	}
	if len(dynamicParams) == 0 {
		logging.Logger.Debugf("Not find dynamic Params, %s %s %s", conf.Method, conf.Url, conf.Data)
		dynamicParams, err = getAllGetParams(conf)
	}

	// 遍历每一个动态参数
	for key, value := range dynamicParams {
		// 生成payload 用于报错
		payload := genHeuristicCheckPayload()

		currentUrl := strings.Replace(conf.Url, key+"="+value[0], url.PathEscape(key+"="+value[0]+payload), 1)
		currentData := strings.Replace(conf.Data, key+"="+value[0], key+"="+value[0]+payload, 1)
		conf.Url = currentUrl
		conf.Data = currentData
		_, currentBody, err, request, response := httpDoTimeout(conf)
		if err != nil {
			logging.Logger.Errorln("HeuristicCheckSqlInjection err: ", err)
			return SQLInfo{}, err
		}
		flag := checkIsSamePage(currentBody, conf.BaseData.BaseBody)
		if flag == false {
			payloadStr := fmt.Sprintf("[method]%s [url]%s [args]%s [key]%s", conf.Method, currentUrl, currentData, key)
			logging.Logger.Debugln("[PAYLOAD] ", payloadStr)
			dbms := getDBMSBasedOnErrors(currentBody)
			if dbms != "" {
				logging.Logger.Infoln("heuristic (basic) test shows that GET parameter [", key, "]might be injectable,  possible DBMS:", dbms)
				return SQLInfo{payloadStr, request, response}, nil
			}
		}
	}
	return SQLInfo{}, nil
}

// 正则匹配出数据库类型
func getDBMSBasedOnErrors(currentBody []byte) string {
	for key, value := range dbmsErrorKeyword {
		match, _ := regexp.MatchString(key, string(currentBody))
		if match == true {
			return fmt.Sprintf("%s(%s)", value, key)
		}
	}
	return ""
}
