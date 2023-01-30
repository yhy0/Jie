package gosqlmap

import (
	"github.com/yhy0/Jie/logging"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

var source = rand.New(rand.NewSource(time.Now().UnixNano()))

// CheckConnect 连接性检测
func CheckConnect(conf *ReqConf) (bool, error) {
	statusCode, body, err, _, _ := httpDoTimeout(conf)
	if err != nil {
		logging.Logger.Errorln("CheckConnect error while connect to:", conf.Url, "error:", err)
		return false, err
	}
	if statusCode == 200 {
		conf.BaseData = SinglePageBaseData{
			BaseStatusCode: statusCode,
			BaseBodyLength: len(body),
			BaseBody:       body,
		}
		return true, nil
	}
	return false, nil
}

// CheckStability 稳定性检测
func CheckStability(conf *ReqConf) (bool, error) {
	secondStatusCode, secondBody, err, _, _ := httpDoTimeout(conf)
	isStability := false
	if err != nil {
		logging.Logger.Errorln("CheckStability error while check stability to:", conf.Url, "error:", err)
		return false, err
	}
	if secondStatusCode == conf.BaseData.BaseStatusCode && checkIsSamePage(secondBody, conf.BaseData.BaseBody) {
		isStability = true
	} else {
		// 再尝试一次
		thirdStatusCode, thirdBody, err, _, _ := httpDoTimeout(conf)
		if err != nil {
			logging.Logger.Errorln("checkStability error while check stability to:", conf.Url, "error:", err)
			return false, err
		}
		if thirdStatusCode == conf.BaseData.BaseStatusCode && checkIsSamePage(thirdBody, conf.BaseData.BaseBody) {
			isStability = true
		}
	}
	return isStability, nil
}

func getAllGetParams(conf *ReqConf) (paramMap url.Values, err error) {
	if conf.Data == "" {
		targetUrl, err := url.Parse(conf.Url)
		if err != nil {
			return nil, err
		}
		paramMap, err = url.ParseQuery(targetUrl.RawQuery)
		if err != nil {
			return nil, err
		}
	} else {
		paramMap, err = url.ParseQuery(conf.Data)
		if err != nil {
			return nil, err
		}
	}

	return paramMap, nil
}

func checkParamIsDynamic(conf *ReqConf) (url.Values, error) {
	paramMap, err := getAllGetParams(conf)
	if err != nil {
		return nil, err
	}
	dynamicList := make(url.Values)
	// 遍历参数 替换payload尝试...
	if len(paramMap) == 0 {
		logging.Logger.Debugln("Not found any param: ", conf.Url)
	} else {
		// 遍历每一个参数
		for key, value := range paramMap {
			currentUrl := strings.Replace(conf.Url, key+"="+value[0], key+"="+genRandom4Num(source), 1)
			currentData := strings.Replace(conf.Data, key+"="+value[0], key+"="+genRandom4Num(source), 1)
			conf.Url = currentUrl
			conf.Data = currentData

			_, currentBody, err, _, _ := httpDoTimeout(conf)
			if err != nil {
				logging.Logger.Errorln("checkParamIsDynamic err: ", err)
			}
			flag := checkIsSamePage(currentBody, conf.BaseData.BaseBody)
			if flag == false {
				logging.Logger.Infof("[%s] %s GET parameter %s appears to be dynamic", conf.Method, conf.Url, key)
				dynamicList[key] = value
			}
		}
	}
	return dynamicList, nil
}

// CheckWaf payload 替换掉第一个参数  waf条件： samePage为假 && 页面包含关键词
func CheckWaf(conf *ReqConf) (bool, error) {
	logging.Logger.Infoln("Checking if the target is protected by some kind of WAF/IPS")
	paramMap, err := getAllGetParams(conf)
	logging.Logger.Infoln("Testing parameters is dynamic")
	if err != nil {
		return false, err
	}
	for key, value := range paramMap {
		currentUrl := strings.Replace(conf.Url, key+"="+value[0], key+"="+IPS_WAF_CHECK_PAYLOAD, 1)
		currentData := strings.Replace(conf.Data, key+"="+value[0], key+"="+IPS_WAF_CHECK_PAYLOAD, 1)
		conf.Url = currentUrl
		conf.Data = currentData

		_, currentBody, err, _, _ := httpDoTimeout(conf)
		for _, wafKeyword := range WAF_CHECK_KEYWORD {
			if strings.Contains(string(currentBody), wafKeyword) {
				logging.Logger.Warning("\"heuristics detected that the target is protected by some kind of WAF/IPS")
				logging.Logger.Warning("stop to continue with further target testing")
				return true, nil
			}
		}
		if err != nil {
			logging.Logger.Errorln("checkWaf err: ", err)
		}
		break
	}
	return false, nil
}
