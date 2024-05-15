package util

import (
    "encoding/json"
    "encoding/xml"
    "errors"
    "net/url"
    "strings"
)

/**
   @author yhy
   @since 2024/5/14
   @desc 用于提取 url 中的信息
**/

func GetReqParameters(method, contentType string, target *url.URL, body []byte) ([]string, error) {
    // 提取查询参数的名称  有的即使是 POST 请求，url请求路径中也会存在参数，所以这里全部都要提取
    var paramNames []string
    queryParams := target.Query()
    for paramName := range queryParams {
        paramNames = append(paramNames, paramName)
    }
    
    if strings.ToUpper(method) == "POST" {
        if strings.Contains(contentType, "application/x-www-form-urlencoded") {
            // 解析 POST 请求的请求体
            postParams, err := url.ParseQuery(string(body))
            if err != nil {
                return nil, err
            }
            for paramName := range postParams {
                paramNames = append(paramNames, paramName)
            }
        } else if strings.Contains(contentType, "application/json") {
            var jsonData map[string]interface{}
            err := json.Unmarshal(body, &jsonData)
            if err != nil {
                return nil, err
            }
            for paramName := range jsonData {
                paramNames = append(paramNames, paramName)
            }
        } else if strings.Contains(contentType, "application/xml") {
            var xmlData map[string]interface{}
            err := xml.Unmarshal(body, &xmlData)
            if err != nil {
                return nil, err
            }
            for paramName := range xmlData {
                paramNames = append(paramNames, paramName)
            }
        }
    }
    
    return paramNames, nil
}

func GetResParameters(contentType string, body []byte) ([]string, error) {
    // 提取查询参数的名称  有的即使是 POST 请求，url请求路径中也会存在参数，所以这里全部都要提取
    var paramNames []string
    
    if strings.Contains(contentType, "application/x-www-form-urlencoded") {
        // 解析 POST 请求的请求体
        postParams, err := url.ParseQuery(string(body))
        if err != nil {
            return nil, err
        }
        for paramName := range postParams {
            paramNames = append(paramNames, paramName)
        }
    } else if strings.Contains(contentType, "application/json") {
        var jsonData map[string]interface{}
        err := json.Unmarshal(body, &jsonData)
        if err != nil {
            return nil, err
        }
        for paramName := range jsonData {
            paramNames = append(paramNames, paramName)
        }
    } else if strings.Contains(contentType, "application/xml") {
        var xmlData map[string]interface{}
        err := xml.Unmarshal(body, &xmlData)
        if err != nil {
            return nil, err
        }
        for paramName := range xmlData {
            paramNames = append(paramNames, paramName)
        }
    } else {
        return nil, errors.New("unsupported content type")
    }
    
    return paramNames, nil
}
