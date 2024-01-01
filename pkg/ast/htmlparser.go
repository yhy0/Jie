package ast

import (
    "golang.org/x/net/html"
    "strings"
)

/**
  @author: yhy
  @since: 2023/3/15
  @desc: 处理 html
**/

// GetParamsFromHtml 获取变量 TODO 有待优化
func GetParamsFromHtml(htmlStr *string, t string) []string {
    var result []string
    var inScript bool // 用于判断当前是否在<script>标签中
    var scriptContent string
    parse := html.NewTokenizer(strings.NewReader(*htmlStr))
    for {
        tokenType := parse.Next()
        if tokenType == html.ErrorToken {
            break
        }
        if tokenType == html.StartTagToken {
            token := parse.Token()
            tagname := strings.ToLower(token.Data)
            if tagname == "script" { // 获取 js 中的 变量
                inScript = true
            } else if tagname == "input" { // 获取 input 标签 中的
                var name string
                for _, attr := range token.Attr {
                    if attr.Key == "name" {
                        name = attr.Val
                        break
                    }
                }
                if name != "" {
                    result = append(result, name)
                }
            }

        } else if tokenType == html.EndTagToken {
            token := parse.Token()
            tagname := strings.ToLower(token.Data)
            if tagname == "script" {
                inScript = false
                result = append(result, AnalyseJs(scriptContent, t)...)
                scriptContent = ""
            }
        } else if tokenType == html.TextToken && inScript {
            // 如果标记是<script>标签的开头，将inScript变量设置为true
            // 如果标记是<script>标签的结尾，将inScript变量设置为false
            // 如果inScript变量为true，将标记的内容附加到一个字符串中
            scriptContent += string(parse.Text())
        }
    }

    return result
}

func getAttr(z *html.Tokenizer, attrName string) string {
    for {
        key, val, more := z.TagAttr()
        if string(key) == attrName {
            return string(val)
        }
        if !more {
            break
        }
    }
    return ""
}
