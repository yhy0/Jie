package conf

/**
  @author: yhy
  @since: 2023/1/4
  @desc: //TODO
**/

var DefaultHeader = map[string]string{
	"Accept-Language": "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6",
	"User-Agent":      "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36",
	"Cookie":          "rememberMe=3",
	"Accept":          "text/html,*/*;",
}

type BlackRule struct {
	Type string
	Rule string
}

// BlackLists 命中的页面直接丢弃
var BlackLists []BlackRule
