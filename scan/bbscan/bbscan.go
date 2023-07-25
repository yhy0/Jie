package bbscan

import (
	"github.com/antlabs/strsim"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/Jie/scan/swagger"
	"github.com/yhy0/logging"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
*

	@author: yhy
	@since: 2022/9/17
	@desc: //TODO

*
*/
var (
	RegTag           *regexp.Regexp
	RegStatus        *regexp.Regexp
	RegContentType   *regexp.Regexp
	RegContentTypeNo *regexp.Regexp
)

type Rule struct {
	Tag    string // 文本内容
	Status string // 状态码
	Type   string // 返回的 ContentType
	TypeNo string // 不可能返回的 ContentType
	Root   bool   // 是否为一级目录
}

var Rules map[string]*Rule

type Page struct {
	isBackUpPath bool
	isBackUpPage bool
	title        string
	locationUrl  string
	is302        bool
	is403        bool
}

var (
	path404 = "/file_not_support"
)

func init() {
	Rules = make(map[string]*Rule)
	RegTag, _ = regexp.Compile(`{tag="(.*?)"}`)
	RegStatus, _ = regexp.Compile(`{status=(\d{3})}`)
	RegContentType, _ = regexp.Compile(`{type="(.*?)"}`)
	RegContentTypeNo, _ = regexp.Compile(`{type_no="(.*?)"}`)

	// 返回[]fs.DirEntry
	entries, err := rulesFiles.ReadDir("rules")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		rulesContent, err := rulesFiles.ReadFile("rules/" + entry.Name())
		if err != nil {
			logging.Logger.Errorf("BBscan error , read %s error: %v", entry.Name(), err)
			continue
		}

		for _, str := range util.CvtLines(string(rulesContent)) {
			if strings.Index(str, "/") != 0 {
				continue
			}
			var rule Rule

			tag := RegTag.FindStringSubmatch(str)
			status := RegStatus.FindStringSubmatch(str)
			contentType := RegContentType.FindStringSubmatch(str)
			contentTypeNo := RegContentTypeNo.FindStringSubmatch(str)

			if len(tag) > 0 {
				rule.Tag = tag[1]
			}

			if len(status) > 0 {
				rule.Status = status[1]
			}
			if len(contentType) > 0 {
				rule.Type = contentType[1]
			}
			if len(contentTypeNo) > 0 {
				rule.TypeNo = contentTypeNo[1]
			}

			if util.Contains(str, "{root_only}") {
				rule.Root = true
			}
			path := util.Trim(strings.Split(str, " ")[0])
			Rules[path] = &rule
		}
	}
}

func getTitle(body string) string {
	titleReg := regexp.MustCompile(`<title>([\s\S]{1,200})</title>`)
	title := titleReg.FindStringSubmatch(body)
	if len(title) > 1 {
		return title[1]
	}
	return ""
}

// BBscan todo 还应该传进来爬虫找到的 api 目录
func BBscan(u string, ip string, custom map[string]*Rule) {
	if strings.HasSuffix(u, "/") {
		u = u[:len(u)-1]
	}

	res404, err := httpx.Request(u+path404, "GET", "", false, conf.DefaultHeader)

	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	ch := make(chan struct{}, 20)

	rules := Rules
	if custom != nil {
		rules = custom
	}

	for path, rule := range rules {
		if util.Contains(path, "{sub}") {
			t, _ := url.Parse(u)
			path = strings.ReplaceAll(path, "{sub}", t.Hostname())
		}

		wg.Add(1)
		ch <- struct{}{}
		go func(uri string, rule *Rule) {
			defer wg.Done()
			defer func() { <-ch }()
			res, err := httpx.Request(u+uri, "GET", "", false, conf.DefaultHeader)

			if err != nil {
				return
			}

			if util.In(res.Body, conf.WafContent) {
				return
			}

			contentType := res.Header.Get("Content-Type")
			// 返回是个图片
			if util.Contains(contentType, "image/") {
				return
			}

			// 返回包是个下载文件，但文件内容为空丢弃
			if res.Header.Get("Content-Type") == "application/octet-stream" && res.ContentLength == 0 {
				return
			}

			title := getTitle(res.Body)

			if res.StatusCode == 404 || res.StatusCode == 403 || util.In(title, conf.Page403title) || util.In(title, conf.Page404Title) || util.In(res.Body, conf.Page404Content) || util.In(res.Body, conf.Page403Content) {
				return
			}

			// 比较与 page_404_test_api 页面返回值的相似度
			similar := true
			if len(res.Body) != 0 && res404 != nil && len(res404.Body) != 0 {
				similar = strsim.Compare(strings.ReplaceAll(res404.Body, path404, ""), strings.ReplaceAll(res.Body, uri, "")) <= 0.9
			}

			// 不相似才会往下执行
			if !similar {
				return
			}

			// 规则匹配
			if (rule.Type != "" && !util.Contains(contentType, rule.Type)) || (rule.TypeNo != "" && util.Contains(contentType, rule.TypeNo)) {
				return
			}

			if rule.Status != "" && strconv.Itoa(res.StatusCode) != rule.Status {
				return
			}

			if rule.Tag != "" && !util.Contains(res.Body, rule.Tag) {
				return
			}

			// swagger 自动化测试
			if strings.Contains(uri, "swagger") {
				go swagger.Scan(u+uri, ip)
			}

			output.OutChannel <- output.VulMessage{
				DataType: "web_vul",
				Plugin:   "BBscan",
				VulnData: output.VulnData{
					CreateTime: time.Now().Format("2006-01-02 15:04:05"),
					Target:     u,
					Ip:         ip,
					Payload:    u + uri,
					Method:     "GET",
					Request:    res.RequestDump,
					Response:   res.Body,
				},
				Level: output.Low,
			}
		}(path, rule)
	}

	wg.Wait()
}
