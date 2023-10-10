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

/**
	@author: yhy
	@since: 2022/9/17
	@desc: //TODO
**/

var (
	RegTag           *regexp.Regexp
	RegStatus        *regexp.Regexp
	RegContentType   *regexp.Regexp
	RegContentTypeNo *regexp.Regexp

	BlackText      *regexp.Regexp
	BlackRegexText *regexp.Regexp
	BlackAllText   *regexp.Regexp
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
	isBackUpPage bool
	title        string
	locationUrl  string
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

	BlackText, _ = regexp.Compile(`{text="(.*)"}`)
	BlackRegexText, _ = regexp.Compile(`{regex_text="(.*)"}`)
	BlackAllText, _ = regexp.Compile(`{all_text="(.*)"}`)

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

		if entry.Name() == "black.list" {
			for _, str := range util.CvtLines(string(rulesContent)) {
				if !strings.HasPrefix(str, "{") {
					continue
				}
				var black conf.BlackRule

				text := BlackText.FindStringSubmatch(str)
				if len(text) > 0 {
					black.Type = "text"
					black.Rule = text[1]
					conf.BlackLists = append(conf.BlackLists, black)
				} else {
					regexText := BlackRegexText.FindStringSubmatch(str)
					if len(regexText) > 0 {
						black.Type = "regexText"
						black.Rule = regexText[1]
						conf.BlackLists = append(conf.BlackLists, black)
					} else {
						allText := BlackAllText.FindStringSubmatch(str)
						black.Type = "allText"
						black.Rule = allText[1]
						conf.BlackLists = append(conf.BlackLists, black)
					}
				}
			}
		} else {
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
}

func getTitle(body string) string {
	titleReg := regexp.MustCompile(`<title>([\s\S]{1,200})</title>`)
	title := titleReg.FindStringSubmatch(body)
	if len(title) > 1 {
		return title[1]
	}
	return ""
}

func ReqPage(u string) (*Page, *httpx.Response, error) {
	page := &Page{}
	var backUpSuffixList = []string{".tar", ".tar.gz", ".zip", ".rar", ".7z", ".bz2", ".gz", ".war"}
	var method = "GET"

	for _, ext := range backUpSuffixList {
		if strings.HasSuffix(u, ext) {
			method = "HEAD"
		}
	}

	if res, err := httpx.Request(u, method, "", false, conf.DefaultHeader); err == nil {
		page.title = getTitle(res.Body)
		page.locationUrl = res.Location
		if res.StatusCode != 302 && res.Location == "" {
			regs := []string{"application/.*download", "application/.*file", "application/.*zip", "application/.*rar", "application/.*tar", "application/.*down", "application/.*compressed", "application/.*stream"}
			for _, reg := range regs {
				matched, _ := regexp.Match(reg, []byte(res.Header.Get("Content-Type")))
				if matched {
					page.isBackUpPage = true
					break
				}
			}
		}

		return page, res, err
	} else {
		return page, nil, err
	}
}

func BBscan(u string, ip string, custom map[string]*Rule, dirs []string) []string {
	if strings.HasSuffix(u, "/") {
		u = u[:len(u)-1]
	}

	var (
		technologies []string
		url404res    *httpx.Response
		err          error
		resContents  []string // 找到的页面返回集合，用来进行网页相似度比较，用来去除大量的返回一样的
	)

	if _, url404res, err = ReqPage(u + path404); err == nil {
		if url404res.StatusCode == 404 {
			technologies = addFingerprints404(technologies, url404res) //基于404页面文件扫描指纹添加
		}
		resContents = append(resContents, strings.ReplaceAll(url404res.Body, path404, ""))
	}

	wg := sync.WaitGroup{}
	ch := make(chan struct{}, 20)
	var l sync.Mutex
	rules := Rules
	if custom != nil {
		rules = custom
	}

	count := 0
	for path, rule := range rules {
		if util.Contains(path, "{sub}") {
			t, _ := url.Parse(u)
			path = strings.ReplaceAll(path, "{sub}", t.Hostname())
		}
		wg.Add(1)
		ch <- struct{}{}
		go func(path string, rule *Rule) {
			defer wg.Done()
			defer func() { <-ch }()
			<-time.After(time.Duration(100) * time.Millisecond)

			var targets []string
			if len(dirs) > 0 && !rule.Root {
				for _, dir := range dirs {
					dir = strings.Trim(dir, "/")
					targets = append(targets, u+"/"+dir+path)
				}
			} else {
				targets = append(targets, u+path)
			}

			for _, t := range targets {
				if target, res, err := ReqPage(t); err == nil && res != nil {
					if count > 30 {
						return
					}

					// 黑名单，跳过
					if util.IsBlackHtml(res.Body) {
						continue
					}

					// ContentLength 为 0 的，都丢弃
					if res.ContentLength == 0 {
						continue
					}

					contentType := res.Header.Get("Content-Type")
					// 返回是个图片
					if util.Contains(contentType, "image/") {
						continue
					}

					if strings.HasSuffix(path, ".xml") {
						if !util.Contains(contentType, "xml") {
							continue
						}
					} else if strings.HasSuffix(path, ".json") {
						if !util.Contains(contentType, "json") {
							continue
						}
					}

					// 规则匹配
					if !target.isBackUpPage {
						if len(strings.TrimSpace(res.Body)) == 0 {
							continue
						}
						if (rule.Type != "" && !util.Contains(contentType, rule.Type)) || (rule.TypeNo != "" && util.Contains(contentType, rule.TypeNo)) {
							continue
						}
						if rule.Status != "" && strconv.Itoa(res.StatusCode) != rule.Status {
							continue
						}
					} else {
						//压缩包的单独搞，规则不太对
						if res.StatusCode < 200 || res.StatusCode > 300 {
							continue
						}

					}

					if rule.Tag != "" && !util.Contains(res.Body, rule.Tag) {
						continue
					}

					similar := false
					if len(res.Body) != 0 {
						// 与成功的进行相似度比较，排除一些重复项 比如一个目标返回很多这种，写入黑名单的话，会有很多，所以先这样去除 {"code":99999,"msg":"未知错误","status":0}
						for _, body := range resContents {
							similar = strsim.Compare(body, res.Body) > 0.9 // 不相似才会往下执行
						}
					}

					if !similar {
						// swagger 自动化测试
						if strings.Contains(path, "swagger") {
							swagger.Scan(u+path, ip)
						}
						if res.StatusCode == 401 {
							l.Lock()
							technologies = append(technologies, "Basic")
							l.Unlock()

						}
						l.Lock()
						technologies = append(addFingerprintsnormal(path, technologies, res)) // 基于200页面文件扫描指纹添加
						resContents = append(resContents, strings.ReplaceAll(res.Body, path, ""))
						count += 1
						l.Unlock()

						output.OutChannel <- output.VulMessage{
							DataType: "web_vul",
							Plugin:   "BBscan",
							VulnData: output.VulnData{
								CreateTime: time.Now().Format("2006-01-02 15:04:05"),
								Target:     u,
								Ip:         ip,
								Payload:    t,
								Method:     "GET",
								Request:    res.RequestDump,
								Response:   res.ResponseDump,
							},
							Level: output.Low,
						}
					}
				}
			}

		}(path, rule)
	}

	wg.Wait()
	return technologies
}

func SingleScan(targets []string, path string) {
	rule := Rules[path]

	wg := sync.WaitGroup{}
	ch := make(chan struct{}, 50)
	for _, target := range targets {
		if util.Contains(path, "{sub}") {
			t, _ := url.Parse(target)
			path = strings.ReplaceAll(path, "{sub}", t.Hostname())
		}

		wg.Add(1)
		ch <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-ch }()
			res, err := httpx.Request(u+path, "GET", "", false, conf.DefaultHeader)

			if err != nil {
				return
			}
			// 黑名单，跳过
			if util.IsBlackHtml(res.Body) {
				return
			}

			contentType := res.Header.Get("Content-Type")
			// 返回是个图片
			if util.Contains(contentType, "image/") {
				return
			}

			if strings.HasSuffix(path, ".xml") {
				if !util.Contains(contentType, "xml") {
					return
				}
			} else if strings.HasSuffix(path, ".json") {
				if !util.Contains(contentType, "json") {
					return
				}
			}

			// 返回包是个下载文件，但文件内容为空丢弃
			//if res.Header.Get("Content-Type") == "application/octet-stream" && res.ContentLength == 0 {
			//	return
			//}

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
			if strings.Contains(path, "swagger") {
				swagger.Scan(u+path, "")
			}

			output.OutChannel <- output.VulMessage{
				DataType: "web_vul",
				Plugin:   "BBscan",
				VulnData: output.VulnData{
					CreateTime: time.Now().Format("2006-01-02 15:04:05"),
					Target:     u,
					Ip:         "",
					Payload:    u + path,
					Method:     "GET",
					Request:    res.RequestDump,
					Response:   res.ResponseDump,
				},
				Level: output.Low,
			}
		}(target)
	}
	wg.Wait()
}
