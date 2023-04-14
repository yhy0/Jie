package sensitive

import (
	"embed"
	"fmt"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/logging"
	"gopkg.in/yaml.v3"
	"io/fs"
	"regexp"
	"time"
)

/**
  @author: yhy
  @since: 2022/7/22
  @desc:

  - pattern:
      name: aws_secret_key
      regex: "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]"

	报错 found unknown escape character, 反斜杠被解释为转义序列引起的。 改为
"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\\/+]{40}['\"]"
**/

//go:embed rules/*
var ruleFiles embed.FS
var rules []Rule

type Rule struct {
	Patterns []struct {
		Pattern struct {
			Name       string `yaml:"name"`
			Regex      string `yaml:"regex"`
			Confidence string `yaml:"confidence"`
		} `yaml:"pattern"`
	} `yaml:"patterns"`
}

// LoadRules 加载规则
func LoadRules() {
	ruleDir, err := fs.ReadDir(ruleFiles, "rules")
	if err != nil {
		logging.Logger.Errorln("sensitive err:", err)
		return
	}

	for _, file := range ruleDir {
		content, err := ruleFiles.ReadFile("rules/" + file.Name())
		if err != nil {
			logging.Logger.Errorf("sensitive[%s] err: %v", file.Name(), err)
			continue
		}

		var rule Rule
		err = yaml.Unmarshal(content, &rule)
		if err != nil {
			logging.Logger.Errorf("sensitive[%s] err: %v", file.Name(), err)
			continue
		}
		rules = append(rules, rule)
	}
}

//// 待优化的正则
//var black = []string{"Mapbox - 1"}

// Detection 页面敏感信息检测
func Detection(url, body string) {
	for _, rule := range rules {
		for _, p := range rule.Patterns {

			//if funk.Contains(black, p.Pattern.Name) {
			//	continue
			//}
			re, err := regexp.Compile(p.Pattern.Regex)
			if err != nil {
				logging.Logger.Errorln(err)
				continue
			}

			match := re.FindStringIndex(body)
			if match != nil {
				matchStr := body[match[0]:match[1]]
				startIndex := match[0] - 20
				if startIndex < 0 {
					startIndex = 0
				}
				endIndex := match[1] + 20
				if endIndex > len(body) {
					endIndex = len(body)
				}
				output.OutChannel <- output.VulMessage{
					DataType: "web_vul",
					Plugin:   "Sensitive",
					VulnData: output.VulnData{
						VulnType:   p.Pattern.Name + " " + p.Pattern.Regex,
						CreateTime: time.Now().Format("2006-01-02 15:04:05"),
						Target:     url,
						Payload:    fmt.Sprintf("%s [%s] %s\n", body[startIndex:match[0]], matchStr, body[match[1]:endIndex]),
					},
					Level: p.Pattern.Confidence,
				}

				fmt.Printf("Matched pattern: %v\n", p.Pattern)
				fmt.Printf("Context: %s [%s] %s\n", body[startIndex:match[0]], matchStr, body[match[1]:endIndex])
			}

		}

	}

}
