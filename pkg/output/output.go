package output

import (
	"fmt"
	"github.com/logrusorgru/aurora"
)

/**
  @author: yhy
  @since: 2023/1/4
  @desc: //TODO
**/

var OutChannel = make(chan VulMessage)

// 漏洞等级
var (
	Low      = "Low"
	High     = "High"
	Medium   = "Medium"
	Critical = "Critical"
)

type VulMessage struct {
	DataType string   `json:"data_type"`
	VulnData VulnData `json:"vul_data"`
	Plugin   string   `json:"plugin"`
	Level    string   `json:"level"`
}

type VulnData struct {
	CreateTime  string `json:"create_time"`
	VulnType    string `json:"vuln_type"`
	Target      string `json:"target"`
	Ip          string `json:"ip"`
	Method      string `json:"method"`
	Param       string `json:"param"`
	Payload     string `json:"payload"`
	CURLCommand string `json:"curl_command"`
	Description string `json:"description"`
	Request     string `json:"request"`
	Response    string `json:"response"`
}

func (vul *VulMessage) PrintScreen() string {
	var screen []string

	screen = append(screen, fmt.Sprintf("[Vuln: %s]", vul.Plugin))
	screen = append(screen, fmt.Sprintf("  Level: %s", vul.Level))
	screen = append(screen, fmt.Sprintf("  Target: %s", vul.VulnData.Target))

	if vul.VulnData.VulnType != "" {
		screen = append(screen, fmt.Sprintf("  VulnType: %s", vul.VulnData.VulnType))
	}
	if vul.VulnData.Ip != "" {
		screen = append(screen, fmt.Sprintf("  Ip: %s", vul.VulnData.Ip))
	}
	if vul.VulnData.Method != "" {
		screen = append(screen, fmt.Sprintf("  Method: %s", vul.VulnData.Method))
	}
	if vul.VulnData.Param != "" {
		screen = append(screen, fmt.Sprintf("  Param: %s", vul.VulnData.Param))
	}

	if vul.VulnData.Payload != "" {
		screen = append(screen, fmt.Sprintf("  Payload: %s", vul.VulnData.Payload))
	}
	if vul.VulnData.CURLCommand != "" {
		screen = append(screen, fmt.Sprintf("  CURLCommand: %s", vul.VulnData.CURLCommand))
	}
	if vul.VulnData.Description != "" {
		screen = append(screen, fmt.Sprintf("  Description: %s", vul.VulnData.Description))
	}

	var res = ""
	for i := 0; i < len(screen); i++ {
		res += aurora.Red(screen[i] + "\n").String()
		//res += screen[i] + "\n  "
	}

	return "\n" + res
}
