package output

import (
	"fmt"
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
	DataType string  `json:"data_type"`
	VulData  VulData `json:"vul_data"`
	Plugin   string  `json:"plugin"`
	Level    string  `json:"level"`
}

type VulData struct {
	CreateTime  string `json:"create_time"`
	Target      string `json:"target"`
	Ip          string `json:"ip"`
	Method      string `json:"method"`
	Param       string `json:"param"`
	Payload     string `json:"payload"`
	Description string `json:"description"`
	Request     string `json:"request"`
	Response    string `json:"response"`
}

func (vul *VulMessage) PrintScreen() string {
	var screen []string
	screen = append(screen, fmt.Sprintf("[Vuln: %s]", vul.Plugin))
	screen = append(screen, fmt.Sprintf("Level: %s", vul.Level))
	screen = append(screen, fmt.Sprintf("Target: %s", vul.VulData.Target))

	if vul.VulData.Ip != "" {
		screen = append(screen, fmt.Sprintf("Ip: %s", vul.VulData.Ip))
	}
	if vul.VulData.Method != "" {
		screen = append(screen, fmt.Sprintf("Method: %s", vul.VulData.Method))
	}
	if vul.VulData.Param != "" {
		screen = append(screen, fmt.Sprintf("Param: %s", vul.VulData.Param))
	}

	if vul.VulData.Payload != "" {
		screen = append(screen, fmt.Sprintf("Payload: %s", vul.VulData.Payload))
	}
	if vul.VulData.Description != "" {
		screen = append(screen, fmt.Sprintf("Description: %s", vul.VulData.Description))
	}

	var res = ""
	for i := 0; i < len(screen); i++ {
		res += fmt.Sprintf("%s\n ", screen[i])
	}
	return "\n" + res
}
