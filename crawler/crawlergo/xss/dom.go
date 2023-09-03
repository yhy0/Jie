package xss

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/gokitx/pkgs/bytesconv"
	"github.com/sirupsen/logrus"
	"github.com/yhy0/Jie/scan/xss/dom"
	"regexp"
)

/**
  @author: yhy
  @since: 2023/8/3
  @desc: //TODO
**/

const (
	EventPushVul = "xssfinderPushDomVul"
)

var (
	//go:embed preload.js
	PreloadJS        string
	scriptContentRex = regexp.MustCompile(`<script[^/>]*?>(?:\s*<!--)?\s*(\S[\s\S]+?\S)\s*(?:-->\s*)?<\/script>`)
)

type VulPoint struct {
	Url    string     `json:"url"`
	Source TrackChain `json:"source"`
	Sink   TrackChain `json:"sink"`
}

type TrackChain struct {
	Label      string `json:"label"`
	Stacktrace []struct {
		Url    string `json:"url"`
		Line   string `json:"line"`
		Column string `json:"column"`
	} `json:"stacktrace"`
}

func ParseDomHookResponseJs(ctx context.Context, event *fetch.EventRequestPaused) error {
	resBody, err := fetch.GetResponseBody(event.RequestID).Do(ctx)
	if err != nil {
		return err
	}
	switch event.ResourceType {
	case network.ResourceTypeDocument:
		ss := scriptContentRex.FindAllSubmatch(resBody, -1)
		for i := range ss {
			convedBody, err := dom.HookParse(bytesconv.BytesToString(ss[i][1]))
			if err != nil {
				logrus.Errorf("[dom-based] body hookconv %s error: %s\n", event.Request.URL, err)
				continue
			}
			resBody = bytes.Replace(resBody, ss[i][1], bytesconv.StringToBytes(convedBody), 1)
		}
		return fetch.FulfillRequest(event.RequestID, event.ResponseStatusCode).WithBody(string(resBody)).Do(ctx)
	case network.ResourceTypeScript:
		convertedResBody, err := dom.HookParse(bytesconv.BytesToString(resBody))
		if err != nil {
			logrus.Errorf("[dom-based] script hookconv %s error: %s\n", event.Request.URL, err)
			return err
		}
		return fetch.FulfillRequest(event.RequestID, event.ResponseStatusCode).WithBody(base64.StdEncoding.EncodeToString(
			bytesconv.StringToBytes(convertedResBody))).Do(ctx)
	}
	return nil
}
