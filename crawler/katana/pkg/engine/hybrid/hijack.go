package hybrid

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/scan/xss/dom"
	"github.com/yhy0/logging"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// NewHijack create hijack from page.
func NewHijack(page *rod.Page) *Hijack {
	return &Hijack{
		page:    page,
		disable: &proto.FetchDisable{},
	}
}

// HijackHandler type
type HijackHandler = func(e *proto.FetchRequestPaused) error

// Hijack is a hijack handler
type Hijack struct {
	page    *rod.Page
	enable  *proto.FetchEnable
	disable *proto.FetchDisable
	cancel  func()
}

// SetPattern set pattern directly
func (h *Hijack) SetPattern(pattern *proto.FetchRequestPattern) {
	h.enable = &proto.FetchEnable{
		Patterns: []*proto.FetchRequestPattern{pattern},
	}
}

// Start hijack.
func (h *Hijack) Start(handler HijackHandler) func() error {
	if h.enable == nil {
		panic("hijack pattern not set")
	}

	p, cancel := h.page.WithCancel()
	h.cancel = cancel

	err := h.enable.Call(p)
	if err != nil {
		return func() error { return err }
	}

	wait := p.EachEvent(func(e *proto.FetchRequestPaused) {
		if handler != nil {
			err = handler(e)
		}
	}, func(e *proto.RuntimeBindingCalled) { // 实现绑定调用监听，接收污点分析结果
		switch e.Name {
		case eventPushVul:
			logging.Logger.Infoln("[dom-based] EventBindingCalled", e.Payload)
			points := make([]dom.VulPoint, 0)
			if err := json.Unmarshal([]byte(e.Payload), &points); err != nil {
				logging.Logger.Errorln("[dom-based] json.Unmarshal error:", err)
				return
			}

			for _, point := range points {
				output.OutChannel <- output.VulMessage{
					DataType: "web_vul",
					Plugin:   "XSS",
					VulnData: output.VulnData{
						CreateTime: time.Now().Format("2006-01-02 15:04:05"),
						Target:     point.Url,
						VulnType:   "Dom XSS",
						Method:     "GET",
						Payload:    fmt.Sprintf("Source:%v \t Sink:%v\n", point.Source, point.Sink),
					},
					Level: output.Medium,
				}
			}
		}
	})

	return func() error {
		wait()
		return err
	}
}

// Stop
func (h *Hijack) Stop() error {
	if h.cancel != nil {
		h.cancel()
	}
	return h.disable.Call(h.page)
}

// FetchGetResponseBody get request body.
func FetchGetResponseBody(page *rod.Page, e *proto.FetchRequestPaused) ([]byte, error) {
	m := proto.FetchGetResponseBody{
		RequestID: e.RequestID,
	}
	r, err := m.Call(page)
	if err != nil {
		return nil, err
	}

	if !r.Base64Encoded {
		return []byte(r.Body), nil
	}

	bs, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

// FetchContinueRequest continue request
func FetchContinueRequest(page *rod.Page, e *proto.FetchRequestPaused) error {
	m := proto.FetchContinueRequest{
		RequestID: e.RequestID,
	}
	return m.Call(page)
}
