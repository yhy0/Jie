package test

import (
	"github.com/yhy0/Jie/pkg/protocols/mitmproxy"
	"github.com/yhy0/logging"
	"testing"
)

/**
  @author: yhy
  @since: 2023/10/10
  @desc: //TODO
**/

func TestPassive(t *testing.T) {
	logging.New(true, "", "Passive", true)
	mitmproxy.NewMitmproxy()
}
