package filter

import (
	"github.com/yhy0/Jie/crawler/crawlergo/model"
)

type Handler interface {
	DoFilter(req *model.Request) bool
}
