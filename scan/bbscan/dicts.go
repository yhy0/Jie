package bbscan

import (
	"embed"
	_ "embed"
)

//go:embed rules/**
var rulesFiles embed.FS
