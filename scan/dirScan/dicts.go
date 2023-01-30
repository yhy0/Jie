package dirScan

import (
	"embed"
	_ "embed"
)

//go:embed filedic.txt
var filedic string

//go:embed rules/**
var rulesFiles embed.FS
