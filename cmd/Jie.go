package cmd

import (
	"flag"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/yhy0/Jie/conf"
	"strings"
)

/**
  @author: yhy
  @since: 2023/1/3
  @desc: //TODO
**/

var (
	plugins = flag.String("p", "all", "plugins(all,xss,sql,ssrf,cmd,xxe,crlf)")
)

func init() {
	fmt.Println("\t" + aurora.Green(conf.Banner).String())
	fmt.Println("\t\t\t" + aurora.Red("v"+conf.Version).String())
	fmt.Println("\t\t" + aurora.Blue(conf.Website).String() + "\n\n")

	fmt.Println(aurora.Red("Use with caution. You are responsible for your actions.").String())
	fmt.Println(aurora.Red("Developers assume no liability and are not responsible for any misuse or damage.").String() + "\n")
}

func RunApp() {
	flag.Parse()

	if *plugins != "all" {
		strings.Split(*plugins, ",")

	}
}
