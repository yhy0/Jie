package cmd

import (
    "fmt"
    "github.com/logrusorgru/aurora"
    "github.com/spf13/cobra"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/PerFolder/traversal"
    "github.com/yhy0/Jie/scan/bbscan"
    "github.com/yhy0/Jie/scan/gadget/brute"
    "github.com/yhy0/Jie/scan/gadget/swagger"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var otherCmd = &cobra.Command{
    Use:   "other",
    Short: "other scan && exp bb:BasicBrute、swagger:Swagger、nat:NginxAliasTraversal、dir:dir)",
    Run: func(cmd *cobra.Command, args []string) {
        client := httpx.NewClient(nil)
        for _, target := range conf.GlobalConfig.Options.Targets {
            switch conf.GlobalConfig.Options.Mode {
            case "bb":
                user, pwd, _ := brute.BasicBrute(target, client)
                if user != "" {
                    fmt.Println(aurora.Red(fmt.Sprintf("[Success] %v %v", user, pwd)))
                }
            case "nat":
                traversal.NginxAlias(target, "", "")
            case "swagger":
                swagger.Scan(target, client)
            case "dir":
                bbscan.BBscan(target, true, nil, nil, client)
            }
        }
    },
}

func otherCmdInit() {
    rootCmd.AddCommand(otherCmd)
    otherCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Mode, "mode", "m", "", "mode (eg: bb:basic brute、nat:Nginx Alias Traversal)")
    otherCmd.MarkFlagRequired("mode")
}
