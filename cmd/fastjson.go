package cmd

import (
    "github.com/spf13/cobra"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/PerFile/fastjson"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var fastjsonCmd = &cobra.Command{
    Use:   "fastjson",
    Short: "fastjson scan && exp",
    Run: func(cmd *cobra.Command, args []string) {
        for _, target := range conf.GlobalConfig.Options.Targets {
            fastjson.Scan(target, httpx.NewClient(nil))
        }

    },
}

func fastjsonCmdInit() {
    rootCmd.AddCommand(fastjsonCmd)
}
