package cmd

import (
    "github.com/spf13/cobra"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/Pocs/pocs_go/log4j"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var log4jCmd = &cobra.Command{
    Use:   "log4j",
    Short: "log4j scan && exp",
    Run: func(cmd *cobra.Command, args []string) {
        for _, target := range conf.GlobalConfig.Options.Targets {
            log4j.Scan(target, "GET", "", httpx.NewClient(nil))
        }

    },
}

func log4jCmdInit() {
    rootCmd.AddCommand(log4jCmd)
    log4jCmd.Flags().StringVarP(&conf.GlobalConfig.Reverse.Host, "host", "h", "https://dig.pm", "dns host")
    log4jCmd.Flags().StringVarP(&domain, "domain", "d", "", "domain ")
}
