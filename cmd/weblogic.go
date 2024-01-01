package cmd

import (
    "github.com/spf13/cobra"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    weblogic2 "github.com/yhy0/Jie/scan/Pocs/java/weblogic"
)

/**
   @author yhy
   @since 2023/8/20
   @desc //TODO
**/

var (
    name int
    m    string
    cmd  string
)

var webLogicCmd = &cobra.Command{
    Use:   "weblogic",
    Short: "WebLogic scan && exp",
    Run: func(cmd *cobra.Command, args []string) {
        client := httpx.NewClient(nil)
        for _, target := range conf.GlobalConfig.Options.Targets {
            if m == "scan" {
                switch name {
                case 1:
                    weblogic2.CVE_2014_4210(target, client)
                case 2:
                    weblogic2.CVE_2017_3506(target, client)
                case 3:
                    weblogic2.CVE_2017_10271(target, client)
                case 4:
                    weblogic2.CVE_2018_2894(target, client)
                case 5:
                    weblogic2.CVE_2019_2725(target, client)
                case 6:
                    weblogic2.CVE_2019_2729(target, client)
                case 7:
                    weblogic2.CVE_2020_2883(target)
                case 8:
                    weblogic2.CVE_2020_14882(target, client)
                case 9:
                    weblogic2.CVE_2020_14883(target, client)
                case 10:
                    weblogic2.CVE_2021_2109(target, client)
                case 0:
                    weblogic2.CVE_2014_4210(target, client)
                    weblogic2.CVE_2017_3506(target, client)
                    weblogic2.CVE_2017_10271(target, client)
                    weblogic2.CVE_2018_2894(target, client)
                    weblogic2.CVE_2019_2725(target, client)
                    weblogic2.CVE_2019_2729(target, client)
                    weblogic2.CVE_2020_2883(target)
                    weblogic2.CVE_2020_14882(target, client)
                    weblogic2.CVE_2020_14883(target, client)
                    weblogic2.CVE_2021_2109(target, client)
                }
            }
        }

    },
}

func webLogicCmdInit() {
    rootCmd.AddCommand(webLogicCmd)
    webLogicCmd.Flags().IntVarP(&name, "name", "n", 0, "vul name: 1:CVE_2014_4210, 2:CVE_2017_3506, 3:CVE_2017_10271, 4:CVE_2018_2894, 5:CVE_2019_2725, 6:CVE_2019_2729, 7:CVE_2020_2883, 8:CVE_2020_14882, 9:CVE_2020_14883, 10:CVE_2021_2109, 0:all")
    webLogicCmd.Flags().StringVarP(&m, "mode", "m", "scan", "Specify work mode: scan exp")
    webLogicCmd.Flags().StringVarP(&cmd, "cmd", "c", "id", "Exec command(Only works on mode exp.)")
}
