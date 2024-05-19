package cmd

import (
    "fmt"
    "github.com/logrusorgru/aurora"
    "github.com/panjf2000/ants/v2"
    "github.com/spf13/cobra"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/PerFolder/traversal"
    "github.com/yhy0/Jie/scan/bbscan"
    "github.com/yhy0/Jie/scan/gadget/brute"
    "github.com/yhy0/Jie/scan/gadget/swagger"
    "sync"
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
        pool, _ := ants.NewPool(20)
        defer pool.Release() // 释放协程池
        
        wg := sync.WaitGroup{}
        
        for _, target := range conf.GlobalConfig.Options.Targets {
            wg.Add(1)
            switch conf.GlobalConfig.Options.Mode {
            case "bb":
                _ = pool.Submit(func() {
                    defer wg.Done()
                    user, pwd, _ := brute.BasicBrute(target, client)
                    if user != "" {
                        fmt.Println(aurora.Red(fmt.Sprintf("[Success] %v %v", user, pwd)))
                    }
                })
            case "nat":
                _ = pool.Submit(func() {
                    defer wg.Done()
                    traversal.NginxAlias(target, "", "")
                })
            
            case "swagger":
                _ = pool.Submit(func() {
                    defer wg.Done()
                    swagger.Scan(target, client)
                })
            case "dir":
                _ = pool.Submit(func() {
                    defer wg.Done()
                    bbscan.BBscan(target, true, nil, nil, client)
                })
            }
        }
        
        wg.Wait()
    },
}

func otherCmdInit() {
    rootCmd.AddCommand(otherCmd)
    otherCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Mode, "mode", "m", "", "mode (eg: bb:basic brute、nat:Nginx Alias Traversal)")
    otherCmd.MarkFlagRequired("mode")
}
