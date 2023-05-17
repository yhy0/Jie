package main

import (
	"fmt"
	"time"
)

/**
  @author: yhy
  @since: 2023/1/27
  @desc: //TODO
**/

func main() {
	//cmd.RunApp()
	var Done = make(chan bool, 1)

	go func() {
		fmt.Println("-------------")

	}()
	aaa := Done
	time.Sleep(1 * time.Second)
	close(Done)
	fmt.Println("111", aaa)
}
