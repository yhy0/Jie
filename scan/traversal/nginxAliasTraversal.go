package traversal

import (
	"github.com/PuerkitoBio/goquery"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/logging"
	"net/url"
	"strings"
	"sync"
	"time"
)

/**
   @author yhy
   @since 2023/8/15
   @desc nginx alias traversal https://github.com/hakaioffsec/navgix
**/

// Check for alias traversal vulnerability (bruteforce)
var dictionary = []string{
	"file",
	"files",
	"static",
	"js",
	"images",
	"img",
	"css",
	"assets",
	"media",
	"lib",
}

func NginxAlias(url string, body string, dicts []string) {
	if url[len(url)-1:] != "/" {
		url = url + "/"
	}
	logging.Logger.Debugln(url, " dicts:", dicts)
	dictionary = util.RemoveDuplicateElement(append(dicts, dictionary...))
	CheckFoldersForTraversal(url, dictionary)
	// Check for alias traversal vulnerability (endpoint finding)

	if body == "" {
		resp, err := httpx.Get(url)
		if err != nil {
			logging.Logger.Errorln(err)
			return
		}
		body = resp.Body
	}

	CheckFoldersForTraversal(url, findEndpoints(body))
	// Check for directory listing
	// Check for file existence
	// Check for file contents
}

func CheckFolderForTraversal(url string, folder string) bool {
	resp, err := httpx.Get(url + folder + ".")

	if err != nil {
		return false
	}

	if resp.StatusCode == 404 {
		return false
	}

	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		if strings.HasSuffix(resp.Location, folder+"./") {
			resp, err := httpx.Get(url + folder + "..")
			if err != nil {
				return false
			}
			if resp.StatusCode == 301 || resp.StatusCode == 302 {
				if strings.HasSuffix(resp.Location, folder+"../") {
					respNotFound, err := httpx.Get(url + folder + "." + util.RandomString(4))
					if err != nil {
						return false
					}
					if respNotFound.StatusCode == 404 || strings.Contains(strings.ToLower(respNotFound.Body), "not found") {
						respNotFound2, err := httpx.Get(url + folder + "z")
						if err != nil {
							return false
						}
						if respNotFound2.StatusCode == 404 || strings.Contains(strings.ToLower(respNotFound2.Body), "not found") {
							// vulnerable
							statusNotFound3, err := httpx.Get(url + folder + "z..")
							if err != nil {
								return false
							}
							if statusNotFound3.StatusCode != 302 && statusNotFound3.StatusCode != 301 {
								// vulnerable
								output.OutChannel <- output.VulMessage{
									DataType: "web_vul",
									Plugin:   "Nginx Alias Traversal",
									VulnData: output.VulnData{
										CreateTime: time.Now().Format("2006-01-02 15:04:05"),
										Target:     url + folder,
										Method:     "GET",
										Ip:         "",
										Param:      "",
										Request:    statusNotFound3.RequestDump,
										Response:   statusNotFound3.ResponseDump,
										Payload:    url + folder + "../",
									},
									Level: output.Medium,
								}
								logging.Logger.Infof("Vulnerable: %s", url+folder+"../")
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func CheckFoldersForTraversal(url string, folders []string) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	// Use a bounded semaphore with a capacity of 'threads'
	for i := 0; i < 10; i++ {
		semaphore <- struct{}{}
	}

	for _, word := range folders {
		wg.Add(1)
		// Acquire a token from the semaphore channel
		<-semaphore
		go func(word string) {
			CheckFolderForTraversal(url, word)
			// Release the token back to the semaphore channel
			semaphore <- struct{}{}
			wg.Done()
		}(word)
	}

	wg.Wait()
}

func MakeFolderEndpointsFromPath(path string) []string {
	// remove query string
	// "/img/media/a.jpg" -> ["img", "img/media"]
	var endpoints []string
	var endpoint string

	// check if begins with https:// or http:// or //
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "//") {
		// get path
		u, err := url.Parse(path)
		if err != nil {
			logging.Logger.Errorln(err)
			return nil
		}
		path = u.Path
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
	}

	for _, word := range strings.Split(path, "/") {
		if word != "" {
			// check if last
			if word == strings.Split(path, "/")[len(strings.Split(path, "/"))-1] {
				break
			}
			// remove query string
			if strings.Contains(word, "?") {
				word = strings.Split(word, "?")[0]
			}

			endpoint = endpoint + word + "/"
			endpointNoSlash := strings.TrimSuffix(endpoint, "/")
			if !util.InSlice(endpoints, endpointNoSlash) {
				endpoints = append(endpoints, endpointNoSlash)
			}
		}
	}
	return endpoints
}

func findEndpoints(html string) []string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		logging.Logger.Errorln(err)
		return nil
	}
	var foundEndpoints []string
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			for _, endpoint := range foundEndpoints {
				//check if endpoint already exists
				if endpoint == src {
					return
				}
			}
			foundEndpoints = append(foundEndpoints, src)

		}
	})
	finalDirectoryEndpoints := []string{}
	for _, endpoint := range foundEndpoints {
		directoryEndpoints := MakeFolderEndpointsFromPath(endpoint)
		for _, directoryEndpoint := range directoryEndpoints {
			if !util.InSlice(finalDirectoryEndpoints, directoryEndpoint) && !util.InSlice(dictionary, directoryEndpoint) {
				finalDirectoryEndpoints = append(finalDirectoryEndpoints, directoryEndpoint)
			}
		}
	}
	return finalDirectoryEndpoints
}
