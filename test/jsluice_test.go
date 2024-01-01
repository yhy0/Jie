package test

import (
    "encoding/json"
    "fmt"
    "github.com/BishopFox/jsluice"
    "testing"
)

/**
   @author yhy
   @since 2023/12/26
   @desc //TODO
**/

func TestJsluice(t *testing.T) {
    analyzer := jsluice.NewAnalyzer([]byte(`
        const login = (redirect) => {
            document.location = "/login?redirect=" + redirect + "&method=oauth"
        }
    `))

    for _, url := range analyzer.GetURLs() {
        fmt.Println(url.URL)
        j, err := json.MarshalIndent(url, "", "  ")
        if err != nil {
            continue
        }
        fmt.Printf("%s\n", j)
    }
}
