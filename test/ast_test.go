package test

import (
	"fmt"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"io"
	"testing"
)

/**
   @author yhy
   @since 2023/6/12
   @desc //TODO
**/

func TestAst(t *testing.T) {
	//	a := ast.SearchInputInResponse("ycPOCq", `
	//        <div id="guestbook_comments">Name: 123<pasd/>Message: 456<br /></div>
	//<div id="guestbook_comments">Name: ycPOCq<br />Message: rnSCKL<br /></div>
	//`)
	//	t.Log(a)

	script := `
function lookupCookie(name) {
  var parts = document.cookie.split(/\s*;\s*/);
  var nameEq = name + '=';
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].indexOf(nameEq) == 0) {
      return parts[i].substr(nameEq.length);
    }
  }
}`

	l := js.NewLexer(parse.NewInputString(script))
	var varDiscover bool
	for {
		tt, text := l.Next()
		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				fmt.Println("Error on line:", l.Err())
			}
			return
		case js.VarToken, js.ConstToken, js.LetToken: // var, const, let
			varDiscover = true
		case js.IdentifierToken:
			if varDiscover {
				fmt.Println(string(text))
			}
			varDiscover = false
		default:
			if varDiscover {
				varDiscover = false
			}
		}
	}
}
