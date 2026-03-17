package sanitizer

import "testing"

func FuzzNormalizeAll(f *testing.F) {
	f.Add("%27%20OR%201%3D1")
	f.Add("normal")
	f.Add("%2527")
	f.Add("")
	f.Add("/hello/world")
	f.Add("/../../../etc/passwd")
	f.Add("%252e%252e%252f")
	f.Add("&lt;script&gt;alert(1)&lt;/script&gt;")
	f.Add("%00null%00byte")
	f.Add("hello\\0world")
	f.Add("C:\\Windows\\System32")
	f.Add("\uff53\uff45\uff4c\uff45\uff43\uff54")
	f.Add("   lots   of   spaces   ")
	f.Add("%u0027%u0020OR%u00201=1")
	f.Add("&#x3c;script&#x3e;")

	f.Fuzz(func(t *testing.T, input string) {
		// NormalizeAll should not panic
		result := NormalizeAll(input)
		_ = result

		// DecodeURLRecursive should not panic
		decoded := DecodeURLRecursive(input)
		_ = decoded

		// RemoveNullBytes should not panic
		cleaned := RemoveNullBytes(input)
		_ = cleaned

		// CanonicalizePath should not panic
		canon := CanonicalizePath(input)
		_ = canon

		// NormalizeUnicode should not panic
		uni := NormalizeUnicode(input)
		_ = uni

		// DecodeHTMLEntities should not panic
		html := DecodeHTMLEntities(input)
		_ = html

		// NormalizeWhitespace should not panic
		ws := NormalizeWhitespace(input)
		_ = ws
	})
}

func FuzzDecodeURLRecursive(f *testing.F) {
	f.Add("%27")
	f.Add("%2527")
	f.Add("%252527")
	f.Add("normal text")
	f.Add("")
	f.Add("%")
	f.Add("%%")
	f.Add("%zz")
	f.Add("%u0041")
	f.Add("%uffff")
	f.Add("100%25 complete")

	f.Fuzz(func(t *testing.T, input string) {
		result := DecodeURLRecursive(input)
		_ = result
	})
}

func FuzzCanonicalizePath(f *testing.F) {
	f.Add("/a/b/c")
	f.Add("/../../../etc/passwd")
	f.Add("/a/./b/../c")
	f.Add("")
	f.Add("/")
	f.Add("//")
	f.Add("/a//b///c")
	f.Add("\\a\\b\\c")
	f.Add("/a/b/..")
	f.Add("a/b/c")

	f.Fuzz(func(t *testing.T, input string) {
		result := CanonicalizePath(input)
		_ = result
	})
}
