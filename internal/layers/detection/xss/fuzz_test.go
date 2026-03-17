package xss

import "testing"

func FuzzXSSDetector(f *testing.F) {
	// Add seed corpus
	f.Add("<script>alert(1)</script>")
	f.Add("normal input")
	f.Add("' OR 1=1 --")
	f.Add("")
	f.Add("<img src=x onerror=alert(1)>")
	f.Add("<svg onload=alert(1)>")
	f.Add("javascript:alert(1)")
	f.Add("<a href=\"javascript:alert(1)\">click</a>")
	f.Add("hello world")
	f.Add("<b>bold text</b>")
	f.Add("Use <b>bold</b> for emphasis")
	f.Add("<SCRIPT>alert(document.cookie)</SCRIPT>")
	f.Add("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>")
	f.Add("{{constructor.constructor('alert(1)')()}}")
	f.Add("<div onmouseover=\"alert(1)\">hover</div>")
	f.Add("<iframe src=\"data:text/html,<script>alert(1)</script>\">")
	f.Add("%3Cscript%3Ealert(1)%3C/script%3E")

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		findings := Detect(input, "query")
		for _, f := range findings {
			if f.Score < 0 {
				t.Errorf("negative score for input %q: %d", input, f.Score)
			}
		}
	})
}
