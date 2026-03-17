package sqli

import "testing"

func FuzzSQLiDetector(f *testing.F) {
	// Add seed corpus
	f.Add("' OR 1=1 --")
	f.Add("normal input")
	f.Add("<script>alert(1)</script>")
	f.Add("")
	f.Add("' UNION SELECT username, password FROM users --")
	f.Add("1; DROP TABLE users --")
	f.Add("' AND SLEEP(5) --")
	f.Add("hello world")
	f.Add("O'Brien")
	f.Add("SELECT * FROM products WHERE id=1")
	f.Add("' OR ''='")
	f.Add("admin' --")
	f.Add("1' AND 1=1 UNION ALL SELECT 1,2,3,NULL --")
	f.Add("%27%20OR%201%3D1%20--")
	f.Add("'; EXEC xp_cmdshell('whoami') --")
	f.Add("1 AND (SELECT COUNT(*) FROM users)>0")
	f.Add("/**/ UNION /**/ SELECT /**/ 1,2,3")

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

func FuzzSQLiTokenizer(f *testing.F) {
	f.Add("' OR 1=1 --")
	f.Add("SELECT * FROM users")
	f.Add("")
	f.Add("normal text without sql")
	f.Add("1234567890")
	f.Add("0x1A 0b1010")
	f.Add("/* comment */ SELECT 1")
	f.Add("'single quoted' \"double quoted\"")
	f.Add("func(1, 2, 3)")
	f.Add("a = b AND c <> d OR e != f")
	f.Add(string([]byte{0, 1, 2, 255, 254, 253}))

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		tokens := Tokenize(input)
		_ = tokens
	})
}
