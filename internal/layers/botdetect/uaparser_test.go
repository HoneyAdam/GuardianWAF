package botdetect

import "testing"

func TestParseUserAgent_Chrome(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36"
	p := ParseUserAgent(ua)
	if p.Browser != "Chrome" {
		t.Errorf("expected Chrome, got %q", p.Browser)
	}
	if p.BrVersion != "120.0.6099.130" {
		t.Errorf("expected version 120.0.6099.130, got %q", p.BrVersion)
	}
	if p.OS != "Windows 10/11" {
		t.Errorf("expected Windows 10/11, got %q", p.OS)
	}
	if p.DeviceType != "desktop" {
		t.Errorf("expected desktop, got %q", p.DeviceType)
	}
	if p.IsBot {
		t.Error("expected not bot")
	}
}

func TestParseUserAgent_Firefox(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
	p := ParseUserAgent(ua)
	if p.Browser != "Firefox" {
		t.Errorf("expected Firefox, got %q", p.Browser)
	}
	if p.OS != "Linux" {
		t.Errorf("expected Linux, got %q", p.OS)
	}
	if p.DeviceType != "desktop" {
		t.Errorf("expected desktop, got %q", p.DeviceType)
	}
}

func TestParseUserAgent_Safari_macOS(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
	p := ParseUserAgent(ua)
	if p.Browser != "Safari" {
		t.Errorf("expected Safari, got %q", p.Browser)
	}
	if p.BrVersion != "17.2" {
		t.Errorf("expected version 17.2, got %q", p.BrVersion)
	}
	if p.OS != "macOS 10.15.7" {
		t.Errorf("expected macOS 10.15.7, got %q", p.OS)
	}
}

func TestParseUserAgent_Edge(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91"
	p := ParseUserAgent(ua)
	if p.Browser != "Edge" {
		t.Errorf("expected Edge, got %q", p.Browser)
	}
}

func TestParseUserAgent_iPhone(t *testing.T) {
	ua := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
	p := ParseUserAgent(ua)
	if p.OS != "iOS 17.2" {
		t.Errorf("expected iOS 17.2, got %q", p.OS)
	}
	if p.DeviceType != "mobile" {
		t.Errorf("expected mobile, got %q", p.DeviceType)
	}
}

func TestParseUserAgent_iPad(t *testing.T) {
	ua := "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
	p := ParseUserAgent(ua)
	if p.OS != "iPadOS 17.2" {
		t.Errorf("expected iPadOS 17.2, got %q", p.OS)
	}
	if p.DeviceType != "tablet" {
		t.Errorf("expected tablet, got %q", p.DeviceType)
	}
}

func TestParseUserAgent_Android(t *testing.T) {
	ua := "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
	p := ParseUserAgent(ua)
	if p.OS != "Android 14" {
		t.Errorf("expected Android 14, got %q", p.OS)
	}
	if p.DeviceType != "mobile" {
		t.Errorf("expected mobile, got %q", p.DeviceType)
	}
	if p.Browser != "Chrome" {
		t.Errorf("expected Chrome, got %q", p.Browser)
	}
}

func TestParseUserAgent_Googlebot(t *testing.T) {
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	p := ParseUserAgent(ua)
	if p.Browser != "Googlebot" {
		t.Errorf("expected Googlebot, got %q", p.Browser)
	}
	if !p.IsBot {
		t.Error("expected bot")
	}
	if p.DeviceType != "bot" {
		t.Errorf("expected bot device, got %q", p.DeviceType)
	}
}

func TestParseUserAgent_SQLMap(t *testing.T) {
	ua := "sqlmap/1.7.2#stable"
	p := ParseUserAgent(ua)
	if p.Browser != "sqlmap" {
		t.Errorf("expected sqlmap, got %q", p.Browser)
	}
	if !p.IsBot {
		t.Error("expected bot")
	}
}

func TestParseUserAgent_Curl(t *testing.T) {
	ua := "curl/8.4.0"
	p := ParseUserAgent(ua)
	if p.Browser != "curl" {
		t.Errorf("expected curl, got %q", p.Browser)
	}
	if p.DeviceType != "cli" {
		t.Errorf("expected cli, got %q", p.DeviceType)
	}
}

func TestParseUserAgent_Wget(t *testing.T) {
	ua := "Wget/1.21"
	p := ParseUserAgent(ua)
	if p.Browser != "wget" {
		t.Errorf("expected wget, got %q", p.Browser)
	}
}

func TestParseUserAgent_Empty(t *testing.T) {
	p := ParseUserAgent("")
	if p.Browser != "Unknown" {
		t.Errorf("expected Unknown, got %q", p.Browser)
	}
}

func TestParseUserAgent_Opera(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
	p := ParseUserAgent(ua)
	if p.Browser != "Opera" {
		t.Errorf("expected Opera, got %q", p.Browser)
	}
}

func TestParseUserAgent_SamsungInternet(t *testing.T) {
	ua := "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36"
	p := ParseUserAgent(ua)
	if p.Browser != "Samsung Internet" {
		t.Errorf("expected Samsung Internet, got %q", p.Browser)
	}
}

func TestParseUserAgent_PythonRequests(t *testing.T) {
	ua := "python-requests/2.31.0"
	p := ParseUserAgent(ua)
	if p.Browser != "Python Requests" {
		t.Errorf("expected Python Requests, got %q", p.Browser)
	}
	if p.DeviceType != "cli" {
		t.Errorf("expected cli, got %q", p.DeviceType)
	}
}

func TestParseUserAgent_Windows7(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
	p := ParseUserAgent(ua)
	if p.OS != "Windows 7" {
		t.Errorf("expected Windows 7, got %q", p.OS)
	}
}

func TestParseUserAgent_ChromeOS(t *testing.T) {
	ua := "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	p := ParseUserAgent(ua)
	if p.OS != "Chrome OS" {
		t.Errorf("expected Chrome OS, got %q", p.OS)
	}
}

func TestParseUserAgent_IE(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
	p := ParseUserAgent(ua)
	if p.Browser != "Internet Explorer" {
		t.Errorf("expected Internet Explorer, got %q", p.Browser)
	}
}
