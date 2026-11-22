# 평가 입력 검토 (2주차, v0)

- 케이스 20개, 모두 공개 저장소의 실제 파일 (커밋 고정). 스냅샷 기준일 2026-11-20 (KEV·EPSS 고정)
- 정답은 1주차 DB에서 코드로 계산 (`eval/build_gold.py`). 사람이나 모델이 쓴 정답이 아님
- 에이전트 입력 = 파서 결과(검사할 패키지 + 검사 불가 목록). 원본 파일 대신 이것을 받는다

| id | 태그 | 출처 | 검사 | 검사불가 | 정답 취약점 | KEV | 취약 패키지 |
|---|---|---|---|---|---|---|---|
| npm-nodegoat-lock | npm, lockfile | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/package-lock.json) | 36 | 0 | 19 | 0 | 8 |
| npm-nodegoat-manifest | npm, ranges | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/package.json) | 5 | 31 | 6 | 0 | 1 |
| npm-nodejs-goof-lock | npm, lockfile | [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/package-lock.json) | 35 | 0 | 77 | 1 | 19 |
| npm-vulnerable-node-lock | npm, lockfile | [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/package-lock.json) | 8 | 0 | 1 | 0 | 1 |
| npm-dvna-manifest | npm, ranges | [appsecco/dvna](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/package.json) | 3 | 16 | 4 | 0 | 2 |
| npm-juice-shop-manifest | npm, ranges, large | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop/blob/c9f99228d9d56afb5f5ca7925376292f7fa44b13/package.json) | 3 | 95 | 15 | 0 | 3 |
| pypi-pygoat | pypi, pinned | [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/requirements.txt) | 32 | 0 | 190 | 0 | 15 |
| pypi-dvpwa | pypi, pinned | [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa/blob/4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756/requirements.txt) | 20 | 0 | 0 | 0 | 0 |
| pypi-vulpy | pypi, unpinned | [fportantier/vulpy](https://github.com/fportantier/vulpy/blob/5249cc8b05a1c37f6b2f757b1cf16a509c327122/requirements.txt) | 0 | 9 | 0 | 0 | 0 |
| pypi-tiredful-api | pypi, pinned | [payatu/Tiredful-API](https://github.com/payatu/Tiredful-API/blob/0134124496b3c4f1b969e51a24fd8a059104fb98/requirements.txt) | 6 | 0 | 37 | 0 | 3 |
| pypi-lets-be-bad-guys | pypi, pinned | [mpirnat/lets-be-bad-guys](https://github.com/mpirnat/lets-be-bad-guys/blob/7cbf11014bfc6dc9e199dc0b8a64e4597bc2338f/requirements.txt) | 2 | 0 | 24 | 0 | 2 |
| pypi-django-nv | pypi, pinned | [nVisium/django.nV](https://github.com/nVisium/django.nV/blob/a48901f106da4888417339b7b44b8ed56b64c63f/requirements.txt) | 1 | 0 | 29 | 0 | 1 |
| pypi-log4j-shell-poc | pypi, unpinned | [kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc/blob/7861abc92e862bba1cf938b4c79a248e994fee07/requirements.txt) | 0 | 2 | 0 | 0 | 0 |
| maven-benchmark-java | maven, large | [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17/pom.xml) | 43 | 0 | 28 | 0 | 6 |
| maven-webgoat | maven, parent-managed | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat/blob/4e98f1cbbf896fdd06edcc9930515ebe0ade7c69/pom.xml) | 24 | 23 | 36 | 1 | 1 |
| gradle-log4shell-app | maven, gradle, transitive-blind-spot | [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app/blob/c962aabb31a6af0a77f0e9bbc7100e175c7c04e1/build.gradle) | 1 | 2 | 0 | 0 | 0 |
| maven-spring4shell-poc | maven, starters | [reznok/Spring4Shell-POC](https://github.com/reznok/Spring4Shell-POC/blob/cee9a2162fde4e48afe0308cee483d923efd15c1/pom.xml) | 4 | 0 | 1 | 1 | 1 |
| maven-java-goof-log4shell | maven | [snyk-labs/java-goof](https://github.com/snyk-labs/java-goof/blob/f5719ae0f757a7482e54d1ebda945dd304cf2529/log4shell-goof/log4shell-server/pom.xml) | 5 | 0 | 31 | 1 | 5 |
| maven-java-goof-struts | maven, parent-provided | [snyk-labs/java-goof](https://github.com/snyk-labs/java-goof/blob/f5719ae0f757a7482e54d1ebda945dd304cf2529/todolist-goof/todolist-web-struts/pom.xml) | 8 | 0 | 50 | 6 | 4 |
| maven-java-goof-core | maven, parent-provided | [snyk-labs/java-goof](https://github.com/snyk-labs/java-goof/blob/f5719ae0f757a7482e54d1ebda945dd304cf2529/todolist-goof/todolist-core/pom.xml) | 13 | 0 | 7 | 0 | 4 |

## npm-nodegoat-lock

출처: [OWASP/NodeGoat@c5cb68a7084e package-lock.json](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/package-lock.json)

**정답 요약**

- `npm/body-parser@1.18.3`: 취약점 3건, 안전한 최소 업그레이드 `1.20.9`
- `npm/express@4.16.4`: 취약점 2건, 안전한 최소 업그레이드 `4.20.0`
- `npm/marked@0.3.5`: 취약점 6건, 안전한 최소 업그레이드 `4.0.10`
- `npm/mongodb@2.2.36`: 취약점 1건, 안전한 최소 업그레이드 `3.1.13`
- `npm/swig@1.4.2`: 취약점 1건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- `npm/underscore@1.9.1`: 취약점 2건, 안전한 최소 업그레이드 `1.13.8`
- `npm/async@2.6.1`: 취약점 1건, 안전한 최소 업그레이드 `2.6.4`
- `npm/grunt@1.0.3`: 취약점 3건, 안전한 최소 업그레이드 `1.5.3`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "package-lock.json",
 "ecosystem": "npm",
 "dependencies": [
  {
   "ecosystem": "npm",
   "name": "bcrypt-nodejs",
   "version": "0.0.3"
  },
  {
   "ecosystem": "npm",
   "name": "body-parser",
   "version": "1.18.3"
  },
  {
   "ecosystem": "npm",
   "name": "consolidate",
   "version": "0.14.5"
  },
  {
   "ecosystem": "npm",
   "name": "csurf",
   "version": "1.9.0"
  },
  {
   "ecosystem": "npm",
   "name": "dont-sniff-mimetype",
   "version": "1.0.0"
  },
  {
   "ecosystem": "npm",
   "name": "express",
   "version": "4.16.4"
  },
  {
   "ecosystem": "npm",
   "name": "express-session",
   "version": "1.15.6"
  },
  {
   "ecosystem": "npm",
   "name": "forever",
   "version": "2.0.0"
  },
  {
   "ecosystem": "npm",
   "name": "helmet",
   "version": "2.3.0"
  },
  {
   "ecosystem": "npm",
   "name": "marked",
   "version": "0.3.5"
  },
  {
   "ecosystem": "npm",
   "name": "mongodb",
   "version": "2.2.36"
  },
  {
   "ecosystem": "npm",
   "name": "needle",
   "version": "2.2.4"
  },
  {
   "ecosystem": "npm",
   "name": "node-esapi",
   "version": "0.0.1"
  },
  {
   "ecosystem": "npm",
   "name": "serve-favicon",
   "version": "2.5.0"
  },
  {
   "ecosystem": "npm",
   "name": "swig",
   "version": "1.4.2"
  },
  {
   "ecosystem": "npm",
   "name": "underscore",
   "version": "1.9.1"
  },
  {
   "ecosystem": "npm",
   "name": "async",
   "version": "2.6.1",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "cross-env",
   "version": "7.0.2",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "cypress",
   "version": "3.3.1",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt",
   "version": "1.0.3",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-cli",
   "version": "1.3.2",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-concurrent",
   "version": "2.3.1",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-contrib-jshint",
   "version": "3.2.0",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-contrib-watch",
   "version": "1.1.0",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-env",
   "version": "1.0.1",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-if",
   "version": "0.2.0",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-jsbeautifier",
   "version": "0.2.13",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-mocha-test",
   "version": "0.12.7",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-npm-install",
   "version": "0.3.1",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "grunt-retire",
   "version": "0.3.12",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "jshint",
   "version": "2.12.0",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "mocha",
   "version": "2.5.3",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "nodemon",
   "version": "1.19.1",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "selenium-webdriver",
   "version": "2.53.3",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "should",
   "version": "8.4.0",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "zaproxy",
   "version": "0.2.0",
   "scope": "dev"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "lockfileVersion 2: 1479 packages in total, only direct dependencies checked"
 ]
}
```
````

## npm-nodegoat-manifest

출처: [OWASP/NodeGoat@c5cb68a7084e package.json](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/package.json)

**정답 요약**

- `npm/marked@0.3.5`: 취약점 6건, 안전한 최소 업그레이드 `4.0.10`
- 검사 불가로 보고해야 할 항목 31개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "package.json",
 "ecosystem": "npm",
 "dependencies": [
  {
   "ecosystem": "npm",
   "name": "bcrypt-nodejs",
   "version": "0.0.3"
  },
  {
   "ecosystem": "npm",
   "name": "marked",
   "version": "0.3.5"
  },
  {
   "ecosystem": "npm",
   "name": "needle",
   "version": "2.2.4"
  },
  {
   "ecosystem": "npm",
   "name": "node-esapi",
   "version": "0.0.1"
  },
  {
   "ecosystem": "npm",
   "name": "jshint",
   "version": "2.12.0",
   "scope": "dev"
  }
 ],
 "unchecked": [
  {
   "spec": "body-parser@^1.15.1",
   "reason": "version range '^1.15.1' and no lockfile to resolve it"
  },
  {
   "spec": "consolidate@^0.14.1",
   "reason": "version range '^0.14.1' and no lockfile to resolve it"
  },
  {
   "spec": "csurf@^1.8.3",
   "reason": "version range '^1.8.3' and no lockfile to resolve it"
  },
  {
   "spec": "dont-sniff-mimetype@^1.0.0",
   "reason": "version range '^1.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "express@^4.13.4",
   "reason": "version range '^4.13.4' and no lockfile to resolve it"
  },
  {
   "spec": "express-session@^1.13.0",
   "reason": "version range '^1.13.0' and no lockfile to resolve it"
  },
  {
   "spec": "forever@^2.0.0",
   "reason": "version range '^2.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "helmet@^2.0.0",
   "reason": "version range '^2.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "mongodb@^2.1.18",
   "reason": "version range '^2.1.18' and no lockfile to resolve it"
  },
  {
   "spec": "serve-favicon@^2.3.0",
   "reason": "version range '^2.3.0' and no lockfile to resolve it"
  },
  {
   "spec": "swig@^1.4.2",
   "reason": "version range '^1.4.2' and no lockfile to resolve it"
  },
  {
   "spec": "underscore@^1.8.3",
   "reason": "version range '^1.8.3' and no lockfile to resolve it"
  },
  {
   "spec": "async@^2.0.0-rc.4",
   "reason": "version range '^2.0.0-rc.4' and no lockfile to resolve it"
  },
  {
   "spec": "cross-env@^7.0.2",
   "reason": "version range '^7.0.2' and no lockfile to resolve it"
  },
  {
   "spec": "cypress@^3.3.1",
   "reason": "version range '^3.3.1' and no lockfile to resolve it"
  },
  {
   "spec": "grunt@^1.0.3",
   "reason": "version range '^1.0.3' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-cli@^1.2.0",
   "reason": "version range '^1.2.0' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-concurrent@^2.3.0",
   "reason": "version range '^2.3.0' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-contrib-jshint@^3.0.0",
   "reason": "version range '^3.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-contrib-watch@^1.0.0",
   "reason": "version range '^1.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-env@latest",
   "reason": "version range 'latest' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-if@https://github.com/binarymist/grunt-if/tarball/master",
   "reason": "version range 'https://github.com/binarymist/grunt-if/tarball/master' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-jsbeautifier@^0.2.12",
   "reason": "version range '^0.2.12' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-mocha-test@^0.12.7",
   "reason": "version range '^0.12.7' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-npm-install@^0.3.0",
   "reason": "version range '^0.3.0' and no lockfile to resolve it"
  },
  {
   "spec": "grunt-retire@^0.3.12",
   "reason": "version range '^0.3.12' and no lockfile to resolve it"
  },
  {
   "spec": "mocha@^2.4.5",
   "reason": "version range '^2.4.5' and no lockfile to resolve it"
  },
  {
   "spec": "nodemon@^1.19.1",
   "reason": "version range '^1.19.1' and no lockfile to resolve it"
  },
  {
   "spec": "selenium-webdriver@^2.53.2",
   "reason": "version range '^2.53.2' and no lockfile to resolve it"
  },
  {
   "spec": "should@^8.3.1",
   "reason": "version range '^8.3.1' and no lockfile to resolve it"
  },
  {
   "spec": "zaproxy@^0.2.0",
   "reason": "version range '^0.2.0' and no lockfile to resolve it"
  }
 ],
 "parser_notes": []
}
```
````

## npm-nodejs-goof-lock

출처: [snyk-labs/nodejs-goof@add14ba59e98 package-lock.json](https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/package-lock.json)

**정답 요약**

- `npm/adm-zip@0.4.7`: 취약점 8건, 안전한 최소 업그레이드 `0.6.1`
- `npm/body-parser@1.9.0`: 취약점 3건, 안전한 최소 업그레이드 `1.20.9`
- `npm/dustjs-linkedin@2.5.0`: 취약점 1건, 안전한 최소 업그레이드 `3.0.0`
- `npm/ejs@1.0.0`: 취약점 5건, 안전한 최소 업그레이드 `3.1.10`
- `npm/express@4.12.4`: 취약점 2건, 안전한 최소 업그레이드 `4.20.0`
- `npm/express-fileupload@0.0.5`: 취약점 3건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- `npm/hbs@4.0.4`: 취약점 1건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- `npm/jquery@2.2.4`: 취약점 4건, 안전한 최소 업그레이드 `3.5.0`
- `npm/lodash@4.17.4`: 취약점 9건, 안전한 최소 업그레이드 `4.18.0`
- `npm/marked@0.3.5`: 취약점 6건, 안전한 최소 업그레이드 `4.0.10`
- `npm/moment@2.15.1`: 취약점 2건, 안전한 최소 업그레이드 `2.29.2`
- `npm/mongoose@4.2.4`: 취약점 13건, 안전한 최소 업그레이드 `6.13.12`
- `npm/morgan@1.10.0`: 취약점 3건, 안전한 최소 업그레이드 `1.12.1`
- `npm/ms@0.7.3`: 취약점 1건, 안전한 최소 업그레이드 `2.0.0`
- `npm/npmconf@0.0.24`: 취약점 1건, 안전한 최소 업그레이드 `2.1.3`
- `npm/st@0.2.4`: 취약점 2건, 안전한 최소 업그레이드 `1.2.2`
- `npm/typeorm@0.2.24`: 취약점 5건, 안전한 최소 업그레이드 `0.3.31`
- `npm/validator@13.5.2`: 취약점 4건, 안전한 최소 업그레이드 `13.15.22`
- `npm/snyk@1.278.1`: 취약점 4건, 안전한 최소 업그레이드 `1.1297.3`
- KEV 등재: CVE-2020-11023 (이것들이 순위 맨 위여야 함)

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "package-lock.json",
 "ecosystem": "npm",
 "dependencies": [
  {
   "ecosystem": "npm",
   "name": "adm-zip",
   "version": "0.4.7"
  },
  {
   "ecosystem": "npm",
   "name": "body-parser",
   "version": "1.9.0"
  },
  {
   "ecosystem": "npm",
   "name": "cfenv",
   "version": "1.2.2"
  },
  {
   "ecosystem": "npm",
   "name": "consolidate",
   "version": "0.14.5"
  },
  {
   "ecosystem": "npm",
   "name": "dustjs-helpers",
   "version": "1.5.0"
  },
  {
   "ecosystem": "npm",
   "name": "dustjs-linkedin",
   "version": "2.5.0"
  },
  {
   "ecosystem": "npm",
   "name": "ejs",
   "version": "1.0.0"
  },
  {
   "ecosystem": "npm",
   "name": "ejs-locals",
   "version": "1.0.2"
  },
  {
   "ecosystem": "npm",
   "name": "errorhandler",
   "version": "1.2.0"
  },
  {
   "ecosystem": "npm",
   "name": "express",
   "version": "4.12.4"
  },
  {
   "ecosystem": "npm",
   "name": "express-fileupload",
   "version": "0.0.5"
  },
  {
   "ecosystem": "npm",
   "name": "express-session",
   "version": "1.17.2"
  },
  {
   "ecosystem": "npm",
   "name": "file-type",
   "version": "8.1.0"
  },
  {
   "ecosystem": "npm",
   "name": "hbs",
   "version": "4.0.4"
  },
  {
   "ecosystem": "npm",
   "name": "humanize-ms",
   "version": "1.0.1"
  },
  {
   "ecosystem": "npm",
   "name": "jquery",
   "version": "2.2.4"
  },
  {
   "ecosystem": "npm",
   "name": "lodash",
   "version": "4.17.4"
  },
  {
   "ecosystem": "npm",
   "name": "marked",
   "version": "0.3.5"
  },
  {
   "ecosystem": "npm",
   "name": "method-override",
   "version": "3.0.0"
  },
  {
   "ecosystem": "npm",
   "name": "moment",
   "version": "2.15.1"
  },
  {
   "ecosystem": "npm",
   "name": "mongodb",
   "version": "3.5.9"
  },
  {
   "ecosystem": "npm",
   "name": "mongoose",
   "version": "4.2.4"
  },
  {
   "ecosystem": "npm",
   "name": "morgan",
   "version": "1.10.0"
  },
  {
   "ecosystem": "npm",
   "name": "ms",
   "version": "0.7.3"
  },
  {
   "ecosystem": "npm",
   "name": "mysql",
   "version": "2.18.1"
  },
  {
   "ecosystem": "npm",
   "name": "npmconf",
   "version": "0.0.24"
  },
  {
   "ecosystem": "npm",
   "name": "optional",
   "version": "0.1.4"
  },
  {
   "ecosystem": "npm",
   "name": "st",
   "version": "0.2.4"
  },
  {
   "ecosystem": "npm",
   "name": "stream-buffers",
   "version": "3.0.2"
  },
  {
   "ecosystem": "npm",
   "name": "tap",
   "version": "11.1.5"
  },
  {
   "ecosystem": "npm",
   "name": "typeorm",
   "version": "0.2.24"
  },
  {
   "ecosystem": "npm",
   "name": "validator",
   "version": "13.5.2"
  },
  {
   "ecosystem": "npm",
   "name": "browserify",
   "version": "13.3.0",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "nodemon",
   "version": "2.0.7",
   "scope": "dev"
  },
  {
   "ecosystem": "npm",
   "name": "snyk",
   "version": "1.278.1",
   "scope": "dev"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "lockfileVersion 2: 1274 packages in total, only direct dependencies checked"
 ]
}
```
````

## npm-vulnerable-node-lock

출처: [cr0hn/vulnerable-node@d68f2a3c9277 package-lock.json](https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/package-lock.json)

**정답 요약**

- `npm/morgan@1.12.0`: 취약점 1건, 안전한 최소 업그레이드 `1.12.1`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "package-lock.json",
 "ecosystem": "npm",
 "dependencies": [
  {
   "ecosystem": "npm",
   "name": "cookie-parser",
   "version": "1.4.7"
  },
  {
   "ecosystem": "npm",
   "name": "ejs",
   "version": "3.1.10"
  },
  {
   "ecosystem": "npm",
   "name": "express",
   "version": "4.22.2"
  },
  {
   "ecosystem": "npm",
   "name": "express-session",
   "version": "1.19.0"
  },
  {
   "ecosystem": "npm",
   "name": "jsonwebtoken",
   "version": "9.0.3"
  },
  {
   "ecosystem": "npm",
   "name": "mongodb",
   "version": "6.21.0"
  },
  {
   "ecosystem": "npm",
   "name": "morgan",
   "version": "1.12.0"
  },
  {
   "ecosystem": "npm",
   "name": "pg",
   "version": "8.23.0"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "lockfileVersion 3: 127 packages in total, only direct dependencies checked"
 ]
}
```
````

## npm-dvna-manifest

출처: [appsecco/dvna@9ba473add536 package.json](https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/package.json)

**정답 요약**

- `npm/mathjs@3.10.1`: 취약점 3건, 안전한 최소 업그레이드 `7.5.1`
- `npm/node-serialize@0.0.4`: 취약점 1건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- 검사 불가로 보고해야 할 항목 16개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "package.json",
 "ecosystem": "npm",
 "dependencies": [
  {
   "ecosystem": "npm",
   "name": "express-flash",
   "version": "0.0.2"
  },
  {
   "ecosystem": "npm",
   "name": "mathjs",
   "version": "3.10.1"
  },
  {
   "ecosystem": "npm",
   "name": "node-serialize",
   "version": "0.0.4"
  }
 ],
 "unchecked": [
  {
   "spec": "bcrypt@^1.0.3",
   "reason": "version range '^1.0.3' and no lockfile to resolve it"
  },
  {
   "spec": "csurf@^1.9.0",
   "reason": "version range '^1.9.0' and no lockfile to resolve it"
  },
  {
   "spec": "ejs@^2.5.7",
   "reason": "version range '^2.5.7' and no lockfile to resolve it"
  },
  {
   "spec": "express@^4.16.2",
   "reason": "version range '^4.16.2' and no lockfile to resolve it"
  },
  {
   "spec": "express-fileupload@^0.4.0",
   "reason": "version range '^0.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "express-session@^1.15.6",
   "reason": "version range '^1.15.6' and no lockfile to resolve it"
  },
  {
   "spec": "flash@^1.1.0",
   "reason": "version range '^1.1.0' and no lockfile to resolve it"
  },
  {
   "spec": "libxmljs@^0.19.1",
   "reason": "version range '^0.19.1' and no lockfile to resolve it"
  },
  {
   "spec": "md5@^2.2.1",
   "reason": "version range '^2.2.1' and no lockfile to resolve it"
  },
  {
   "spec": "morgan@^1.9.0",
   "reason": "version range '^1.9.0' and no lockfile to resolve it"
  },
  {
   "spec": "mysql2@^1.4.2",
   "reason": "version range '^1.4.2' and no lockfile to resolve it"
  },
  {
   "spec": "passport@^0.4.0",
   "reason": "version range '^0.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "passport-local@^1.0.0",
   "reason": "version range '^1.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "sequelize@^4.13.10",
   "reason": "version range '^4.13.10' and no lockfile to resolve it"
  },
  {
   "spec": "winston@^3.0.0",
   "reason": "version range '^3.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "x-xss-protection@^1.1.0",
   "reason": "version range '^1.1.0' and no lockfile to resolve it"
  }
 ],
 "parser_notes": []
}
```
````

## npm-juice-shop-manifest

출처: [juice-shop/juice-shop@c9f99228d9d5 package.json](https://github.com/juice-shop/juice-shop/blob/c9f99228d9d56afb5f5ca7925376292f7fa44b13/package.json)

**정답 요약**

- `npm/express-jwt@0.1.3`: 취약점 1건, 안전한 최소 업그레이드 `6.0.0`
- `npm/jsonwebtoken@0.4.0`: 취약점 4건, 안전한 최소 업그레이드 `9.0.0`
- `npm/sanitize-html@1.4.2`: 취약점 10건, 안전한 최소 업그레이드 `2.18.0`
- 검사 불가로 보고해야 할 항목 95개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "package.json",
 "ecosystem": "npm",
 "dependencies": [
  {
   "ecosystem": "npm",
   "name": "express-jwt",
   "version": "0.1.3"
  },
  {
   "ecosystem": "npm",
   "name": "jsonwebtoken",
   "version": "0.4.0"
  },
  {
   "ecosystem": "npm",
   "name": "sanitize-html",
   "version": "1.4.2"
  }
 ],
 "unchecked": [
  {
   "spec": "@ai-sdk/openai-compatible@^2.0.35",
   "reason": "version range '^2.0.35' and no lockfile to resolve it"
  },
  {
   "spec": "@fontsource/roboto@^5.2.9",
   "reason": "version range '^5.2.9' and no lockfile to resolve it"
  },
  {
   "spec": "@simplewebauthn/server@^14.0.3",
   "reason": "version range '^14.0.3' and no lockfile to resolve it"
  },
  {
   "spec": "ai@^6.0.116",
   "reason": "version range '^6.0.116' and no lockfile to resolve it"
  },
  {
   "spec": "beercss@^4.0.19",
   "reason": "version range '^4.0.19' and no lockfile to resolve it"
  },
  {
   "spec": "clarinet@^0.12.6",
   "reason": "version range '^0.12.6' and no lockfile to resolve it"
  },
  {
   "spec": "compression@^1.8.1",
   "reason": "version range '^1.8.1' and no lockfile to resolve it"
  },
  {
   "spec": "config@^3.3.12",
   "reason": "version range '^3.3.12' and no lockfile to resolve it"
  },
  {
   "spec": "cookie-parser@^1.4.7",
   "reason": "version range '^1.4.7' and no lockfile to resolve it"
  },
  {
   "spec": "cookieconsent@^3.1.1",
   "reason": "version range '^3.1.1' and no lockfile to resolve it"
  },
  {
   "spec": "cors@^2.8.5",
   "reason": "version range '^2.8.5' and no lockfile to resolve it"
  },
  {
   "spec": "errorhandler@^1.5.1",
   "reason": "version range '^1.5.1' and no lockfile to resolve it"
  },
  {
   "spec": "ethers@^6.16.0",
   "reason": "version range '^6.16.0' and no lockfile to resolve it"
  },
  {
   "spec": "express@^4.22.1",
   "reason": "version range '^4.22.1' and no lockfile to resolve it"
  },
  {
   "spec": "express-ipfilter@^1.3.2",
   "reason": "version range '^1.3.2' and no lockfile to resolve it"
  },
  {
   "spec": "express-rate-limit@^7.5.1",
   "reason": "version range '^7.5.1' and no lockfile to resolve it"
  },
  {
   "spec": "express-robots-txt@^0.5.0",
   "reason": "version range '^0.5.0' and no lockfile to resolve it"
  },
  {
   "spec": "express-security.txt@^2.0.0",
   "reason": "version range '^2.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "feature-policy@^0.6.0",
   "reason": "version range '^0.6.0' and no lockfile to resolve it"
  },
  {
   "spec": "file-stream-rotator@^1.0.0",
   "reason": "version range '^1.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "file-type@^16.5.4",
   "reason": "version range '^16.5.4' and no lockfile to resolve it"
  },
  {
   "spec": "finale-rest@^1.2.2",
   "reason": "version range '^1.2.2' and no lockfile to resolve it"
  },
  {
   "spec": "hashids@^2.3.0",
   "reason": "version range '^2.3.0' and no lockfile to resolve it"
  },
  {
   "spec": "hbs@^4.2.0",
   "reason": "version range '^4.2.0' and no lockfile to resolve it"
  },
  {
   "spec": "helmet@^4.6.0",
   "reason": "version range '^4.6.0' and no lockfile to resolve it"
  },
  {
   "spec": "html-entities@^1.4.0",
   "reason": "version range '^1.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "i18n@^0.11.1",
   "reason": "version range '^0.11.1' and no lockfile to resolve it"
  },
  {
   "spec": "js-yaml@^3.14.0",
   "reason": "version range '^3.14.0' and no lockfile to resolve it"
  },
  {
   "spec": "libxml2-wasm@^0.7.1",
   "reason": "version range '^0.7.1' and no lockfile to resolve it"
  },
  {
   "spec": "marsdb@^0.6.11",
   "reason": "version range '^0.6.11' and no lockfile to resolve it"
  },
  {
   "spec": "material-icons@^1.13.14",
   "reason": "version range '^1.13.14' and no lockfile to resolve it"
  },
  {
   "spec": "morgan@^1.10.0",
   "reason": "version range '^1.10.0' and no lockfile to resolve it"
  },
  {
   "spec": "multer@^2.4.0",
   "reason": "version range '^2.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "notevil@^1.3.3",
   "reason": "version range '^1.3.3' and no lockfile to resolve it"
  },
  {
   "spec": "otplib@^13.4.0",
   "reason": "version range '^13.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "pdfkit@^0.11.0",
   "reason": "version range '^0.11.0' and no lockfile to resolve it"
  },
  {
   "spec": "prom-client@^15.1.3",
   "reason": "version range '^15.1.3' and no lockfile to resolve it"
  },
  {
   "spec": "proxy-agent@^8.0.2",
   "reason": "version range '^8.0.2' and no lockfile to resolve it"
  },
  {
   "spec": "pug@^3.0.3",
   "reason": "version range '^3.0.3' and no lockfile to resolve it"
  },
  {
   "spec": "sanitize-filename@^1.6.3",
   "reason": "version range '^1.6.3' and no lockfile to resolve it"
  },
  {
   "spec": "semver@^7.6.3",
   "reason": "version range '^7.6.3' and no lockfile to resolve it"
  },
  {
   "spec": "sequelize@^6.37.3",
   "reason": "version range '^6.37.3' and no lockfile to resolve it"
  },
  {
   "spec": "serve-index@^1.9.1",
   "reason": "version range '^1.9.1' and no lockfile to resolve it"
  },
  {
   "spec": "socket.io@^4.8.4",
   "reason": "version range '^4.8.4' and no lockfile to resolve it"
  },
  {
   "spec": "sqlite3@^5.1.7",
   "reason": "version range '^5.1.7' and no lockfile to resolve it"
  },
  {
   "spec": "svg-captcha@^1.4.0",
   "reason": "version range '^1.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "swagger-ui-express@^5.0.1",
   "reason": "version range '^5.0.1' and no lockfile to resolve it"
  },
  {
   "spec": "unzipper@^0.12.3",
   "reason": "version range '^0.12.3' and no lockfile to resolve it"
  },
  {
   "spec": "winston@^3.16.0",
   "reason": "version range '^3.16.0' and no lockfile to resolve it"
  },
  {
   "spec": "z85@^0.0.2",
   "reason": "version range '^0.0.2' and no lockfile to resolve it"
  },
  {
   "spec": "zod@^4.4.3",
   "reason": "version range '^4.4.3' and no lockfile to resolve it"
  },
  {
   "spec": "@cyclonedx/cyclonedx-npm@^2.0.0||^3.0.0||^4.00",
   "reason": "version range '^2.0.0||^3.0.0||^4.00' and no lockfile to resolve it"
  },
  {
   "spec": "@eslint/js@^9.33.0",
   "reason": "version range '^9.33.0' and no lockfile to resolve it"
  },
  {
   "spec": "@istanbuljs/nyc-config-typescript@^1.0.2",
   "reason": "version range '^1.0.2' and no lockfile to resolve it"
  },
  {
   "spec": "@types/clarinet@^0.12.3",
   "reason": "version range '^0.12.3' and no lockfile to resolve it"
  },
  {
   "spec": "@types/compression@^1.8.1",
   "reason": "version range '^1.8.1' and no lockfile to resolve it"
  },
  {
   "spec": "@types/config@^3.3.5",
   "reason": "version range '^3.3.5' and no lockfile to resolve it"
  },
  {
   "spec": "@types/cookie-parser@^1.4.10",
   "reason": "version range '^1.4.10' and no lockfile to resolve it"
  },
  {
   "spec": "@types/cors@^2.8.19",
   "reason": "version range '^2.8.19' and no lockfile to resolve it"
  },
  {
   "spec": "@types/cross-spawn@^6.0.6",
   "reason": "version range '^6.0.6' and no lockfile to resolve it"
  },
  {
   "spec": "@types/diff@^7.0.1",
   "reason": "version range '^7.0.1' and no lockfile to resolve it"
  },
  {
   "spec": "@types/errorhandler@^1.5.3",
   "reason": "version range '^1.5.3' and no lockfile to resolve it"
  },
  {
   "spec": "@types/exif@^0.6.5",
   "reason": "version range '^0.6.5' and no lockfile to resolve it"
  },
  {
   "spec": "@types/express@^4.17.25",
   "reason": "version range '^4.17.25' and no lockfile to resolve it"
  },
  {
   "spec": "@types/express-jwt@^6.0.4",
   "reason": "version range '^6.0.4' and no lockfile to resolve it"
  },
  {
   "spec": "@types/i18n@^0.12.0",
   "reason": "version range '^0.12.0' and no lockfile to resolve it"
  },
  {
   "spec": "@types/js-yaml@^3.12.10",
   "reason": "version range '^3.12.10' and no lockfile to resolve it"
  },
  {
   "spec": "@types/jsonwebtoken@^8.5.9",
   "reason": "version range '^8.5.9' and no lockfile to resolve it"
  },
  {
   "spec": "@types/jws@^3.2.10",
   "reason": "version range '^3.2.10' and no lockfile to resolve it"
  },
  {
   "spec": "@types/lodash@^4.17.14",
   "reason": "version range '^4.17.14' and no lockfile to resolve it"
  },
  {
   "spec": "@types/morgan@^1.9.9",
   "reason": "version range '^1.9.9' and no lockfile to resolve it"
  },
  {
   "spec": "@types/multer@^1.4.12",
   "reason": "version range '^1.4.12' and no lockfile to resolve it"
  },
  {
   "spec": "@types/node@^26.0.1",
   "reason": "version range '^26.0.1' and no lockfile to resolve it"
  },
  {
   "spec": "@types/pdfkit@^0.10.6",
   "reason": "version range '^0.10.6' and no lockfile to resolve it"
  },
  {
   "spec": "@types/pug@^2.0.10",
   "reason": "version range '^2.0.10' and no lockfile to resolve it"
  },
  {
   "spec": "@types/sanitize-html@^1.27.2",
   "reason": "version range '^1.27.2' and no lockfile to resolve it"
  },
  {
   "spec": "@types/semver@^7.5.8",
   "reason": "version range '^7.5.8' and no lockfile to resolve it"
  },
  {
   "spec": "@types/sequelize@^4.28.20",
   "reason": "version range '^4.28.20' and no lockfile to resolve it"
  },
  {
   "spec": "@types/serve-index@^1.9.4",
   "reason": "version range '^1.9.4' and no lockfile to resolve it"
  },
  {
   "spec": "@types/supertest@^7.2.0",
   "reason": "version range '^7.2.0' and no lockfile to resolve it"
  },
  {
   "spec": "@types/swagger-ui-express@^4.1.6",
   "reason": "version range '^4.1.6' and no lockfile to resolve it"
  },
  {
   "spec": "@types/unzipper@^0.10.10",
   "reason": "version range '^0.10.10' and no lockfile to resolve it"
  },
  {
   "spec": "concurrently@^5.3.0",
   "reason": "version range '^5.3.0' and no lockfile to resolve it"
  },
  {
   "spec": "cypress@^16.2.0",
   "reason": "version range '^16.2.0' and no lockfile to resolve it"
  },
  {
   "spec": "diff@^9.0.0",
   "reason": "version range '^9.0.0' and no lockfile to resolve it"
  },
  {
   "spec": "eslint@^9.39.4",
   "reason": "version range '^9.39.4' and no lockfile to resolve it"
  },
  {
   "spec": "exif@^0.6.0",
   "reason": "version range '^0.6.0' and no lockfile to resolve it"
  },
  {
   "spec": "globals@^17.4.0",
   "reason": "version range '^17.4.0' and no lockfile to resolve it"
  },
  {
   "spec": "neostandard@^0.13.0",
   "reason": "version range '^0.13.0' and no lockfile to resolve it"
  },
  {
   "spec": "nyc@^15.1.0",
   "reason": "version range '^15.1.0' and no lockfile to resolve it"
  },
  {
   "spec": "socket.io-client@^4.8.4",
   "reason": "version range '^4.8.4' and no lockfile to resolve it"
  },
  {
   "spec": "supertest@^7.2.2",
   "reason": "version range '^7.2.2' and no lockfile to resolve it"
  },
  {
   "spec": "tsx@^4.21.0",
   "reason": "version range '^4.21.0' and no lockfile to resolve it"
  },
  {
   "spec": "typescript@^6.0.3",
   "reason": "version range '^6.0.3' and no lockfile to resolve it"
  },
  {
   "spec": "typescript-eslint@^8.57.1",
   "reason": "version range '^8.57.1' and no lockfile to resolve it"
  }
 ],
 "parser_notes": []
}
```
````

## pypi-pygoat

출처: [adeyosemanputra/pygoat@2aa4cc14f251 requirements.txt](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/requirements.txt)

**정답 요약**

- `PyPI/black@26.1.0`: 취약점 3건, 안전한 최소 업그레이드 `26.10.1`
- `PyPI/certifi@2022.12.7`: 취약점 3건, 안전한 최소 업그레이드 `2026.10.18`
- `PyPI/cryptography@39.0.1`: 취약점 13건, 안전한 최소 업그레이드 `49.0.0`
- `PyPI/django@4.2`: 취약점 51건, 안전한 최소 업그레이드 `5.2.17`
- `PyPI/django-allauth@0.52.0`: 취약점 3건, 안전한 최소 업그레이드 `65.14.1`
- `PyPI/idna@3.4`: 취약점 2건, 안전한 최소 업그레이드 `3.15`
- `PyPI/oauthlib@3.2.2`: 취약점 3건, 안전한 최소 업그레이드 `4.0.0`
- `PyPI/pillow@12.1.0`: 취약점 62건, 안전한 최소 업그레이드 `13.0.0`
- `PyPI/pyjwt@2.4.0`: 취약점 14건, 안전한 최소 업그레이드 `2.15.0`
- `PyPI/pyyaml@5.1`: 취약점 3건, 안전한 최소 업그레이드 `5.4`
- `PyPI/requests@2.28.2`: 취약점 4건, 안전한 최소 업그레이드 `2.33.0`
- `PyPI/sqlparse@0.3.1`: 취약점 8건, 안전한 최소 업그레이드 `0.6.0`
- `PyPI/urllib3@1.26.9`: 취약점 10건, 안전한 최소 업그레이드 `2.8.0`
- `PyPI/werkzeug@2.1.2`: 취약점 10건, 안전한 최소 업그레이드 `3.1.9`
- `PyPI/zipp@3.8.0`: 취약점 1건, 안전한 최소 업그레이드 `3.19.1`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [
  {
   "ecosystem": "PyPI",
   "name": "argon2-cffi",
   "version": "21.3.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "argon2-cffi-bindings",
   "version": "21.2.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "asgiref",
   "version": "3.6.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "black",
   "version": "26.1.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "certifi",
   "version": "2022.12.7"
  },
  {
   "ecosystem": "PyPI",
   "name": "cffi",
   "version": "2.0.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "charset-normalizer",
   "version": "3.0.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "cryptography",
   "version": "39.0.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "crispy-bootstrap4",
   "version": "2022.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "defusedxml",
   "version": "0.7.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "dj-database-url",
   "version": "0.5.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "Django",
   "version": "4.2"
  },
  {
   "ecosystem": "PyPI",
   "name": "django-allauth",
   "version": "0.52.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "django-crispy-forms",
   "version": "2.3"
  },
  {
   "ecosystem": "PyPI",
   "name": "gunicorn",
   "version": "23.0.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "idna",
   "version": "3.4"
  },
  {
   "ecosystem": "PyPI",
   "name": "oauthlib",
   "version": "3.2.2"
  },
  {
   "ecosystem": "PyPI",
   "name": "Pillow",
   "version": "12.1.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "pre_commit",
   "version": "4.5.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "pycparser",
   "version": "2.21"
  },
  {
   "ecosystem": "PyPI",
   "name": "PyJWT",
   "version": "2.4.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "python3-openid",
   "version": "3.2.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "pytz",
   "version": "2020.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "PyYAML",
   "version": "5.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "requests",
   "version": "2.28.2"
  },
  {
   "ecosystem": "PyPI",
   "name": "requests-oauthlib",
   "version": "1.3.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "sqlparse",
   "version": "0.3.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "urllib3",
   "version": "1.26.9"
  },
  {
   "ecosystem": "PyPI",
   "name": "Werkzeug",
   "version": "2.1.2"
  },
  {
   "ecosystem": "PyPI",
   "name": "whitenoise",
   "version": "6.2.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "zipp",
   "version": "3.8.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "docker",
   "version": "7.1.0"
  }
 ],
 "unchecked": [],
 "parser_notes": []
}
```
````

## pypi-dvpwa

출처: [anxolerd/dvpwa@4a8f4a43fafc requirements.txt](https://github.com/anxolerd/dvpwa/blob/4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756/requirements.txt)

**정답 요약**

- 취약점 없음 (보고서에 패키지가 하나도 없어야 정답)

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [
  {
   "ecosystem": "PyPI",
   "name": "aiohappyeyeballs",
   "version": "2.7.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "aiohttp",
   "version": "3.14.5"
  },
  {
   "ecosystem": "PyPI",
   "name": "aiohttp-jinja2",
   "version": "1.6"
  },
  {
   "ecosystem": "PyPI",
   "name": "aiohttp-session",
   "version": "2.12.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "aiopg",
   "version": "1.4.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "aiosignal",
   "version": "1.4.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "async-timeout",
   "version": "4.0.3"
  },
  {
   "ecosystem": "PyPI",
   "name": "attrs",
   "version": "26.1.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "frozenlist",
   "version": "1.8.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "idna",
   "version": "3.20"
  },
  {
   "ecosystem": "PyPI",
   "name": "jinja2",
   "version": "3.1.6"
  },
  {
   "ecosystem": "PyPI",
   "name": "markupsafe",
   "version": "3.0.4"
  },
  {
   "ecosystem": "PyPI",
   "name": "multidict",
   "version": "7.2.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "propcache",
   "version": "0.5.4"
  },
  {
   "ecosystem": "PyPI",
   "name": "psycopg2-binary",
   "version": "2.9.13"
  },
  {
   "ecosystem": "PyPI",
   "name": "pyyaml",
   "version": "6.0.3"
  },
  {
   "ecosystem": "PyPI",
   "name": "redis",
   "version": "8.1.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "trafaret",
   "version": "2.1.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "trafaret-config",
   "version": "2.0.2"
  },
  {
   "ecosystem": "PyPI",
   "name": "yarl",
   "version": "1.25.1"
  }
 ],
 "unchecked": [],
 "parser_notes": []
}
```
````

## pypi-vulpy

출처: [fportantier/vulpy@5249cc8b05a1 requirements.txt](https://github.com/fportantier/vulpy/blob/5249cc8b05a1c37f6b2f757b1cf16a509c327122/requirements.txt)

**정답 요약**

- 취약점 없음 (보고서에 패키지가 하나도 없어야 정답)
- 검사 불가로 보고해야 할 항목 9개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [],
 "unchecked": [
  {
   "spec": "click",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "cryptography",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "Flask",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "geoip2",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "jsonschema",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "PyJWT",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "pyotp",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "qrcode",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "requests",
   "reason": "not pinned: no version specified"
  }
 ],
 "parser_notes": []
}
```
````

## pypi-tiredful-api

출처: [payatu/Tiredful-API@0134124496b3 requirements.txt](https://github.com/payatu/Tiredful-API/blob/0134124496b3c4f1b969e51a24fd8a059104fb98/requirements.txt)

**정답 요약**

- `PyPI/django@1.11.7`: 취약점 29건, 안전한 최소 업그레이드 `5.2.17`
- `PyPI/djangorestframework@3.7.3`: 취약점 6건, 안전한 최소 업그레이드 `3.18.2`
- `PyPI/oauthlib@2.0.6`: 취약점 2건, 안전한 최소 업그레이드 `4.0.0`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [
  {
   "ecosystem": "PyPI",
   "name": "Django",
   "version": "1.11.7"
  },
  {
   "ecosystem": "PyPI",
   "name": "django-oauth-toolkit",
   "version": "1.0.0"
  },
  {
   "ecosystem": "PyPI",
   "name": "djangorestframework",
   "version": "3.7.3"
  },
  {
   "ecosystem": "PyPI",
   "name": "oauth",
   "version": "1.0.1"
  },
  {
   "ecosystem": "PyPI",
   "name": "oauthlib",
   "version": "2.0.6"
  },
  {
   "ecosystem": "PyPI",
   "name": "python-oauth2",
   "version": "1.0.1"
  }
 ],
 "unchecked": [],
 "parser_notes": []
}
```
````

## pypi-lets-be-bad-guys

출처: [mpirnat/lets-be-bad-guys@7cbf11014bfc requirements.txt](https://github.com/mpirnat/lets-be-bad-guys/blob/7cbf11014bfc6dc9e199dc0b8a64e4597bc2338f/requirements.txt)

**정답 요약**

- `PyPI/django@1.9.6`: 취약점 23건, 안전한 최소 업그레이드 `5.2.17`
- `PyPI/django-debug-toolbar@1.4`: 취약점 1건, 안전한 최소 업그레이드 `1.11.1`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [
  {
   "ecosystem": "PyPI",
   "name": "Django",
   "version": "1.9.6"
  },
  {
   "ecosystem": "PyPI",
   "name": "django-debug-toolbar",
   "version": "1.4"
  }
 ],
 "unchecked": [],
 "parser_notes": []
}
```
````

## pypi-django-nv

출처: [nVisium/django.nV@a48901f106da requirements.txt](https://github.com/nVisium/django.nV/blob/a48901f106da4888417339b7b44b8ed56b64c63f/requirements.txt)

**정답 요약**

- `PyPI/django@1.8.3`: 취약점 29건, 안전한 최소 업그레이드 `5.2.17`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [
  {
   "ecosystem": "PyPI",
   "name": "Django",
   "version": "1.8.3"
  }
 ],
 "unchecked": [],
 "parser_notes": []
}
```
````

## pypi-log4j-shell-poc

출처: [kozmer/log4j-shell-poc@7861abc92e86 requirements.txt](https://github.com/kozmer/log4j-shell-poc/blob/7861abc92e862bba1cf938b4c79a248e994fee07/requirements.txt)

**정답 요약**

- 취약점 없음 (보고서에 패키지가 하나도 없어야 정답)
- 검사 불가로 보고해야 할 항목 2개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "requirements.txt",
 "ecosystem": "PyPI",
 "dependencies": [],
 "unchecked": [
  {
   "spec": "colorama",
   "reason": "not pinned: no version specified"
  },
  {
   "spec": "argparse",
   "reason": "not pinned: no version specified"
  }
 ],
 "parser_notes": []
}
```
````

## maven-benchmark-java

출처: [OWASP-Benchmark/BenchmarkJava@10dfcc54ad02 pom.xml](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17/pom.xml)

**정답 요약**

- `Maven/commons-lang:commons-lang@2.6`: 취약점 1건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- `Maven/org.bouncycastle:bcprov-jdk15on@1.70`: 취약점 5건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- `Maven/org.hibernate:hibernate-core@3.6.10.Final`: 취약점 2건, 안전한 최소 업그레이드 `5.3.20.Final`
- `Maven/org.springframework:spring-context@5.3.39`: 취약점 2건, 안전한 최소 업그레이드 `6.1.20`
- `Maven/org.springframework:spring-web@5.3.39`: 취약점 2건, 안전한 최소 업그레이드 `6.1.14`
- `Maven/org.springframework:spring-webmvc@5.3.39`: 취약점 16건, 안전한 최소 업그레이드 `7.0.9`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "pom.xml",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "javax:javaee-api",
   "version": "8.0.1",
   "scope": "provided"
  },
  {
   "ecosystem": "Maven",
   "name": "javax.xml.bind:jaxb-api",
   "version": "2.3.1"
  },
  {
   "ecosystem": "Maven",
   "name": "com.sun.xml.bind:jaxb-impl",
   "version": "2.3.9"
  },
  {
   "ecosystem": "Maven",
   "name": "com.sun.jersey:jersey-servlet",
   "version": "1.19.4"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-codec:commons-codec",
   "version": "1.23.0"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-dbcp:commons-dbcp",
   "version": "1.4"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-io:commons-io",
   "version": "2.22.0"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-lang:commons-lang",
   "version": "2.6"
  },
  {
   "ecosystem": "Maven",
   "name": "org.slf4j:slf4j-reload4j",
   "version": "2.0.20"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.api:api-ldap-model",
   "version": "2.1.7"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.api:api-ldap-schema-data",
   "version": "2.1.9"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-core",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-core-annotations",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-core-api",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-core-avl",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-core-constants",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-core-jndi",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-interceptor-kerberos",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-jdbm-partition",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-kerberos-codec",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-ldif-partition",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-protocol-ldap",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-protocol-shared",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-server-annotations",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-server-jndi",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-test-framework",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.directory.server:apacheds-xdbm-partition",
   "version": "2.0.0.AM27"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.httpcomponents.client5:httpclient5",
   "version": "5.6.5"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.httpcomponents.core5:httpcore5",
   "version": "5.5"
  },
  {
   "ecosystem": "Maven",
   "name": "org.bouncycastle:bcprov-jdk15on",
   "version": "1.70"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hibernate:hibernate-core",
   "version": "3.6.10.Final"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hibernate:hibernate-entitymanager",
   "version": "3.6.10.Final"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hsqldb:hsqldb",
   "version": "2.7.4"
  },
  {
   "ecosystem": "Maven",
   "name": "org.owasp.esapi:esapi",
   "version": "2.7.0.0"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-context",
   "version": "5.3.39"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-jdbc",
   "version": "5.3.39"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-tx",
   "version": "5.3.39"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-web",
   "version": "5.3.39"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-webmvc",
   "version": "5.3.39"
  },
  {
   "ecosystem": "Maven",
   "name": "xml-apis:xml-apis",
   "version": "1.4.01"
  },
  {
   "ecosystem": "Maven",
   "name": "com.fasterxml.jackson.core:jackson-databind",
   "version": "2.23.0"
  },
  {
   "ecosystem": "Maven",
   "name": "org.junit.jupiter:junit-jupiter-api",
   "version": "5.14.4",
   "scope": "test"
  },
  {
   "ecosystem": "Maven",
   "name": "org.junit.jupiter:junit-jupiter-params",
   "version": "5.14.4",
   "scope": "test"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "Maven: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````

## maven-webgoat

출처: [WebGoat/WebGoat@4e98f1cbbf89 pom.xml](https://github.com/WebGoat/WebGoat/blob/4e98f1cbbf896fdd06edcc9930515ebe0ade7c69/pom.xml)

**정답 요약**

- `Maven/com.thoughtworks.xstream:xstream@1.4.5`: 취약점 36건, 안전한 최소 업그레이드 `1.4.21`
- KEV 등재: CVE-2021-39144 (이것들이 순위 맨 위여야 함)
- 검사 불가로 보고해야 할 항목 23개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "pom.xml",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "org.apache.commons:commons-exec",
   "version": "1.6.0"
  },
  {
   "ecosystem": "Maven",
   "name": "org.projectlombok:lombok",
   "version": "1.18.48",
   "scope": "provided"
  },
  {
   "ecosystem": "Maven",
   "name": "javax.xml.bind:jaxb-api",
   "version": "2.3.1"
  },
  {
   "ecosystem": "Maven",
   "name": "org.asciidoctor:asciidoctorj",
   "version": "3.0.1"
  },
  {
   "ecosystem": "Maven",
   "name": "org.bouncycastle:bcprov-jdk18on",
   "version": "1.85"
  },
  {
   "ecosystem": "Maven",
   "name": "org.jsoup:jsoup",
   "version": "1.23.2"
  },
  {
   "ecosystem": "Maven",
   "name": "com.nulab-inc:zxcvbn",
   "version": "1.9.0"
  },
  {
   "ecosystem": "Maven",
   "name": "com.thoughtworks.xstream:xstream",
   "version": "1.4.5"
  },
  {
   "ecosystem": "Maven",
   "name": "cglib:cglib-nodep",
   "version": "3.3.0"
  },
  {
   "ecosystem": "Maven",
   "name": "xml-resolver:xml-resolver",
   "version": "1.2"
  },
  {
   "ecosystem": "Maven",
   "name": "io.jsonwebtoken:jjwt",
   "version": "0.9.1"
  },
  {
   "ecosystem": "Maven",
   "name": "com.auth0:jwks-rsa",
   "version": "0.24.1"
  },
  {
   "ecosystem": "Maven",
   "name": "com.auth0:java-jwt",
   "version": "4.6.2"
  },
  {
   "ecosystem": "Maven",
   "name": "com.google.guava:guava",
   "version": "33.7.2-jre"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-io:commons-io",
   "version": "2.22.0"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.commons:commons-text",
   "version": "1.15.0"
  },
  {
   "ecosystem": "Maven",
   "name": "org.bitbucket.b_c:jose4j",
   "version": "0.9.6"
  },
  {
   "ecosystem": "Maven",
   "name": "org.webjars:bootstrap",
   "version": "5.3.5"
  },
  {
   "ecosystem": "Maven",
   "name": "org.webjars:jquery",
   "version": "4.0.0"
  },
  {
   "ecosystem": "Maven",
   "name": "org.webjars:webjars-locator-lite",
   "version": "1.1.5"
  },
  {
   "ecosystem": "Maven",
   "name": "com.github.terma:javaniotcpproxy",
   "version": "1.6",
   "scope": "test"
  },
  {
   "ecosystem": "Maven",
   "name": "org.wiremock:wiremock-standalone",
   "version": "3.13.2"
  },
  {
   "ecosystem": "Maven",
   "name": "io.rest-assured:rest-assured",
   "version": "6.2.0",
   "scope": "test"
  },
  {
   "ecosystem": "Maven",
   "name": "com.microsoft.playwright:playwright",
   "version": "1.64.0",
   "scope": "test"
  }
 ],
 "unchecked": [
  {
   "spec": "org.springframework.boot:spring-boot-starter-validation",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-webmvc",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "com.fasterxml.jackson.core:jackson-databind",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "com.fasterxml.jackson.datatype:jackson-datatype-jsr310",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-actuator",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.flywaydb:flyway-core",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.flywaydb:flyway-database-hsqldb",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-data-jpa",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-security",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-thymeleaf",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-security-oauth2-client",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.thymeleaf.extras:thymeleaf-extras-springsecurity6",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "jakarta.servlet:jakarta.servlet-api",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.hsqldb:hsqldb",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.apache.commons:commons-lang3",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "jakarta.xml.bind:jakarta.xml.bind-api",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "com.sun.xml.bind:jaxb-impl",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-test",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-webmvc-test",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-data-jpa-test",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-security-test",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.security:spring-security-test",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  },
  {
   "spec": "org.springframework.boot:spring-boot-properties-migrator",
   "reason": "version managed by parent org.springframework.boot:spring-boot-starter-parent:4.1.2"
  }
 ],
 "parser_notes": [
  "parent POM org.springframework.boot:spring-boot-starter-parent:4.1.2 is not resolved (its managed versions and dependencies are unknown)",
  "Maven: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````

## gradle-log4shell-app

출처: [christophetd/log4shell-vulnerable-app@c962aabb31a6 build.gradle](https://github.com/christophetd/log4shell-vulnerable-app/blob/c962aabb31a6af0a77f0e9bbc7100e175c7c04e1/build.gradle)

**정답 요약**

- 취약점 없음 (보고서에 패키지가 하나도 없어야 정답)
- 검사 불가로 보고해야 할 항목 2개

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "build.gradle",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "org.springframework.boot:spring-boot-starter-log4j2",
   "version": "2.6.1"
  }
 ],
 "unchecked": [
  {
   "spec": "org.springframework.boot:spring-boot-starter-web",
   "reason": "no version: managed by a BOM or the Spring dependency-management plugin"
  },
  {
   "spec": "org.springframework.boot:spring-boot-starter-test",
   "reason": "no version: managed by a BOM or the Spring dependency-management plugin"
  }
 ],
 "parser_notes": [
  "Spring Boot plugin 2.6.1 manages versions of starters and their transitive dependencies",
  "Gradle: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````

## maven-spring4shell-poc

출처: [reznok/Spring4Shell-POC@cee9a2162fde pom.xml](https://github.com/reznok/Spring4Shell-POC/blob/cee9a2162fde4e48afe0308cee483d923efd15c1/pom.xml)

**정답 요약**

- `Maven/org.springframework.boot:spring-boot-starter-web@2.6.3`: 취약점 1건, 안전한 최소 업그레이드 `2.6.6`
- KEV 등재: CVE-2022-22965 (이것들이 순위 맨 위여야 함)

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "pom.xml",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "org.springframework.boot:spring-boot-starter-thymeleaf",
   "version": "2.6.3"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework.boot:spring-boot-starter-web",
   "version": "2.6.3"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework.boot:spring-boot-starter-test",
   "version": "2.6.3",
   "scope": "test"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework.boot:spring-boot-starter-tomcat",
   "version": "2.6.3",
   "scope": "provided"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "parent POM org.springframework.boot:spring-boot-starter-parent:2.6.3 is not resolved (its managed versions and dependencies are unknown)",
  "Maven: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````

## maven-java-goof-log4shell

출처: [snyk-labs/java-goof@f5719ae0f757 log4shell-goof/log4shell-server/pom.xml](https://github.com/snyk-labs/java-goof/blob/f5719ae0f757a7482e54d1ebda945dd304cf2529/log4shell-goof/log4shell-server/pom.xml)

**정답 요약**

- `Maven/org.apache.logging.log4j:log4j-core@2.15.0`: 취약점 7건, 안전한 최소 업그레이드 `2.25.4`
- `Maven/com.unboundid:unboundid-ldapsdk@3.1.1`: 취약점 1건, 안전한 최소 업그레이드 `4.0.5`
- `Maven/io.undertow:undertow-core@2.2.13.Final`: 취약점 20건, 안전한 최소 업그레이드 `없음 (모두 고치는 버전 없음)`
- `Maven/commons-collections:commons-collections@3.1`: 취약점 2건, 안전한 최소 업그레이드 `3.2.2`
- `Maven/org.apache.commons:commons-lang3@3.11`: 취약점 1건, 안전한 최소 업그레이드 `3.18.0`
- KEV 등재: CVE-2021-45046 (이것들이 순위 맨 위여야 함)

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "pom.xml",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "org.apache.logging.log4j:log4j-core",
   "version": "2.15.0"
  },
  {
   "ecosystem": "Maven",
   "name": "com.unboundid:unboundid-ldapsdk",
   "version": "3.1.1"
  },
  {
   "ecosystem": "Maven",
   "name": "io.undertow:undertow-core",
   "version": "2.2.13.Final"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-collections:commons-collections",
   "version": "3.1"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.commons:commons-lang3",
   "version": "3.11"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "Maven: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````

## maven-java-goof-struts

출처: [snyk-labs/java-goof@f5719ae0f757 todolist-goof/todolist-web-struts/pom.xml](https://github.com/snyk-labs/java-goof/blob/f5719ae0f757a7482e54d1ebda945dd304cf2529/todolist-goof/todolist-web-struts/pom.xml)
함께 쓴 부모 POM: `todolist-goof/pom.xml`

**정답 요약**

- `Maven/org.apache.logging.log4j:log4j-core@2.7`: 취약점 9건, 안전한 최소 업그레이드 `2.25.4`
- `Maven/org.springframework:spring-web@3.2.6.RELEASE`: 취약점 7건, 안전한 최소 업그레이드 `6.1.14`
- `Maven/org.apache.struts:struts2-core@2.3.20`: 취약점 31건, 안전한 최소 업그레이드 `6.8.0`
- `Maven/org.zeroturnaround:zt-zip@1.12`: 취약점 3건, 안전한 최소 업그레이드 `1.18.1`
- KEV 등재: CVE-2021-44228, CVE-2021-45046, CVE-2016-3081, CVE-2017-5638, CVE-2018-11776, CVE-2020-17530 (이것들이 순위 맨 위여야 함)

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "pom.xml",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "io.github.snyk:todolist-web-common",
   "version": "0.0.1-SNAPSHOT"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.logging.log4j:log4j-core",
   "version": "2.7"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.logging.log4j:log4j-api",
   "version": "2.7"
  },
  {
   "ecosystem": "Maven",
   "name": "javax:javaee-web-api",
   "version": "7.0",
   "scope": "provided"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-web",
   "version": "3.2.6.RELEASE"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.struts:struts2-core",
   "version": "2.3.20"
  },
  {
   "ecosystem": "Maven",
   "name": "org.apache.struts:struts2-spring-plugin",
   "version": "2.3.20"
  },
  {
   "ecosystem": "Maven",
   "name": "org.zeroturnaround:zt-zip",
   "version": "1.12"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "parent POM io.github.snyk:todolist-mvc:0.0.1-SNAPSHOT provided: its properties and managed versions were applied",
  "Maven: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````

## maven-java-goof-core

출처: [snyk-labs/java-goof@f5719ae0f757 todolist-goof/todolist-core/pom.xml](https://github.com/snyk-labs/java-goof/blob/f5719ae0f757a7482e54d1ebda945dd304cf2529/todolist-goof/todolist-core/pom.xml)
함께 쓴 부모 POM: `todolist-goof/pom.xml`

**정답 요약**

- `Maven/org.springframework:spring-context@3.2.6.RELEASE`: 취약점 3건, 안전한 최소 업그레이드 `6.1.20`
- `Maven/org.hsqldb:hsqldb@2.3.2`: 취약점 1건, 안전한 최소 업그레이드 `2.7.1`
- `Maven/org.hibernate:hibernate-core@4.3.7.Final`: 취약점 2건, 안전한 최소 업그레이드 `5.3.20.Final`
- `Maven/junit:junit@4.12`: 취약점 1건, 안전한 최소 업그레이드 `4.13.1`

**에이전트가 받는 입력 전문**

````
Triage this dependency file.

```json
{
 "file": "pom.xml",
 "ecosystem": "Maven",
 "dependencies": [
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-context",
   "version": "3.2.6.RELEASE"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-orm",
   "version": "3.2.6.RELEASE"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-aspects",
   "version": "3.2.6.RELEASE"
  },
  {
   "ecosystem": "Maven",
   "name": "cglib:cglib",
   "version": "2.2.2"
  },
  {
   "ecosystem": "Maven",
   "name": "org.aspectj:aspectjweaver",
   "version": "1.8.2"
  },
  {
   "ecosystem": "Maven",
   "name": "c3p0:c3p0",
   "version": "0.9.1.2"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hsqldb:hsqldb",
   "version": "2.3.2"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hibernate:hibernate-core",
   "version": "4.3.7.Final"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hibernate:hibernate-entitymanager",
   "version": "4.3.7.Final"
  },
  {
   "ecosystem": "Maven",
   "name": "org.hibernate.javax.persistence:hibernate-jpa-2.0-api",
   "version": "1.0.1.Final"
  },
  {
   "ecosystem": "Maven",
   "name": "commons-collections:commons-collections",
   "version": "3.2.2"
  },
  {
   "ecosystem": "Maven",
   "name": "junit:junit",
   "version": "4.12",
   "scope": "test"
  },
  {
   "ecosystem": "Maven",
   "name": "org.springframework:spring-test",
   "version": "3.2.6.RELEASE",
   "scope": "test"
  }
 ],
 "unchecked": [],
 "parser_notes": [
  "parent POM io.github.snyk:todolist-mvc:0.0.1-SNAPSHOT provided: its properties and managed versions were applied",
  "Maven: direct dependencies only; transitive dependencies need a resolved dependency tree"
 ]
}
```
````
