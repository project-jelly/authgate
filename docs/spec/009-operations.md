# Spec 009: 운영

## 개요

authgate의 초기 설정, 시크릿 관리, 키 로테이션, 일상 운영에 대한 스펙.
운영자는 authgate에 로그인하지 않는다. 환경변수, DB, 키 파일로 관리한다.

## 초기 설정

authgate를 처음 배포할 때 필요한 것:

```
1. PostgreSQL 준비
   → DB 생성 (authgate)
   → 마이그레이션은 authgate가 시작 시 자동 실행
     (golang-migrate, migrations/*.up.sql 순차 적용, schema_migrations 테이블로 상태 추적)
     여러 replica가 동시에 시작해도 Postgres advisory lock으로 안전
   → 012_fk_indexes: FK 컬럼(user_identities/sessions/refresh_tokens의 user_id,
     refresh_tokens.family_id)에 인덱스 추가. 시작 시 해당 테이블을 잠깐 잠그며
     (CONCURRENTLY 아님), 배포 점검창 안에서 적용된다
   → 013_refresh_token_families: refresh 토큰 재사용 감지 시 family tombstone을
     기록하는 테이블 추가 (빈 테이블 생성, 영향 없음)
   → 015_cleanup_indexes: cleanup 잡이 조건으로 쓰는 expires_at/revoked_at 컬럼에
     인덱스 추가 (refresh_tokens/sessions/auth_requests/device_codes). 012와
     마찬가지로 시작 시 해당 테이블을 잠깐 잠그며(CONCURRENTLY 아님), 배포
     점검창 안에서 적용된다
   → 016_device_codes_resource: v0.10.0에서 추가된 nullable resource 컬럼.
     v0.10.1부터 Device Flow에서는 사용하지 않지만 이미 적용된 migration 이력을
     보존하기 위해 파일과 컬럼을 유지하며 번호를 재사용하지 않는다
   → 017_refresh_tokens_parent_id: refresh_tokens에 nullable parent_id(교환 전 토큰 id)
     컬럼과 부분 인덱스 추가. 재사용 유예 시간이 한 교환의 자식 토큰 수를 정확히 세는 데
     쓴다. 기존 행은 NULL로 남으며 컬럼 추가는 테이블 재작성이 없다. 인덱스 생성은
     012/015처럼 시작 시 테이블을 잠깐 잠근다(CONCURRENTLY 아님)
   → 018_auth_requests_prompt: auth_requests에 `prompt TEXT[] NOT NULL DEFAULT '{}'`
     컬럼 추가 (`/authorize`의 OIDC prompt 값). 상수 기본값이라 테이블 재작성이 없고,
     배포 중 생성된 기존 행은 빈 배열(= prompt 없음)로 읽힌다. 롤링 배포 중 구버전 파드가 만든
     auth_request(최대 10분)는 prompt를 저장하지 않으므로, 그 사이 `prompt=none` 요청은 prompt 없음처럼 처리될 수 있다
   → 020_auth_requests_max_age: auth_requests에 nullable `max_age BIGINT` 컬럼 추가
     (OIDC `max_age` 초). NULL 기본값이라 테이블 재작성이 없다. 롤링 배포 중 구버전 파드가
     만든 auth_request(최대 10분)는 max_age를 저장하지 않으므로 그 사이 `max_age` 요청은
     제한 없이 세션을 재사용할 수 있다
   → 019_user_identities_hosted_domain: user_identities에 nullable `hosted_domain TEXT`
     컬럼 추가 (Google Workspace `hd`, 클라이언트 `access` 정책용). 테이블 재작성이 없다.
     기존 행은 NULL이며 그 계정의 **다음 upstream 로그인 때** 채워진다. 그 전까지
     `google_workspace_domains` 규칙은 그 계정에 매칭되지 않는다

2. OIDC IdP 자격증명 발급
   → IdP(예: Google Cloud Console)에서 OAuth 2.0 Client ID/Secret 생성
   → **승인된 리디렉션 URI** (IdP에 등록하는 것):
     - `https://<authgate-domain>/login/callback` (브라우저 로그인용)
     - `https://<authgate-domain>/mcp/callback` (MCP 로그인용)
     - `https://<authgate-domain>/device/auth/callback` (Device 로그인용)
   → OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET 획득
     - Google 예시: OIDC_ISSUER_URL=https://accounts.google.com

   **주의: 이것은 upstream IdP redirect_uri다.**
   `clients.yaml`의 `redirect_uris`와 다른 것이다.
   - IdP redirect_uri = "IdP가 authgate로 돌려보내는 경로"
   - clients.yaml redirect_uri = "authgate가 각 앱으로 돌려보내는 경로"

3. 시크릿 생성
   → SESSION_SECRET: openssl rand -base64 32
   → signing_key.pem: authgate가 첫 실행 시 자동 생성 (또는 수동 생성)

4. 첫 번째 클라이언트 등록
   → clients.yaml 파일 생성 (아래 "클라이언트 등록" 참조)

5. 환경변수 설정 → 서버 시작
```

### 마이그레이션 번호 비고 (008 결번)

`migrations/`는 001–007 및 009 이후 번호로 구성되며 **008은 결번**이다. 008은
제거된 마이그레이션이 쓰던 번호라 재사용하지 않는다. golang-migrate가
`schema_migrations` 버전으로 상태를 추적하므로 결번은 런타임에 영향이 없다.
마이그레이션 정본은 `migrations/*.up.sql`이다.

버전 간 업그레이드 순서와 하위 호환이 깨지는 변경(특히 PII 암호화 → 평문 컬럼 제거 2단계)은
[010 업그레이드 & 하위 호환](010-upgrade-compatibility.md)을 따른다.

## 환경변수

| 변수 | 필수 | 기본값 | 설명 |
|------|------|--------|------|
| `PORT` | X | `8080` | 서버 포트 |
| `DATABASE_URL` | O | — | PostgreSQL 연결 문자열 |
| `DB_MAX_OPEN_CONNS` | X | `25` | DB 최대 오픈 커넥션 수 (`0`은 제한 없음) |
| `DB_MAX_IDLE_CONNS` | X | `25` | DB 최대 idle 커넥션 수 |
| `DB_CONN_MAX_LIFETIME_SEC` | X | `300` | DB 커넥션 최대 수명(초) |
| `DB_CONN_MAX_IDLE_TIME_SEC` | X | `120` | DB 커넥션 최대 idle 시간(초) |
| `SESSION_SECRET` | O | — | OIDC 암호화 키 (최소 32자) |
| `PUBLIC_URL` | O | — | 외부 접근 URL (예: `https://auth.example.com`) |
| `OIDC_ISSUER_URL` | X | `http://localhost:8082` | OIDC IdP issuer URL (예: `https://accounts.google.com`) |
| `OIDC_ISSUER_HOST_ALLOWLIST` | X | — | 콤마 구분 host 목록 (예: `accounts.google.com,login.microsoftonline.com`). 비어 있으면 검사 안 함. 설정되면 `OIDC_ISSUER_URL`의 host가 정확히 일치해야 시작. 운영자 misconfig 시 attacker IdP로 phishing redirect 되는 경로를 fail-fast로 차단한다. 운영에서 설정 권장 — `DEV_MODE=false`인데 비어 있으면 시작 시 경고 로그를 남긴다. |
| `OIDC_INTERNAL_URL` | X | — | 서버 간 OIDC 호출용 내부 URL (Docker/K8s 환경) |
| `OIDC_HTTP_TIMEOUT_SEC` | X | `10` | Upstream OIDC HTTP 호출 timeout(초) |
| `OIDC_CLIENT_ID` | X | `authgate` | OIDC Client ID |
| `OIDC_CLIENT_SECRET` | X | — | OIDC Client Secret (`DEV_MODE=false`에서 필수) |
| `PII_ENC_ROOT_KEY_ID` | △ | — | PII 암호화(ENC) root 식별자 (ADR-002). **PII at-rest 암호화는 필수** — 키 없이는 가입/로그인 불가(평문 컬럼 제거됨, migration 014). `DEV_MODE=false`는 4개 미설정 시 시작 거부, dev는 docker-compose가 더미 키 주입 |
| `PII_ENC_ROOT_SECRET` | △ | — | ENC root secret (base64, ≥32 bytes). 로그/감사에 노출 금지 |
| `PII_LOOKUP_ROOT_KEY_ID` | △ | — | lookup HMAC(LOOKUP) root 식별자 |
| `PII_LOOKUP_ROOT_SECRET` | △ | — | LOOKUP root secret (base64, ≥32 bytes). 로그/감사에 노출 금지 |
| `SESSION_TTL` | X | `86400` | 세션 수명 (초) |
| `ACCESS_TOKEN_TTL` | X | `900` | access_token 수명 (초, 15분) |
| `REFRESH_TOKEN_TTL` | X | `2592000` | refresh_token 수명 (초, 30일) |
| `REFRESH_TOKEN_REUSE_GRACE_SEC` | X | `5` | 인증된 confidential client에 한해 방금 교환된 refresh_token을 재사용 탐지 없이 한 번 더 받아주는 시간 (초, `0`~`60`, `0`이면 끔). 한 자격증명을 여러 세션이 동시에 갱신하는 클라이언트가 탈취로 오판돼 강제 로그아웃되는 것을 막는다. Public client/CIMD에는 적용하지 않는다. 규칙은 [Spec 005](005-token-lifecycle.md#재사용-유예-시간-reuse-grace) |
| `AUDIT_LOG_PII_RETENTION_DAYS` | X | `90` | **최종 사용자** 활동 기록의 PII(`user_id`, IP, User-Agent) 익명화 전 보존일. 최소 `30`. 법정 접속기록 의무는 취급자(운영자) 대상이라 여기 해당하지 않으며, 침해조사 목적의 기간이다 |
| `ADMIN_AUDIT_LOG_PII_RETENTION_DAYS` | X | `730` | **운영자 조치**(`admin.*`) 기록의 PII 익명화 전 보존일. 최소 `365` — 법정 접속기록 하한 |
| `SIGNING_KEY_PATH` | X | `signing_key.pem` | JWT 서명용 RSA private key 파일 경로. 운영에서는 persistent secret/volume로 주입 |
| `HTTP_READ_HEADER_TIMEOUT_SEC` | X | `5` | HTTP ReadHeader timeout(초) |
| `HTTP_READ_TIMEOUT_SEC` | X | `15` | HTTP Read timeout(초) |
| `HTTP_WRITE_TIMEOUT_SEC` | X | `30` | HTTP Write timeout(초) |
| `HTTP_IDLE_TIMEOUT_SEC` | X | `60` | HTTP Idle timeout(초) |
| `SHUTDOWN_TIMEOUT_SEC` | X | `10` | graceful shutdown timeout(초) |
| `METRICS_ADDR` | X | — | 별도 metrics listener 주소. 비워두면 disabled. 설정 시 Go runtime/process Prometheus metrics만 노출. 운영에서는 `127.0.0.1:9090` 또는 private network address 사용. |
| `DEV_MODE` | X | `false` | true 시: insecure 허용, cookie Secure=false |
| `ENABLE_MCP` | X | `true` | MCP optional adapter 활성화 여부 (`/mcp/*`, CIMD/resource binding) |
| `MCP_CIMD_HOST_ALLOWLIST` | X | `claude.ai,chatgpt.com` | CIMD 클라이언트 문서를 받아올 수 있는 host 목록 (콤마 구분, 소문자, 정확 일치 — 서브도메인은 따로 적어야 한다). 목록 밖 host의 `client_id`는 fetch 없이 `invalid_client`로 거부된다. `*` 한 항목만 두면 모든 host를 허용한다(권장하지 않음: MCP 채널은 동의 화면이 없어 누구나 만든 문서로 로그인된 사용자의 MCP 토큰을 받아갈 수 있다). 잘못된 값이면 시작을 거부한다. `ENABLE_MCP=false`면 쓰지 않는다 |
| `CLIENT_CONFIG` | X | `/etc/authgate/clients.yaml` | 클라이언트 설정 YAML 파일 경로 (없으면 무시) |
| `MIGRATIONS_PATH` | X | `/migrations` | golang-migrate 마이그레이션 디렉터리 경로 (Docker 이미지 기본, 로컬 개발은 `./migrations`) |
| `BRAND_NAME` | X | `authgate` | 디바이스 플로우 및 에러 페이지 좌측 상단에 표시되는 브랜드 이름 |
| `BRAND_LOGO_PATH` | X | (없음) | 페이지에 인라인 삽입할 SVG 마크 파일 경로. 미설정 시 이름만 표시. SVG가 아니거나 32KB 초과 시 기동 실패 |
| `BRAND_PRIMARY_COLOR` | X | (없음) | 버튼·포커스 강조색. `#185fc4` 같은 hex만 허용하며 그 외 값은 기동 실패 |
| `RATE_LIMIT_TOKEN_RPS` | X | `30` | 토큰성 엔드포인트 (`/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/device/authorize`, `/device/approve`) 초당 허용 요청 수 |
| `RATE_LIMIT_TOKEN_BURST` | X | `60` | 토큰 엔드포인트 버스트 허용 요청 수 (최솟값: 1) |
| `RATE_LIMIT_AUTH_RPS` | X | `10` | 인증 엔드포인트 (`/authorize`, `/login`, `/login/callback`, `/mcp/*`, `/device`, `/device/auth/callback`) 초당 허용 요청 수 |
| `RATE_LIMIT_AUTH_BURST` | X | `20` | 인증 엔드포인트 버스트 허용 요청 수 (최솟값: 1) |
| `TRUSTED_PROXIES` | X | — | 프록시 hop으로 신뢰할 CIDR 목록 (콤마 구분). 직전 hop이 이 범위에 속할 때만 클라이언트 IP 추정에 (1) `X-Envoy-External-Address` 헤더 (envoy/istio 가 직접 계산하므로 spoof 불가), (2) `X-Forwarded-For` rightmost-untrusted walk 폴백을 사용한다. 비워두면 모든 프록시 헤더 무시. 예: `10.244.0.0/16,127.0.0.1/32`. istio ingressgateway 등 reverse proxy 뒤에서 운영할 때만 설정. |

`ENABLE_MCP=false`인 경우 `clients.yaml`에 `login_channel: mcp` 항목이 있으면 서버 시작을 거부한다.

### 프로덕션 필수 조건

`DEV_MODE=false` (기본값)일 때 다음이 강제됨:
- `SESSION_SECRET`이 비어있거나 32자 미만이면 **서버 시작 거부**
- `PUBLIC_URL`이 `https://`로 시작하지 않으면 **서버 시작 거부** (issuer/authorization/token endpoint가 평문으로 광고되는 것을 방지)
- `OIDC_ISSUER_URL`이 `https://`로 시작하지 않으면 **서버 시작 거부**
- `OIDC_CLIENT_ID` 또는 `OIDC_CLIENT_SECRET`이 비어있으면 **서버 시작 거부**
- 쿠키 `Secure=true`
- `op.WithAllowInsecure()` 비활성

## 시크릿 관리

### SESSION_SECRET

```bash
# 생성
openssl rand -base64 32

# 용도: OIDC 프로바이더의 CryptoKey (state 암호화, CSRF 보호)
# 교체: 변경 시 진행 중인 로그인 플로우 실패 (auth_requests 무효화)
# 권장: 배포 후 변경하지 않음. 변경 필요 시 트래픽 낮은 시간에
```

### signing_key.pem (RSA 서명 키)

```bash
# 자동 생성: authgate 첫 실행 시 signing_key.pem 파일 생성 (2048-bit RSA)
# 수동 생성:
openssl genrsa -out signing_key.pem 2048
chmod 600 signing_key.pem

# 용도: JWT (access_token, id_token) 서명
# 교체: 아래 "키 로테이션" 참조
```

**Docker 빌드 컨텍스트에 포함 금지.** 리포 루트의 `signing_key.pem`이 `COPY . .`로 builder 레이어에 진입하면 GHCR에 푸시되는 빌더 캐시(예: `cache-to=type=registry`)나 멀티스테이지 캐시 공유를 통해 RSA private key가 노출될 수 있다. `.dockerignore`가 `signing_key.pem`, `*.pem`, `*.key`, `.env*`를 차단하고 있으니 변경 시 항상 유지하라. 운영에서는 키 파일을 빌드 컨텍스트에 두지 말고 Kubernetes Secret / Vault 등 런타임 시크릿으로 컨테이너에 주입하라.

### client_secret (각 앱별)

```bash
# 생성
SECRET=$(openssl rand -base64 32)
HASH=$(htpasswd -nbBC 10 "" "$SECRET" | cut -d: -f2)

# clients.yaml에 해시를 등록
# client_secret_hash: "$2a$10$...hashed..."

# 앱에게 평문 전달 (1회만, 이후 조회 불가)
```

## 키 로테이션

### 왜 필요한가

signing_key를 교체하면 기존 JWT의 서명을 검증할 수 없다.
**키 2개를 겹쳐 운영**해야 무중단 교체가 가능하다.

### 로테이션 절차

```
교체 전:
  JWKS = [key-1 (signing)]
  새 JWT → key-1으로 서명
  앱 → key-1으로 검증

Step 1: 새 키 추가 (기존 유지)
  JWKS = [key-2 (signing), key-1 (verify only)]
  새 JWT → key-2로 서명
  기존 JWT → key-1으로 검증 가능

Step 2: 겹치는 기간 대기 (최소 ACCESS_TOKEN_TTL = 15분)
  앱이 JWKS 캐시 갱신 → key-2 인식
  key-1 JWT는 만료되어 감

Step 3: 구 키 제거
  JWKS = [key-2 (signing)]
  key-1 JWT는 이미 전부 만료
```

### 구현 요구사항

```
signing key 저장:
  - 현재: 단일 파일 (signing_key.pem)
  - 필요: 2개 슬롯 (current + previous)

JWKS 엔드포인트:
  - 항상 유효한 키 전부 반환 (kid로 구분)
  - 앱은 JWT의 kid와 JWKS의 kid를 매칭하여 검증

앱 측 요구사항:
  - JWKS 캐시 + kid miss 시 재fetch
  - 추가 작업 불필요 (kid 매칭은 JWT 표준 동작)
```

### 로테이션 명령 (향후)

```bash
# 현재: 수동 (파일 교체 + 서버 재시작)
# 향후: CLI 명령 또는 API
authgate key rotate        # 새 키 생성 + 구 키 보존
authgate key list          # 현재 키 목록
authgate key remove <kid>  # 구 키 제거
```

## 클라이언트 등록

### YAML 파일 기반 (권장)

`clients.yaml` 파일로 클라이언트를 정의하면 authgate 시작 시 메모리에 로드된다.
DB 테이블은 사용하지 않는다.

**알 수 없는 필드가 있으면 시작을 거부한다.** 철자가 틀린 키가 조용히 무시되면, 그 키가 보안 설정일 때
보호가 적용되지 않은 채 서버가 뜨기 때문이다. 같은 이유로 **YAML 문서는 하나만** 허용한다(`---` 뒤의 두 번째 문서는 거부).
YAML anchor는 `clients` 목록 안에서 정의한다(최상위의 별도 anchor 키는 알 수 없는 필드다).

- **배포**: 이 파일에 새 필드를 쓰는 설정은 그 필드를 아는 버전을 먼저 배포한 뒤 적용한다.
- **롤백**: 더 오래된 버전으로 되돌리기 전에 그 버전이 모르는 필드를 ConfigMap에서 먼저 뺀다. 빼지 않으면 구버전이 시작을 거부해 파드가 재시작을 반복한다.

```yaml
# clients.yaml
clients:
  - client_id: my-web-app
    client_type: confidential
    client_secret_hash: "$2a$10$...bcrypt_hash..."
    login_channel: browser
    name: My Web App
    redirect_uris:
      - https://my-app.com/auth/callback
    allowed_scopes: [openid, profile, email]
    allowed_grant_types: [authorization_code, refresh_token]

  - client_id: my-cli
    client_type: public
    login_channel: browser
    name: My CLI Tool
    redirect_uris:
      - http://localhost:8080/callback
    allowed_scopes: [openid, profile, email, offline_access]
    allowed_grant_types: [authorization_code, "urn:ietf:params:oauth:grant-type:device_code", refresh_token]
```

필드 목록:

| 필드 | 필수 | 기본값 | 설명 |
|------|------|--------|------|
| `client_id` | O | - | URL 형태(CIMD) 불가, 공백 불가, 중복 불가 |
| `client_type` | O | - | `public` \| `confidential` |
| `client_secret_hash` | confidential만 | - | bcrypt 해시 |
| `skip_pkce` | X | `false` | PKCE S256 요구를 면제한다. **browser 채널의 confidential 클라이언트에서만** 허용 (public 또는 `login_channel: mcp`이면 로드 거부) |
| `id_token_userinfo_assertion` | X | `false` | 요청된 `profile`·`email` UserInfo claim을 ID token에도 포함한다. UserInfo endpoint를 호출하지 않는 클라이언트에만 사용 |
| `login_channel` | X | `browser` | `browser` \| `mcp` |
| `name` | O | - | 최대 256자 |
| `redirect_uris` | O | - | 1~10개 |
| `allowed_scopes` | O | - | 1개 이상 |
| `allowed_grant_types` | O | - | 1~3개 |
| `access` | X | 없음 (= 모든 계정 허용) | 이 클라이언트를 쓸 수 있는 계정 제한. 아래 "클라이언트 접근 정책" 참조 |

`skip_pkce`는 PKCE를 구현하지 않은 OIDC 라이브러리를 위한 탈출구다. 예를 들어
Gitea 는 `markbates/goth` 의 openidConnect 프로바이더를 쓰는데 `code_challenge` 를
보내지 않아, 이 옵션 없이는 `/authorize` 에서 `PKCE S256 required` 로 거부된다.
두 경우에는 설정할 수 없고 로드 시 거부된다.

- **public 클라이언트**: 시크릿이 없으므로 PKCE 가 인가 코드 가로채기에 대한 유일한 방어다.
- **`login_channel: mcp`**: PKCE S256 이 MCP 채널 계약의 일부다 ([Spec 004](004-mcp-login.md)). CIMD 로 등록되는 클라이언트는 전부 public 이라 이미 제외되지만, YAML 로 선언한 confidential mcp 클라이언트가 유일하게 빠져나갈 수 있는 경로였다.

이 옵션은 채널 정책을 완화하는 수단이 아니라, PKCE 를 **구현하지 못하는** 라이브러리를 위한 탈출구다.

### 클라이언트 접근 정책 (`access`)

`access`가 없는 클라이언트는 **모든 authgate 계정**이 쓸 수 있다. 시작 시 그런 클라이언트마다
`client has no access policy; every authgate account can use it` WARN 로그를 한 줄 남긴다.
의도적으로 공개한 클라이언트는 `access: public`으로 적으면 경고가 사라진다(동작은 같다).

```yaml
  - client_id: gitea
    # ...기존 필드...
    access:
      allow:                                   # 하나라도 맞으면 허용 (OR)
        google_workspace_domains: [corp.com]   # Google hd 클레임, 정확히 일치
        email_domains: [partner.com, "*.partner.com"]
        emails: [someone@gmail.com]
      deny:                                    # allow보다 먼저 평가, 맞으면 거부
        emails: [former@corp.com]
```

**평가 대상** — email, email_verified, Google hosted domain(`hd`). 이름은 보지 않는다.

- upstream 로그인 콜백(`/login/callback`, `/mcp/callback`, `/device/auth/callback`)은 **기존 계정이면 IdP가 방금 준 값과 저장된 값을 둘 다** 평가하고, 하나라도 거부되면 거부한다(가입은 방금 준 값만). 콜백 뒤의 모든 토큰 경로가 저장된 값을 쓰므로, 방금 준 값만으로 통과시키면 세션과 code를 만들어 놓고 교환에서 거부하게 된다.
- IdP 왕복이 없는 경로(세션 재사용, device 승인, code 교환, device polling, refresh)는 계정에 **저장된** 값으로 평가한다:
  email·email_verified는 **가입 당시** 값이고(이후 갱신하지 않는다), hd는 **마지막 로그인** 때 기록된 `hosted_domain`이다.

**평가 순서**:

1. `deny.emails`에 email이 있으면 거부 (`deny_listed`). 검증 여부와 무관
2. hd가 `google_workspace_domains`에 있으면 허용 (정확 일치, 대소문자 무시)
3. email이 **검증된** 경우에만: 도메인이 `email_domains`에 맞거나(`example.com`은 그 도메인만,
   `*.example.com`은 서브도메인만 — 도메인 자체는 불포함) 주소가 `emails`에 있으면(대소문자 무시) 허용
4. 그 외 거부 (`not_allowed`). 이메일 규칙에는 맞지만 미검증이면 `email_unverified`

**적용 지점** — 이 클라이언트로 토큰이 나가는 모든 경로:

| 경로 | 거부 시 |
|------|---------|
| `/login/callback` 신규 가입 | 계정을 **만들지 않고** `redirect_uri?error=access_denied&state&iss` |
| `/login/callback` 기존 계정, `/login` 세션 재사용 | `redirect_uri?error=access_denied&state&iss` (세션 생성·재사용 안 함) |
| `/mcp/callback`, `/mcp/login` 세션 재사용 | 〃 |
| `prompt=none` | `login_required`가 아니라 `access_denied` (대화형 로그인으로도 풀리지 않으므로) |
| `/device/auth/callback`, `/device/approve` | 403 "not allowed" 화면. 세션을 만들지 않거나 승인하지 않으며, device code는 pending으로 남는다 |
| authorization code 교환 (`/oauth/token`) | `invalid_grant` (400). 콜백 뒤 교환 전에 정책이 바뀌어도 토큰이 나가지 않는다. 이 검사는 zitadel이 PKCE와 클라이언트 인증을 확인하기 **전에** 호출하므로(`pkg/op/token_code.go` `AuthorizeCodeClient`), 거부 사유를 응답에 담지 않는다 — 계정 상태·정책 거부·subject 조회 실패·코드 만료가 모두 존재하지 않는 코드와 똑같은 `invalid_grant`로 나간다. 사유는 서버 로그(WARN)와 `auth.access_denied` 감사에만 남는다 |
| device code polling (`/oauth/token`) | 400 `access_denied` (zitadel이 device grant의 저장소 오류를 이렇게 감싼다). 승인된 code는 서버에 `approved`로 남지만, RFC 8628 클라이언트는 `access_denied`를 받으면 polling을 멈추므로 보통 처음부터 다시 로그인해야 한다 |
| refresh token 갱신 | `invalid_grant`. 토큰을 revoke하지 않으므로 정책을 되돌리면 다시 갱신된다 |

**정책 변경이 반영되는 시점** (`clients.yaml` 수정 + 재시작 후): 아직 교환하지 않은 authorization code, 승인됐지만 polling 전인
device code, 다음 refresh 모두 새 정책으로 평가된다. 이미 발급된 access token(JWT)은 만료(기본 15분)까지 유효하므로,
늦어도 access token 수명 안에 반영된다.

채널 불일치(`channel_mismatch`)와 비활성 계정(`account_inactive`/`auth.inactive_user`)이 정책보다 먼저 판정된다.
정책은 `pending_deletion` 복구보다 먼저 판정되므로, 거부된 로그인이 탈퇴 요청을 취소하지 않는다.
거부는 `auth.access_denied`로 기록된다 (주소 대신 이메일 도메인만, 가입 거부면 `user_id` 없음). `channel`은 콜백·세션 재사용·
code 교환이면 클라이언트의 로그인 채널(`browser`/`mcp`), device 콜백·승인·polling이면 `device`, refresh면 `refresh`다.

**검증** (위반 시 시작 거부): 알 수 없는 키(`access`·`allow`·`deny` 안 포함), `allow` 누락이나 항목 0개,
값이 없는 `access:`, `public` 이외의 스칼라. 도메인은 ASCII DNS 이름이어야 하고(국제화 도메인은 `xn--` 형태),
와일드카드는 선두 `*.`만, `*.com`처럼 점 없는 도메인 대상은 불가, `google_workspace_domains`는 와일드카드 불가.
이메일은 `@` 정확히 1개, 비어 있지 않은 로컬 파트, 유효한 도메인. 소문자로 정규화하고 중복은 합친다.
`deny`에는 `emails`만 쓸 수 있다.

**CIMD(동적 등록) MCP 클라이언트**는 `clients.yaml` 항목이 없으므로 항상 공개다.

**주의:**
- **`email_domains`·`emails`는 조직 소속을 증명하지 않는다.** IdP가 그 메일함을 검증했다는 뜻일 뿐이다. 누구나 회사 주소로 개인
  Google 계정을 만들 수 있고, 퇴사한 뒤에도 그 계정의 `email_verified`는 true로 남는다. 조직이 관리하는 계정만 받으려면
  `google_workspace_domains`(`hd`)를 쓴다.
- **저장된 email은 가입 당시 값이다.** authgate는 가입 후 `users.email`을 갱신하지 않는다. 로그인 콜백은 방금 준 주소와 저장된
  주소를 둘 다 요구하고, 세션 재사용·device 승인·code 교환·device polling·refresh는 가입 때 주소로 평가한다(hd는 마지막 로그인 값).
  그래서 IdP 쪽에서 주소가 바뀐 계정은 두 주소가 **모두** 규칙에 맞아야 들어온다.
- **`deny.emails`는 계정이 아니라 주소를 막는다.** 주소가 바뀐 계정은 옛 주소든 새 주소든 deny에 올리면 로그인 콜백에서는 막히지만,
  IdP 왕복이 없는 경로(이미 받은 refresh 등)는 가입 때 주소로만 평가된다. 특정 사람을 확실히 막으려면 **그 사람이 쓴 주소를 모두**
  `deny.emails`에 올리거나 계정을 비활성화(`disabled`)한다.
- **`hosted_domain`은 로그인 때 기록된다.** migration 019 이전에 로그인한 계정은 NULL이라, 다음 로그인 전까지
  `google_workspace_domains`로는 허용되지 않는다 (세션 재사용·device 승인·refresh 모두). Workspace를 떠난 계정은
  다음 로그인에서 NULL로 바뀌고 그때부터 거부된다.
- **롤백은 설정부터.** v0.10.7 이하 바이너리는 `clients.yaml`을 엄격 디코딩하지 않아 `access`를 **조용히 무시하고
  모든 계정을 허용**한다. 바이너리를 되돌리기 전에 `access` 제한이 풀려도 되는지 확인하거나 해당 클라이언트를 먼저 내린다.
  엄격 디코딩이 들어간 버전 중 `access`를 모르는 버전은 알 수 없는 키로 시작을 거부한다.

배포 환경별 마운트:
- Docker Compose: `volumes: ["./clients.yaml:/etc/authgate/clients.yaml:ro"]`
- Kubernetes: ConfigMap → volumeMount
- 로컬 개발: `CLIENT_CONFIG=./clients.yaml`

**authgate 코드 변경 0줄.** YAML 파일만 수정하고 재시작하면 끝.

### MCP 클라이언트 (CIMD)

MCP 클라이언트는 YAML에 등록하지 않는다. CIMD (`draft-ietf-oauth-client-id-metadata-document`)를 사용하여
클라이언트가 HTTPS URL에 메타데이터를 호스팅하고, authgate가 on-demand로 fetch한다.
메타데이터를 받아올 수 있는 host는 `MCP_CIMD_HOST_ALLOWLIST`(기본 `claude.ai`, `chatgpt.com`)로 제한된다.
새 MCP 클라이언트(예: 다른 AI 앱)를 쓰려면 그 `client_id` URL의 host를 목록에 추가하고 재시작한다.
거부된 요청은 `cimd: client_id host is not in MCP_CIMD_HOST_ALLOWLIST` 경고 로그에 host가 남는다.
상세는 [Spec 004](004-mcp-login.md)의 CIMD 섹션을 참조한다.

### 클라이언트 제거

YAML 클라이언트: YAML에서 제거 후 서버 재시작. 메모리에서 즉시 사라진다.

CIMD 클라이언트: 클라이언트가 메타데이터 URL을 내리면 CIMD 캐시 만료 후 `invalid_client`로 거부된다.
authgate에서 별도 작업은 불필요하지만, 기존 refresh_token은 DB에 남아있다가 자연 만료된다.

```text
클라이언트 제거 후 연관 데이터 수명:
  auth_requests  → 10분 내 만료 → cleanup 삭제
  device_codes   → 5분 내 만료 → cleanup 삭제
  refresh_tokens → 클라이언트 조회 실패로 갱신 불가 → 만료(최대 30일) 후 cleanup 삭제
```

cleanup의 만료/폐기 행 삭제는 한 번에 최대 10,000행씩 배치로 지우고 남은 행이
없어질 때까지 반복한다. 다운타임 등으로 백로그가 크게 쌓여도 수백만 행을 한
트랜잭션에서 지우며 테이블을 오래 잠그지 않는다. 한 cleanup 주기가 백로그를 다
비우지 못하면 다음 주기(10분 후)가 이어서 처리한다.

### CIMD 장애 대응

CIMD 메타데이터 URL이 응답하지 않거나 잘못된 응답을 반환하면 MCP 클라이언트의 인증이 실패한다.

```text
장애 유형별 authgate 동작:

CIMD URL 타임아웃 (3초 초과)
  → 즉시 실패 반환
  → 다음 요청에서 다시 fetch 시도

CIMD URL 5xx 응답
  → 즉시 실패 반환
  → 다음 요청에서 다시 fetch 시도

CIMD URL DNS 해석 실패
  → 즉시 실패 반환
  → 다음 요청에서 다시 fetch 시도

CIMD 메타데이터 내용 오류 (client_id 불일치, 필수 필드 누락 등)
  → 즉시 실패 반환
  → 문서 수정 후 다음 요청부터 정상화 가능
```

사용자 영향과 복구:

| 상황 | 사용자 영향 | 복구 방법 |
|------|-----------|----------|
| CIMD 일시 장애 (< 5분) | 성공 캐시 내 → 영향 없음 | 자동 복구 |
| CIMD 장기 장애 (> 5분) | 새 인증/토큰 갱신 실패 | CIMD URL 복구 후 자동 정상화 |
| 기존 access_token | 영향 없음 (JWT stateless) | 만료 전까지 유효 |
| refresh_token 갱신 | 실패 (`invalid_client`) | CIMD 복구 후 재로그인 |

감시 항목:

| 항목 | 방법 | 위험 신호 |
|------|------|----------|
| CIMD fetch 실패율 | 로그의 `cimd: fetch failed` / `cimd: HTTP` 에러 모니터링 | 급증 시 외부 CIMD 서버 장애 의심 |
| 동일 URL 반복 에러 | 로그에서 동일 client_id URL 반복 실패 패턴 확인 | 특정 CIMD URL 장기 장애 의심 |
| 응답 시간 | CIMD fetch latency | 3초 타임아웃 빈번 시 네트워크 이슈 |

## 일상 운영

### 컨테이너 이미지 검증

공식 이미지는 `authgate` 비특권 사용자로 실행하며 `/health`를 Docker
`HEALTHCHECK`로 사용한다. Dockerfile과 로컬 Compose의 기반 이미지는 태그와
digest를 함께 고정하고 Dependabot이 digest 변경을 제안한다.

릴리스 워크플로는 멀티 아키텍처 이미지와 함께 SBOM 및 SLSA provenance를
GHCR에 게시하고, GitHub OIDC로 이미지 digest에 대한 artifact attestation을
발급한다. 배포 자동화는 가변 `latest` 태그 대신 릴리스 digest를 사용하고
attestation을 검증한 뒤 승격해야 한다.

### 유저 정지

```sql
UPDATE users SET status = 'disabled', updated_at = NOW() WHERE email = 'bad@example.com';
-- 즉시 로그인/토큰 갱신 차단
-- 복구: UPDATE users SET status = 'active', updated_at = NOW() WHERE email = '...';
```

### audit_log 조회

```sql
-- 최근 로그인 이벤트
SELECT * FROM audit_log WHERE event_type = 'auth.login' ORDER BY created_at DESC LIMIT 50;

-- 특정 유저 이력
SELECT * FROM audit_log WHERE user_id = 'uuid-...' ORDER BY created_at DESC LIMIT 100;

-- 의심스러운 이벤트
SELECT * FROM audit_log WHERE event_type = 'auth.inactive_user' ORDER BY created_at DESC LIMIT 50;
```

위 조회는 `audit_log_event_created_idx` / `audit_log_user_created_idx`를 타도록
`event_type` 또는 `user_id` 필터와 `created_at DESC` 정렬을 함께 사용한다.
보존 cleanup의 `created_at < cutoff` 스캔은 `audit_log_created_brin_idx`가
보조한다.

## 모니터링

| 엔드포인트 | 용도 | 정상 응답 |
|-----------|------|----------|
| `GET /health` | liveness (프로세스 살아있나) | 200 `{"status":"healthy"}` |
| `GET /ready` | readiness (DB 연결 포함) | 200 `{"status":"ready"}` / 실패 시 503 `{"status":"not ready"}` |

`/metrics`는 public authgate listener에 등록하지 않는다. `METRICS_ADDR`가
비어 있으면 기본값은 disabled이며, 설정한 경우에만 별도 listener에서
Go runtime/process Prometheus metrics를 노출한다. 운영에서는
`127.0.0.1:9090` 또는 private network address처럼 외부 인터넷에서
접근할 수 없는 주소를 사용한다.

### 감시해야 할 것

| 항목 | 방법 | 위험 신호 |
|------|------|----------|
| DB 연결 | `/ready` 주기적 체크 | 503 반환 |
| cleanup 고루틴 | audit_log에 `auth.deletion_completed` 확인 | 30일+ pending_deletion 유저 존재 |
| signing_key | JWKS 엔드포인트 체크 | 키 0개 반환 |
| 디스크 | signing_key.pem 파일 존재 확인 | 파일 없음 → 재시작마다 키 변경 |
| runtime/process | `METRICS_ADDR` opt-in 후 내부 Prometheus scrape | goroutine, heap, GC, process resource 급증 |
| audit 쓰기 실패 | `slog.Error` 로그 (`audit log: marshal metadata`, `audit log: insert`) | 침해 탐지 인프라 silent broken (#208) |

### 서버 로그

서버 로그는 stderr에 slog text 형식(`time=… level=… msg=… key=value`)으로 나온다. 요청 처리 중 기록되는 줄에는 요청 속성이 자동으로 붙는다.

| 속성 | 붙는 요청 | 값 |
|------|----------|-----|
| `request_id` | 전체 | `X-Request-ID` (없거나 형식이 틀리면 새로 생성). ingress 접근 로그의 `request_id`와 같은 값이라 두 로그를 이어 볼 수 있다 |
| `path` | 전체 | 요청 경로. 쿼리 문자열은 넣지 않는다 (`state`, `code` 등이 섞이므로) |
| `client_id` | `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/device/authorize` | 폼의 `client_id`, 없으면 HTTP Basic 사용자명 (form-decode). Basic 비밀번호는 읽지 않는다 |
| `grant_type` | 위와 같음 | 폼의 `grant_type` |

클라이언트가 보낸 값(`client_id`, `grant_type`, `path`)은 256바이트까지만 남기고 잘린 경우 `…(truncated)`를 붙인다. 요청 본문은 앞 64KiB만 읽어 속성을 찾은 뒤 그대로 되돌려 놓으므로, 뒤이은 핸들러가 받는 본문과 폼 파싱 오류는 미들웨어가 없을 때와 같다.

토큰 발급 실패는 `level=WARN msg="request error"`로 남는다 (zitadel/oidc). 예:

```text
level=WARN msg="request error" oidc_error.parent=invalid_refresh_token oidc_error.type=invalid_grant request_id=… path=/oauth/token client_id=notegate-web grant_type=refresh_token
```

기동 실패(`log.Fatal`)는 `level=ERROR`로 남고 프로세스가 종료된다. net/http 서버의 연결 단위 오류(TLS handshake 실패 등)는 `level=WARN`이다.

### audit_log 쓰기 실패 모니터링

`Storage.AuditLog`는 best-effort write이므로 marshal/insert 실패가 비즈니스 트랜잭션을 차단하지 않는다. 그러나 감사 로그가 silent하게 누락되면 침해 탐지 능력 자체가 무력화되므로 실패는 구조화 로그로 남긴다.

**예외**: refresh token 재사용 감지 이벤트(`auth.refresh_reuse_detected`, `auth.refresh_family_revoked`)는 family revoke·tombstone과 **같은 트랜잭션**에서 `writeAuditLogTx`로 기록된다. 감사 insert가 실패하면 트랜잭션 전체가 롤백되므로 이 두 이벤트는 silent하게 누락되지 않는다(best-effort 경로와 다름). `auth.refresh_reuse_detected`는 제출마다, `auth.refresh_family_revoked`는 family당 tombstone을 만든 최초 요청에서만 기록된다([Spec 005](005-token-lifecycle.md#토큰-재사용-탐지-family-invalidation)).

| 로그 메시지 | 의미 |
|-------------|------|
| `audit log: marshal metadata` | `json.Marshal(metadata)` 실패 — 호출자 입력 형상 버그 |
| `audit log: insert` | `audit_log INSERT` 실패 — DB outage / 권한 / 디스크 |

## 백업/복구

| 대상 | 백업 방법 | 복구 |
|------|----------|------|
| PostgreSQL | `pg_dump` 정기 백업 | `pg_restore` |
| signing_key.pem | 파일 복사 (암호화 보관) | 파일 복원 → 재시작 |
| 환경변수 | `.env` 또는 시크릿 매니저 | 재설정 |

**signing_key.pem을 잃으면 모든 기존 JWT가 무효화됩니다.** 반드시 백업.
