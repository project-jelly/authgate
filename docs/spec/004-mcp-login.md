# Spec 004: MCP Authorization (OAuth 2.1 + Protected Resource)

## 개요

AI 도구(Claude Desktop, Cursor 등)가 원격 MCP 서버에 접근하기 위해 authgate에서 인증하고
`access_token + refresh_token`을 받는 플로우.

이 스펙의 핵심은 "MCP 로그인 화면"이 아니라, 아래 3개 컴포넌트가 어떤 계약으로 상호작용하는지다.

```text
+------------------+        +------------------+        +------------------+
|   MCP Client     |        |    MCP Server    |        |    authgate      |
| Claude/Cursor    |        | protected res.   |        | authorization sv |
+--------+---------+        +--------+---------+        +--------+---------+
         |                           |                           |
         | resource metadata 조회    |                           |
         |-------------------------->|                           |
         |<--------------------------|                           |
         |                           |                           |
         | auth server metadata 조회 |                           |
         |------------------------------------------------------>|
         |<------------------------------------------------------|
         |                           |                           |
         | authorize / token (CIMD)  |                           |
         |------------------------------------------------------>|
         |<------------------------------------------------------|
         |                           |                           |
         | access_token 사용         |                           |
         |-------------------------->|                           |
         |<--------------------------|                           |
```

**사용자는 브라우저 가입(Spec 001)이 완료된 상태여야 한다.**
MCP는 Browser/Device와 같은 "후속 로그인 채널"이며, 신규 가입 채널이 아니다.

## 본질

MCP는 브라우저 로그인과 같은 `authorization_code + PKCE`를 사용하지만,
역할 분리가 더 명확하다.

```text
Browser 로그인
  = 사용자가 직접 앱에 들어가기 위한 로그인

MCP Authorization
  = AI 도구가 특정 MCP 서버(resource)에 접근하기 위한 OAuth 2.1 계약
```

따라서 MCP에서는 다음 요소가 함께 성립해야 한다.

```text
1. authgate는 Authorization Server
2. MCP 서버는 Protected Resource
3. MCP 클라이언트는 resource 파라미터를 포함해 토큰을 요청
4. authgate는 MCP 전용 로그인 경로(/mcp/login, /mcp/callback)를 사용
5. MCP 서버는 받은 access_token이 "자기 resource 용도"인지 검증
```

## 전제

- authgate에서 `zitadel/oidc`는 **내장 라이브러리**다. 별도 서버가 아니다.
- MCP 클라이언트는 OAuth 2.1 `authorization_code + PKCE(S256)`를 지원해야 한다.
- authgate는 모든 `/authorize` 요청에 대해 `code_challenge` + `code_challenge_method=S256`를 필수로 강제한다.
- MCP 클라이언트는 RFC 8414 metadata를 사용할 수 있어야 한다.
- MCP 클라이언트는 CIMD (Client ID Metadata Document)를 지원해야 한다. DCR(RFC 7591)은 지원하지 않는다.
- **성공적으로 MCP 토큰을 발급받으려면** `user.Status = 'active'` 여야 한다.
- 사용자는 브라우저 접근 가능해야 한다.
- 원격 MCP 서버는 HTTP 기반 protected resource여야 한다.
- 예제 서버는 `Streamable HTTP` 방식으로 구현되어 있다.

## 역할

### MCP Client

```text
책임
  - protected resource metadata 조회
  - authorization server metadata 조회
  - CIMD: HTTPS URL에 client metadata document 호스팅
  - PKCE 생성
  - /authorize, /oauth/token 호출
  - localhost redirect 수신
  - access_token으로 MCP 서버 호출
```

### MCP Server

```text
책임
  - /.well-known/oauth-protected-resource 제공
  - 401 + WWW-Authenticate 에 resource_metadata 힌트 제공
  - access_token 검증
  - scope 부족 시 403 + WWW-Authenticate: Bearer error="insufficient_scope"
  - 자기 resource에 맞는 토큰만 허용
```

### authgate

```text
책임
  - /.well-known/oauth-authorization-server 제공 (`client_id_metadata_document_supported`는 `ENABLE_MCP` 설정값을 반영)
  - /authorize, /oauth/token, /oauth/revoke 제공
  - CIMD: URL 형식 client_id 감지 → metadata fetch → 검증
  - MCP 전용 로그인 경로(/mcp/login, /mcp/callback) 처리
  - user 상태 정책 적용
  - JWT access_token / opaque refresh_token 발급
```

## 관련 엔드포인트

### authgate

| Method | Path | 설명 |
|--------|------|------|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 Authorization Server Metadata (CIMD 지원 광고 포함) |
| GET | `/.well-known/openid-configuration` | OIDC Discovery fallback |
| GET | `/authorize` | Authorization Code + PKCE 시작 (URL 형식 client_id → CIMD fetch) |
| GET | `/mcp/login` | MCP 전용 로그인 진입 |
| GET | `/mcp/callback` | MCP 전용 upstream callback |
| POST | `/oauth/token` | code + code_verifier → 토큰 발급 |
| POST | `/oauth/revoke` | refresh_token 폐기 |
| GET | `/keys` | JWT 검증용 JWKS |
| GET | `/userinfo` | Bearer 토큰 기반 userinfo |

### MCP Server

| Method | Path | 설명 |
|--------|------|------|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 Protected Resource Metadata |
| POST/GET | `/mcp` | 실제 MCP transport endpoint |
| GET | `/health` | 헬스체크 |

## 표준

- OAuth 2.1 draft (`authorization_code + PKCE`, public client 전제)
- RFC 7636 (PKCE, `S256` 필수)
- RFC 8414 (OAuth Authorization Server Metadata)
- RFC 8707 (Resource Indicators)
- RFC 9728 (OAuth Protected Resource Metadata)
- draft-ietf-oauth-client-id-metadata-document (CIMD)
- MCP Authorization spec (2025-11-25)

## Browser / Device와의 차이

| 항목 | Browser (Spec 002) | Device (Spec 003) | MCP (이 스펙) |
|------|-------------------|-------------------|---------------|
| 누가 토큰을 쓰는가 | 웹 앱/사용자 | CLI 도구 | AI 도구 |
| 사용자 상호작용 | 브라우저 직접 | 브라우저 승인 | 브라우저 로그인 + 도구 자동 호출 |
| grant | auth code + PKCE | device_code | auth code + PKCE |
| discovery 시작점 | auth server | auth server | protected resource → auth server |
| 추가 파라미터 | 없음 | 없음 | `resource` |
| client 유형 | public/confidential | 보통 public | 보통 public |
| 로그인 경로 | `/login` | `/device` | `/mcp/login` |
| callback 경로 | `/login/callback` | `/device/auth/callback` | `/mcp/callback` |

## 플로우

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant R as MCP Server
    participant AG as authgate
    participant U as 사용자 브라우저
    participant G as Upstream IdP

    Note over C,G: 1. Protected Resource Discovery
    C->>R: GET /.well-known/oauth-protected-resource
    R-->>C: {resource, authorization_servers}

    Note over C,G: 2. Authorization Server Discovery
    C->>AG: GET /.well-known/oauth-authorization-server
    AG-->>C: {authorization_endpoint, token_endpoint, client_id_metadata_document_supported: (true|false), ...}

    Note over C,G: 3. Authorization Request (CIMD)
    C->>U: 브라우저 열기
    Note right of C: client_id = https://app.example.com/oauth/client.json (CIMD URL)
    U->>AG: GET /authorize?...&client_id=https://app.example.com/oauth/client.json&redirect_uri=http://localhost:PORT/callback&code_challenge=...&code_challenge_method=S256&resource=https://mcp.example.com
    AG->>AG: client_id가 URL → CIMD fetch
    AG->>C: GET https://app.example.com/oauth/client.json
    C-->>AG: {client_id, client_name, redirect_uris, ...}
    AG->>AG: client_id 일치 + redirect_uri 검증 + PKCE 검증
    AG->>AG: auth_request 생성
    AG-->>U: 302 /mcp/login?authRequestID=...

    Note over C,G: 4. MCP 전용 로그인
    U->>AG: GET /mcp/login?authRequestID=...
    alt prompt=login 또는 select_account
        AG-->>U: 302 Upstream IdP (prompt=select_account, 세션 재사용 안 함)
    else 유효한 브라우저 세션 + active
        AG->>AG: auth_request 완료
    else prompt=none + 세션 없음 또는 비활성
        AG-->>U: 302 redirect_uri?error=login_required&state=...&iss=...
    else 세션 없음
        AG-->>U: 302 Upstream IdP
        U->>G: 로그인
        G-->>U: 302 /mcp/callback?code=...&state=authRequestID
        U->>AG: GET /mcp/callback?code=...&state=...
        AG->>AG: 기존 유저 조회 + 상태 검사
        AG->>AG: session 생성 + auth_request 완료
    else 비활성/삭제 유예
        AG-->>U: 403 account_inactive
    else 미가입
        AG-->>U: 403 account_not_found
    end

    Note over C,G: 5. Token Exchange
    U-->>C: localhost callback ?code=...&state=...
    C->>AG: POST /oauth/token
    Note right of C: grant_type=authorization_code<br/>client_id=...<br/>code=...<br/>code_verifier=...<br/>resource=https://mcp.example.com
    AG->>AG: auth_request / user 상태 재검사
    AG-->>C: {access_token, refresh_token, id_token}

    Note over C,G: 6. MCP Resource Access
    C->>R: Authorization: Bearer <access_token>
    R->>R: signature / iss / exp / aud(resource) 검증
    R-->>C: MCP 응답
```

## Discovery

MCP에서는 보통 Authorization Server discovery보다 **Protected Resource discovery**가 먼저 온다.

```text
MCP Client
  -> MCP Server의 resource metadata 조회
  -> authorization_servers 목록 획득
  -> 그 중 authgate metadata 조회
```

### Protected Resource Metadata

MCP 서버는 `/.well-known/oauth-protected-resource`에서 최소한 아래를 제공해야 한다.

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com"]
}
```

### Authorization Server Metadata

authgate는 `/.well-known/oauth-authorization-server`와
`/.well-known/openid-configuration`을 같은 metadata 원천으로 제공한다.
zitadel/oidc의 전체 Discovery 문서에서 endpoint, signing algorithm, subject type,
claims, scope와 인증 방식을 재사용하고 AuthGate가 허용하는 response/grant만 좁힌다.
두 경로는 최소한 아래를 제공한다.

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
  "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true
}
```

`client_id_metadata_document_supported` 값은 두 경로 모두 런타임 설정
`ENABLE_MCP`에 따라 결정되며, 비활성화 시에도 `false`로 명시한다.
implicit·JWT bearer grant는 광고하지 않는다. 실제 클라이언트의 허용 grant,
Gitea용 `skip_pkce` 예외와 MCP resource 정책은 기존대로 별도 검증한다.

`/oauth/token`의 성공·오류 응답은 [Spec 005](005-token-lifecycle.md#토큰-응답의-캐시-금지)의
캐시 금지 계약을 따른다.

`token_endpoint_auth_methods_supported` / `revocation_endpoint_auth_methods_supported` / `introspection_endpoint_auth_methods_supported`는 zitadel/oidc OP가 실제로 받아들이는 인증 방식 집합과 일치해야 한다 (RFC 8414 §2). 컨피덴셜 클라이언트는 이 광고 값을 신뢰해 자격증명 위치를 고를 수 있으므로 누락된 항목이 있으면 디스커버리 기반 클라이언트가 silently 실패한다. `/oauth/introspect`는 zitadel이 기본 마운트하지만 `ClientIDFromRequest`가 Basic 자격증명만 `authenticated=true`로 표시하므로 introspection 광고 집합은 token/revocation보다 좁다.

RFC 9207에 따라 성공 및 redirect 가능한 오류 authorization response에는 `iss`를 포함한다. 값은 metadata의 `issuer`와 정확히 같으며, 클라이언트는 저장해 둔 issuer와 단순 문자열 비교로 검증한다. 로그인 화면으로 향하는 AuthGate 내부 redirect에는 `iss`를 붙이지 않는다.

## Client ID Metadata Document (CIMD)

MCP 클라이언트는 어떤 MCP 서버에 연결될지 사전에 알 수 없기 때문에,
사전 등록 없이 클라이언트를 식별할 수 있는 방법이 필요하다.

authgate는 CIMD (`draft-ietf-oauth-client-id-metadata-document`)를 지원한다.
MCP 클라이언트는 HTTPS URL에 메타데이터 JSON을 호스팅하고, 그 URL을 `client_id`로 사용한다.

```text
MCP 클라이언트가 호스팅하는 메타데이터 예시:
GET https://app.example.com/oauth/client.json

{
  "client_id": "https://app.example.com/oauth/client.json",
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

`grant_types`에 authgate가 지원하지 않는 grant가 추가로 있어도, `authorization_code`가 포함되어 있으면 문서 자체는 거부하지 않는다. authgate는 내부 `ClientModel`에 `authorization_code`와 `refresh_token`만 반영한다.

authgate의 CIMD 처리:

```text
/authorize?client_id=https://app.example.com/oauth/client.json&...
  1. client_id가 URL 형식인지 감지 (HTTPS + path 포함)
  2. client_id의 host가 MCP_CIMD_HOST_ALLOWLIST에 있는지 확인 (없으면 fetch 없이 invalid_client)
  3. 해당 URL에서 메타데이터 JSON fetch
  4. 검증:
     - client_id 필드가 fetch한 URL과 정확히 일치
     - redirect_uri가 메타데이터의 redirect_uris에 포함
  5. 검증 성공 → 메모리에서 ClientModel 생성 → 플로우 진행
```

### URL-form static client_id 금지

`clients.yaml`의 정적 등록 항목 중 `client_id`가 CIMD URL 형식 (HTTPS + path 포함)이면
설정 로드 시점에 거부한다. `ResolveClient`는 정적 in-memory 맵을 CIMD fetcher보다 먼저
조회하므로, URL 형식 정적 등록을 허용하면 CIMDFetcher의 HTTPS / content-type / redirect /
size 검증을 전부 우회하는 고리가 생긴다. 따라서:

- 정적 client_id는 비-URL 형식이어야 한다 (예: `my-app`, `mcp-cli`).
- URL 형식 client_id를 쓰려면 정적 등록 없이 dynamic CIMD 경로로만 진입한다.
- 위반 시 `LoadClientConfig`가 `URL-form (CIMD-shaped) client_id cannot be registered statically` 에러를 반환한다.

CIMD가 DCR을 대체하는 이유:

| 항목 | DCR | CIMD |
|------|-----|------|
| 서버 저장 | client_id를 DB에 저장 (누적) | **저장 없음** (on-demand fetch) |
| 멀티 서버 | 서버마다 다른 client_id | **모든 서버에서 동일 URL** |
| 멀티 파드 | 공유 DB 필요 | **공유 상태 없음** |
| 삭제/정리 | cleanup job 필요 | **불필요** |

### CIMD 네트워크/보안 규칙

CIMD fetch의 네트워크 제약. IETF draft에서 MUST/SHOULD인 것과 authgate 자체 정책을 구분한다.

| 규칙 | 근거 | 값 |
|------|------|-----|
| HTTPS 필수 | IETF draft MUST | `https://` + path 필수 |
| host 허용 목록 | authgate 정책 | `client_id`의 host가 `MCP_CIMD_HOST_ALLOWLIST`(기본 `claude.ai`, `chatgpt.com`)에 정확히 일치해야 한다. 포트는 비교하지 않는다. 목록 밖이면 요청 없이 거부하고 캐시·실패 카운트에도 남기지 않는다. CIMD는 문서 하나만 서빙하면 누구나 클라이언트가 되고 redirect_uris도 스스로 정하는데, MCP 채널은 기존 세션이 있으면 동의 화면 없이 승인한다. 허용 목록이 없으면 공격자 문서로 만든 authorize 링크 한 번에 로그인된 사용자의 MCP 토큰이 공격자 redirect_uri로 간다. 목록은 개별 클라이언트가 아니라 host 운영자를 신뢰한다: 그 host의 문서는 redirect_uris가 host 자신의 콜백(또는 사용자 로컬)을 가리키고, 콜백이 로그인을 시작한 사용자 세션에 state를 묶는다고 본다 |
| private/loopback/unspecified IP 거부 | IETF draft SHOULD (SSRF) | `0.0.0.0`, `::`, `127.0.0.1`, `10/8`, `172.16/12`, `192.168/16`, link-local, multicast 전부 차단 |
| 특수용도 대역 거부 | authgate 정책 (SSRF) | CGNAT `100.64/10`(RFC 6598 — EKS 등 클라우드 파드 대역), `192.0.0/24`, TEST-NET 3종, `198.18/15`(벤치마킹), `240/4`, NAT64 `64:ff9b::/96`, `100::/64`, `2001:db8::/32` 차단 |
| IPv4-mapped IPv6 정규화 | authgate 정책 | `::ffff:x.x.x.x` → IPv4로 변환 후 검사 |
| DNS resolve → 검증된 IP로 직접 dial | authgate 정책 (DNS rebinding 방지) | resolve와 connect 사이 TOCTOU 제거 |
| 리다이렉트 차단 | authgate 정책 | 301/302/307/308 모두 거부. CIMD URL이 곧 client_id이므로 다른 URL로의 이동은 허용 불가 |
| 타임아웃 | authgate 정책 | 연결 3초, TLS handshake 3초, 전체 3초 |
| 응답 크기 | authgate 정책 | 10KB 초과 시 거부 |
| Content-Type 검증 | IETF draft MUST | `application/json`만 허용 |
| userinfo in URL 거부 | authgate 정책 | `https://user:pass@host/path` 형식 차단 |
| fragment 거부 | authgate 정책 | `#` 포함 시 차단 (fragment는 서버로 전송되지 않음) |
| query 허용 | authgate 정책 | `?` 허용. ChatGPT 등 일부 CIMD 제공자는 `?token_endpoint_auth_method=none` 같은 쿼리를 포함한 `client_id`로 요청하면서, 문서에는 쿼리 없는 URL을 `client_id`로 서빙한다. 문서 값은 fetch URL과 정확 일치하거나 fetch URL에서 쿼리만 제거한 값과 일치해야 한다(아래 검증 규칙). 캐시 key·rate limit·ClientModel 신원은 모두 요청된(쿼리 포함) `client_id`를 그대로 쓰므로 authorize/token 간 신원이 일관되고, redirect_uris는 항상 문서 소유자가 발행한 값이다 |

### CIMD 메타데이터 검증 규칙

| 필드 | 검증 | 거부 시 에러 |
|------|------|------------|
| `client_id` | 문서 내 값 == fetch한 URL (정확 일치), 또는 문서 내 값 == fetch한 URL에서 query만 제거한 값 (ChatGPT 호환. path 등 나머지 불일치는 거부) | `invalid_client` |
| `client_name` | 필수, 비어있으면 거부 | `invalid_client` |
| `redirect_uris` | 필수, 1개 이상 | `invalid_client` |
| `grant_types` | `authorization_code` 필수. `refresh_token`은 지원하며, 그 외 grant는 authgate 내부 ClientModel에는 반영하지 않는다. 비어있으면 `authorization_code` 기본 | `invalid_client` |
| `response_types` | `code`만 허용 | `invalid_client` |
| `token_endpoint_auth_method` | `none`만 허용 (public client). 비어있으면 `none` 기본 | `invalid_client` |

### CIMD 입력 제한

CIMD 메타데이터 문서의 필드별 크기/개수 제한. 문서 전체 크기는 10KB로 제한되며, 개별 필드도 아래 상한을 초과하면 거부한다.

| 필드 | 제한 | 이유 |
|------|------|------|
| 문서 전체 | 10KB | 네트워크/파싱 비용 제한 |
| `client_id` (URL) | 2048자 | URL 길이 실용 상한 |
| `client_name` | 256자 | 표시용, UI 오버플로 방지 |
| `redirect_uris` | 최대 10개, 각 2048자 | 과도한 등록 방지 |
| `grant_types` | 최대 8개 | 대형 metadata 방어. authgate는 지원 grant만 선택적으로 사용 |
| `response_types` | 최대 1개 (`code`) | 허용 값이 1종뿐 |
| `token_endpoint_auth_method` | `none` 고정 | 허용 값이 1종뿐 |

YAML 클라이언트(`clients.yaml`)도 입력 크기/개수 검증 원칙은 동일하게 적용한다. 단, 허용 grant/auth 값 집합은 채널 정책에 따라 다르며 서버 시작 시 `LoadClientConfig` 검증에서 처리한다.

### CIMD 캐시 정책

IETF draft 권장사항에 맞춰 성공 응답의 HTTP 캐시 헤더를 적용하되,
CIMD 메타데이터의 정적 특성과 outbound-amplification 방어를 위해
최소 floor TTL을 강제한다. 실패 응답도 짧은 부정 캐시 + 실패 쿼터로
방어한다.

| 항목 | 값 | 이유 |
|------|-----|------|
| **성공 캐시 TTL** | `Cache-Control`(`max-age`, `no-store`, `no-cache`) 해석 후 5초 floor 적용 | 짧거나 부재한 캐시 지시로 인한 outbound 증폭 방어 (#158) |
| **성공 캐시 TTL fallback** | 5분 | 캐시 헤더가 없을 때 기본값 |
| **실패 응답 부정 캐시** | 30초 | 동일 client_id 반복 실패 시 outbound HTTP 차단 (#156) |
| **실패 쿼터** | 5분 윈도우 내 5회 실패 시 후속 요청 즉시 거부 | 부정 캐시 만료 후에도 amplification 방지 (#156) |
| **동시 요청 합치기 (singleflight)** | 동일 정규형 client_id에 대해 1개만 실행 | cache miss 시 thundering herd 방지 |
| **캐시 키** | 정규형 client_id (lowercase host, default port 제거, path.Clean, ASCII 한정) | URL alias로 위 방어선을 우회하지 못하도록 비정규형 입력은 게이트에서 거부 (#156) |
| **캐시 크기 상한** | 4096 엔트리 (bounded LRU) | 고유 client_id URL 폭주로 인한 OOM 방지 (#159) |
| **재시도/백오프** | 없음 (실패 쿼터로 대체) | 실패 시 즉시 에러 반환 |

```text
캐시 동작 흐름:

요청 → 정규형 client_id 검증
  ├─ 비정규형 → 즉시 거부 (HTTP 호출 없음)
  └─ 정규형 → cache hit?
       ├─ 성공 캐시 (TTL 내) → 캐시된 ClientModel 반환
       ├─ 부정 캐시 (TTL 내) → 캐시된 에러 즉시 반환 (HTTP 호출 없음)
       └─ cache miss / 만료
            → 실패 쿼터 초과? → 즉시 거부 (HTTP 호출 없음)
            → singleflight로 동시 요청 합치기
                 └─ fetch 실행
                      ├─ 성공 → 서버 TTL ∨ 5초 floor 로 정상 캐시
                      └─ 실패 → 30초 부정 캐시 + 실패 쿼터 카운트
```

### CIMD 조회 시점별 동작

`GetClientByClientID`는 authorize, token exchange, refresh, revoke 모든 경로에서 호출된다.
CIMD 클라이언트(URL 형식 client_id)는 **매 호출 시 캐시 기반으로 조회**한다.

```text
/authorize
  → CIMD fetch (캐시 기반)
  → client_id 일치, redirect_uri, authorization_code 포함 확인
  → 지원 grant만 내부 ClientModel에 반영

/oauth/token (code exchange)
  → CIMD fetch (캐시 기반)
  → client_id 존재 확인 + grant_types에 authorization_code 포함 확인

/oauth/token (refresh)
  → CIMD fetch (캐시 기반)
  → client_id 존재 확인 + grant_types에 refresh_token 포함 확인
  → fetch 실패 시 invalid_client → refresh 거부

/oauth/revoke
  → CIMD fetch (캐시 기반)
  → client_id 존재 확인
  → fetch 실패 시에도 RFC 7009에 따라 200 반환
```

### CIMD URL 소멸 / 메타데이터 변경 시 동작

클라이언트가 메타데이터 URL을 내리면:

```text
1. 성공 캐시 TTL 내 (최대 5분): 기존 캐시로 정상 동작
2. 캐시 만료 후: re-fetch 실패 → invalid_client
   → refresh 거부 (사용자는 재로그인 필요)
   → DB의 refresh_token은 갱신 불가 상태로 남음
   → 만료 후 cleanup이 자연 삭제
3. 다음 요청 시마다 다시 fetch 시도 (URL이 복구되면 정상화)
```

메타데이터 내용이 중간에 바뀐 경우:
- 캐시 만료 후 re-fetch 시 새 메타데이터 적용
- `redirect_uris` 변경: `/authorize` 시점에만 검증하므로 기존 토큰에는 영향 없음
- `grant_types` 변경: code exchange/refresh 시 재검증하므로 **영향 있음**. `authorization_code`가 빠지면 클라이언트 조회가 실패하고, `refresh_token`이 빠지면 새 refresh_token 발급/갱신이 거부된다. 지원하지 않는 추가 grant는 무시된다.

## 채널 정책

MCP는 Browser와 **같은 code flow를 쓰더라도 정책 채널은 별도**다.

```text
Browser path: /login -> /login/callback
MCP path:     /mcp/login -> /mcp/callback
```

상태 규칙:

```text
user.Status = active
  -> MCP 허용

user.Status = pending_deletion / disabled / deleted
  -> MCP 차단 (account_inactive)
```

MCP는 Device와 같은 "후속 로그인 채널"이다.
가입과 `pending_deletion` 복구는 Browser 채널에서만 처리한다.

### 채널 바인딩 (cross-channel completion 차단)

`/login`, `/login/callback`, `/mcp/login`, `/mcp/callback` 모두 진입 시점에
`auth_request.client_id`로 클라이언트의 `login_channel`을 조회하고, 현재 경로와
기대 채널이 다르면 거부한다 (`channel_mismatch`, HTTP 400). 거부 시
`auth.channel_mismatch` audit 이벤트가 기록되며 `metadata.expected_channel`,
`metadata.actual_channel`, `metadata.client_id` 필드를 포함한다.

이는 공격자가 MCP 클라이언트의 `auth_request`를 브라우저 `/login` 자동승인
경로로 흘려서 MCP 전용 정책 (기존 계정 요구, `pending_deletion` 거부, MCP
callback resource 검증) 을 우회하는 것을 막는다.

### prompt 파라미터

`/mcp/login`은 `/login`과 같은 규칙으로 `auth_requests.prompt`를 따른다 ([Spec 002](002-browser-login.md#prompt-파라미터)).

- `login`, `select_account`: 세션을 재사용하지 않고 상위 IdP에 `prompt=select_account`를 붙여 보낸다.
- `none`: `active` 세션이면 그대로 완료한다. 세션이 없거나 계정이 MCP에서 허용되지 않는 상태(`pending_deletion`, `disabled`, `deleted`)면
  `auth.inactive_user`(상태가 문제일 때)를 기록하고 클라이언트 `redirect_uri`로 `error=login_required`, `state`, `iss`를 붙여 `302`한다.
- `consent`와 prompt 없음: 기존 동작. authgate에는 동의 화면이 없으며, CIMD 3rd-party 클라이언트에도 마찬가지다.
- `max_age`: 세션 나이가 `max_age`를 넘으면 재사용하지 않고 상위 IdP로 보낸다. `prompt=none`이면 `login_required`. 상세는 [Spec 002](002-browser-login.md)의 `max_age`·`auth_time` 항목.

### 클라이언트 접근 정책

`clients.yaml`에 등록된 MCP 클라이언트에 `access` 정책이 있으면([009 운영](009-operations.md#클라이언트-접근-정책-access))
`/mcp/login` 세션 재사용(비활성 계정 → 채널 검증 → 정책)과 `/mcp/callback`(채널 검증 → hd 기록 → 비활성 계정 → 정책)에서
평가하고, 거부 시 `redirect_uri`로 `error=access_denied`, `state`, `iss`를 붙여 `302`한다(`prompt=none` 포함).
콜백은 IdP가 방금 준 email·email_verified·hd로, 세션 재사용은 저장된 값으로 평가한다. code 교환에서도 저장된 값으로 다시 평가해
거부되면 400 `invalid_grant`다.
CIMD 클라이언트는 등록 항목이 없으므로 정책이 없다(공개).

## Resource Parameter

MCP에서 `resource`는 부가 옵션이 아니라, "이 토큰을 어느 MCP 서버에서 쓸 것인가"를 나타내는 식별자다.

```text
/authorize?...&resource=https://mcp.example.com
/oauth/token?...&resource=https://mcp.example.com
```

의미:

```text
이 access_token은 https://mcp.example.com resource에 대한 접근 용도다.
```

## 토큰 의미

MCP access_token 계약은 아래와 같다.

```text
access_token
  -> 특정 resource 용도
  -> MCP 서버는 자기 resource용 토큰만 수용
```

authgate는 authorize 단계와 token 단계 모두에서 같은 `resource`를 취급해야 한다.

```text
1. /authorize 요청의 resource를 auth_request에 저장
2. /oauth/token 요청의 resource와 auth_request.resource를 대조
3. 불일치하면 invalid_target 등으로 거부
4. access_token의 aud는 canonical resource로 발급
```

`resource` 파라미터는 channel별로 강제된다 (RFC 8707 §2.2 AS-side policy):

| login_channel | resource 처리 |
|---------------|--------------|
| `mcp`         | **필수** — 누락 시 `invalid_target` |
| `browser`     | **금지** — 포함 시 `invalid_target` |
| `device`      | **금지** — 포함 시 `invalid_target` |

또한 단일 audience 정책: `resource=` 파라미터가 두 번 이상 나타나면 HTTP 400 `invalid_target`. 이는 `aud=[A,B]` 같은 다중 청자 토큰을 통한 audience smuggling을 차단한다.

MCP 서버가 검증해야 하는 항목:

```text
1. JWT signature
2. iss = authgate issuer
3. exp = 만료 안 됨
4. aud 또는 동등한 resource 의미 = 내 canonical resource
```

즉 MCP 서버는 단순 JWT 검증기가 아니라,
**"이 토큰이 내 resource 용도인가?"** 를 확인하는 protected resource여야 한다.

## 상태 저장과 수명

authgate는 stateless access token만 발급하는 서버가 아니라, 상태를 가진 인증 게이트다.

```text
메모리
├─ 클라이언트 설정   : clients.yaml → 시작 시 로드
├─ CIMD 클라이언트  : URL에서 on-demand fetch (캐시)

DB
├─ auth_requests    : authorize/code 흐름의 단기 상태
├─ sessions         : 브라우저 세션
├─ refresh_tokens   : refresh rotation 상태
├─ users            : 사용자 상태
└─ identities       : upstream identity 연결
```

수명:

```text
클라이언트 설정
  -> 서버 프로세스 수명 (YAML에서 로드)

CIMD 클라이언트
  -> HTTP 캐시 수명 (요청마다 또는 캐시 만료 시 re-fetch)

auth_requests
  -> 짧은 상태 (authorize ~ code exchange)

sessions
  -> 세션 TTL 동안 유지

refresh_tokens
  -> 만료 또는 revoke 후 cleanup
```

`resource`는 `auth_request`와 함께 짧게 유지되는 단기 상태다.
code exchange가 끝나면 auth_request와 함께 정리된다.

## 에러 케이스

| 상황 | 에러 코드 | HTTP | 설명 |
|------|----------|------|------|
| 미등록 클라이언트 | `invalid_client` | 400 | YAML에 없고 CIMD fetch도 실패 |
| CIMD fetch 실패 | `invalid_client` | 400 | URL 접근 불가, 타임아웃, SSRF 차단 |
| CIMD client_id 불일치 | `invalid_client` | 400 | 메타데이터의 client_id가 fetch URL과 다름 |
| PKCE 없음 / plain | `invalid_request` | 400 | `S256` 필수 |
| redirect_uri 불일치 | `invalid_request` | 400 | 메타데이터의 redirect_uris에 포함되어야 함 |
| 미가입 사용자 | `account_not_found` | 403 | Browser에서 먼저 가입 필요 |
| 비활성 계정 | `account_inactive` | 403 | `pending_deletion`, `disabled`, `deleted` |
| `prompt=none` + 유효한 세션 없음 또는 비활성 계정 | `login_required` | 302 | 클라이언트 `redirect_uri`로 오류 응답 (`state`, `iss` 포함) |
| 클라이언트 `access` 정책이 계정 거부 | `access_denied` | 302 | 클라이언트 `redirect_uri`로 오류 응답 (`state`, `iss` 포함). 세션 생성 안 함 |
| auth code 발급 후 상태 변경 | `invalid_grant` | 400 | `/oauth/token` 시점에 최종 상태 재검사 |
| code_verifier 불일치 | `invalid_grant` | 400 | PKCE 검증 실패 |
| resource 검증 실패 | `invalid_target` 등 | 400 | authorize/token resource 불일치 또는 허용되지 않은 resource |

## 보안 요구사항

- PKCE `S256` 필수
- public client 기본 (`token_endpoint_auth_method = none`)
- CIMD redirect_uri는 메타데이터 문서의 redirect_uris와 정확히 일치해야 함
- CIMD fetch 시 SSRF 방어: private/loopback IP 거부, 타임아웃 3초, 크기 10KB 제한
- `user.Status = active`일 때만 MCP 토큰 발급
- `/authorize`와 `/oauth/token` 모두에 동일한 `resource` 파라미터를 포함
- authgate는 `auth_requests.resource`를 저장하고 token 교환 시 대조
- MCP access_token의 `aud`는 canonical resource로 발급
- refresh_token은 해시 저장 + rotation
- MCP 서버는 access_token을 모든 요청마다 검증
- MCP 서버는 `iss`, `exp`, signature뿐 아니라 `aud/resource`를 검증
- access_token은 URI query string에 넣지 않는다

예제 서버는 HTTP 기반 원격 MCP 서버의 샘플이며, transport 자체보다 protected resource 계약을 우선 설명한다.

## 다른 스펙 참조

| 참조 | 내용 |
|------|------|
| [Spec 001](001-signup.md) | 가입은 Browser 전용 |
| [Spec 002](002-browser-login.md) | Browser code flow와 공통되는 로그인 골격 |
| [Spec 003](003-device-login.md) | Device는 별도 grant와 별도 상태 저장을 사용 |
| [Spec 005](005-token-lifecycle.md) | refresh/revoke/JWKS 검증 공통 규칙 |
| [Spec 007](007-data-model.md) | `auth_requests`, `refresh_tokens` 스키마, 클라이언트 설정 |
