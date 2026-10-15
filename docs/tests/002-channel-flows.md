# Test 002: 채널 플로우 테스트

## 목적

Browser / Device / MCP / Refresh / Logout / Delete 각 채널이 공통 상태기계를 깨지 않고 동작하는지 검증한다.

## Browser

### Browser 가입 / 로그인

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-001` | 미가입 | Browser 로그인 | Spec 001 가입 서브플로우 진입 | 가입은 Browser만 가능 |
| `browser-002` | 기존 `active` | Browser 로그인 | auto-approve + 토큰 발급 | 정상 로그인 |
| `browser-003` | `pending_deletion` | Browser 로그인 | active 복구 + 새 세션 | 삭제 유예 복구 |
| `browser-004` | `disabled` | Browser 로그인 | `account_inactive` | 차단 |
| `browser-004b` | `deleted` | Browser 로그인 | Spec 001 신규 가입 서브플로우 진입 | 재가입 경로 |
| `browser-005` | `pending_deletion`, 복구 후 auth_request 완료 상태 반영 실패 | Browser 재로그인 | 다음 재시도에서 정상 완료 | 복구 후 재시도 멱등성 |

### prompt 파라미터 (Browser / MCP 공통)

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `login-prompt-001` | `active` 세션 | `prompt=none` → `/login`, `/mcp/login` | auto-approve | 세션 재사용 유지 |
| `login-prompt-002` | 세션 없음 | `prompt=none` → `/login`, `/mcp/login` | `redirect_uri?error=login_required&state&iss`, 기존 query 유지 | IdP·화면 없음 |
| `login-prompt-003` | Browser `disabled`/`deleted`, MCP `disabled`/`pending_deletion` 세션 | `prompt=none` | `login_required` + `auth.inactive_user` 1건 | 403 화면 대신 오류 응답 |
| `login-prompt-004` | mcp 클라이언트 auth_request | `prompt=none` → `/login` | `channel_mismatch` 화면 | 채널 검증이 redirect보다 먼저 |
| `login-prompt-005` | `active` 세션 | `prompt=login`, `select_account`, `login consent` | IdP redirect + upstream `prompt=select_account`, 세션 조회 없음 | 세션 재사용 안 함 |
| `login-prompt-006` | `active` 세션 / 세션 없음 | prompt 없음, `consent` | auto-approve / upstream prompt 없는 IdP redirect | 기존 동작 |
| `login-prompt-007` | - | `Storage.CreateAuthRequest`(prompt 있음/없음) | `GetAuthRequestModel`에서 같은 값, 없음은 빈 배열 | prompt 저장 |
| `login-prompt-008` | `pending_deletion` 세션 (browser) | `prompt=none` | `login_required`, 복구·완료 없음, `auth.inactive_user` 1 | 백그라운드 확인이 탈퇴를 취소하지 않음 |
| `login-prompt-009` | 만료된 auth_request (browser/mcp) | `/login` | 400 `auth_request_expired` | 만료는 500이 아님 |
| `browser-prompt-001` / `mcp-prompt-001` | 로그인 후 세션 쿠키 | `/authorize?prompt=select_account` → 로그인 경로 | `/fake-auth?...&prompt=select_account` | 실제 서버에서 세션 재사용 안 함 |
| `browser-prompt-002` / `mcp-prompt-002` | 세션 없음 | `/authorize?prompt=none` → 로그인 경로 | `302 /callback?error=login_required&state=test-state&iss=<issuer>` | RFC 9207 `iss` |
| `browser-prompt-003` / `mcp-prompt-003` | 로그인 후 세션 쿠키 | `/authorize?prompt=none` | code 발급 + 토큰 교환 성공 | 무화면 로그인 |
| `browser-prompt-004` | - | `/authorize?prompt=none login` | `invalid_request`, 로그인 경로로 가지 않음 | zitadel 검증 |

단위 테스트(`login-prompt-001`~`006`, `008`, `009`)는 `internal/service/login_unit_test.go`, `login-prompt-007`은
`internal/storage/codes_integration_test.go`, `*-prompt-00N` 통합 테스트는 `internal/integration/integration_prompt_test.go`에 있다.

### 클라이언트 접근 정책 (Browser / MCP / Device / Refresh)

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `client-access-001`~`004` | `access` 없음 / `public` / allow·deny 정책 | `Policy.Evaluate` | deny 우선, hd 정확 일치(NULL 불일치), 와일드카드 라벨 경계·상위 도메인 제외, 미검증 email은 이메일 규칙 불일치(`email_unverified`), ASCII 대소문자만 무시(켈빈 기호 불일치) | 평가 매트릭스 |
| `client-access-010`~`011` | - | `clientaccess.New` | 잘못된 도메인·`*.com`·점 없는 도메인·중간 `*`·hd 와일드카드·잘못된 이메일·빈 allow 거부, 정규화·중복 제거 | 설정 검증 |
| `client-access-020`~`021` | - | YAML `access` 디코딩 (KnownFields 켜짐/꺼짐 모두) | `public`·mapping 허용, 다른 스칼라·`allow` 누락·빈 `allow`·`access`/`allow` 안의 알 수 없는 키·`deny.email_domains` 거부 | 엄격 디코딩 |
| `client-access-030`~`031` | - | `LoadClientConfig` | 정책이 `ResolveClient`로 전달, `access: public`은 명시적 공개, 빈 `access:`/`null`/null을 가리키는 YAML alias 거부 | 시작 시 로드 |
| `client-access-200`~`202` | 미가입, 제한 클라이언트 | `/login/callback` | 거부: `access_denied` redirect, 계정·세션 없음, `auth.access_denied` 1(user_id nil, `signup: true`) / 허용: 가입 + hd 저장 | 계정 생성 **전** 차단 |
| `client-access-203`~`205` | 기존 계정 | `/login/callback` | 거부 시 세션 없음, 방금 받은 hd로 평가·기록, hd 기록 실패는 500 | 최신 hd |
| `client-access-206`~`207` | `disabled` / `pending_deletion` + 거부 정책 | `/login/callback`, `/login` | `account_inactive`(`auth.inactive_user`만) / `access_denied`, 복구 안 함 | 판정 순서 |
| `client-access-208` | 세션 (browser·mcp) | `/login`, `/mcp/login`, prompt 없음·`none` | 거부 계정 `access_denied`(login_required 아님), 저장된 hd 계정·공개 클라이언트는 auto-approve | 세션 재사용 |
| `client-access-209` | mcp 클라이언트 auth_request | `/login` | `channel_mismatch`, `auth.access_denied` 없음 | 채널 검증 우선 |
| `client-access-210` | 기존 계정 | `/mcp/callback` | 거부 시 세션 없음, hd 기록 | MCP 콜백 |
| `client-access-211` | 기존 계정 (저장 email ≠ IdP email) | `/login/callback`, `/mcp/callback`, `/device/auth/callback` | 저장 email 허용 + IdP email deny → 거부(`deny_listed`) / 저장 verified + IdP 미검증 → 거부(`email_unverified`) / 저장 email deny + IdP email 허용 → 통과, `auth.access_denied` 없음 | 콜백은 IdP가 준 email로 평가 |
| `client-access-220`~`221` | 세션 계정 | `/device/approve`, `/device/auth/callback` | 거부 시 403 + 읽을 수 있는 거부 메시지, 승인 안 함, 거부 버튼은 통과 / 콜백이 hd 기록 | Device |
| `client-access-300` | - | `Storage` 가입·`SetIdentityHostedDomain` | 모든 사용자 조회에 hosted_domain, 갱신·NULL 초기화, 같은 값은 쓰지 않음(xmin 불변), 최신 identity가 NULL이면 오래된 identity 값으로 대체 안 함 | 저장 |
| `client-access-301`~`305` | refresh token | `Storage` refresh (유예 끔/켬, 잠금 하 재검증, stateChecker 없음) | `invalid_grant` + `auth.access_denied` 1, 재사용 처리·tombstone 없음, 정책 복원 시 갱신 | Refresh |
| `client-access-100`~`105` | 실제 테스트 서버 + 제한 클라이언트 | 가입 거부 / 허용 email / hd 저장·이탈 / 세션 재사용 / refresh / deny 우선 | `302 /callback?error=access_denied&state=test-state&iss`, users 0 / 토큰 발급 / hd 컬럼 / 공개 test-client는 계속 재사용 / `invalid_grant` / `deny_listed` | 통합 |
| `client-access-106` | 콜백까지 끝나 code 보유 | 정책에 계정 deny 추가(`LoadClients`) 후 code 교환 | 400 `invalid_grant`, 토큰·refresh token 없음, `auth.access_denied` 1(`channel: browser`, `deny_listed`), 응답 본문이 존재하지 않는 code와 완전히 동일 | code 교환 재평가 + 인증 전 사유 비노출 |
| `client-access-107` | device code 승인됨 | 정책에 계정 deny 추가 후 polling → 정책 해제 후 polling | 400 거부, `auth.access_denied` 1(`channel: device`), code는 `approved` 유지 / 해제 후 200 토큰 | device polling 재평가 |

`client-access-001`~`021`은 `internal/clientaccess/clientaccess_test.go`, `030`~`031`은 `internal/storage/clients_test.go`,
`2xx`는 `internal/service/client_access_unit_test.go`, `300`~`305`는 `internal/storage/client_access_integration_test.go`,
`100`~`107`은 `internal/integration/integration_client_access_test.go`에 있다.

### Browser code → token 교환

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `browser-token-001` | `active` | POST `/oauth/token` (auth code) | 200 + 토큰 발급 | 정상 code exchange |
| `browser-token-002` | auth code 발급 후 `pending_deletion` 또는 `disabled/deleted`로 변경 | POST `/oauth/token` | `invalid_grant` | 토큰 발급 시점 재검사 |

## Device

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `device-001` | `active` | `/oauth/device/authorize` → approve | 토큰 발급 성공 | 정상 Device 로그인 |
| `device-002` | 미가입 | `/device/auth/callback` | `account_not_found` | Device에서 신규 가입 불가 |
| `device-003` | `pending_deletion` | `/device/auth/callback` | `account_inactive` | Browser 복구만 가능 |
| `device-004` | `disabled` 또는 `deleted` | `/device/auth/callback` | `account_inactive` | 차단 |
| `device-005` | approved state | 동시 polling 2회 | 정확히 1회만 성공 | consumed 원자성 |
| `device-006` | consumed state | 다시 polling | `invalid_grant` | 재사용 불가 |
| `device-007` | callback 시점 `active` | approve | 토큰 발급 성공 | approve 시점 재검사 통과 |
| `device-008` | callback 시점 `active`, approve 직전 `pending_deletion` 또는 `disabled/deleted`로 변경 | approve | `account_inactive` | approve 시점 차단 |
| `device-samesite` | 세션 없음 | `/device/auth/callback` | 302 `/device?user_code=…` + 세션 쿠키 `SameSite=Lax` | IdP 복귀 리다이렉트에서 쿠키 생존 ([Spec 003](../spec/003-device-login.md#세션-없이-승인-시-흐름)) |
| `device-samesite-2` | 유효 세션 | `/device?user_code=…` | 승인 화면 + device CSRF 쿠키 `SameSite=Strict` | 세션만 완화하고 CSRF는 조이는 조합 유지 |

## MCP

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `mcp-001` | `active` | `/authorize` → callback | 토큰 발급 성공 | 정상 MCP 로그인 |
| `mcp-002` | 미가입 | `/mcp/callback` | `account_not_found` | MCP에서 신규 가입 불가 |
| `mcp-003` | `pending_deletion` | `/mcp/callback` | `account_inactive` | Browser 복구만 가능 |
| `mcp-004` | `disabled` 또는 `deleted` | `/mcp/callback` | `account_inactive` | 차단 |
| `mcp-005` | auth code 발급 후 `code_verifier` 없이 토큰 교환 | `POST /oauth/token` | 토큰 발급 실패 | PKCE 강제 |
| `mcp-006` | 성공 또는 redirect 가능한 오류 authorization response | client callback redirect | `iss` = metadata issuer | RFC 9207 mix-up 방어 |
| `mcp-token-001` | auth code 발급 후 `pending_deletion` 또는 `disabled/deleted`로 변경 | POST `/oauth/token` | `invalid_grant` | MCP 토큰 발급 시점 차단 |

## Refresh

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `refresh-001` | `active` | valid refresh_token | 새 access/refresh 발급 | 정상 rotation |
| `refresh-002` | `pending_deletion` | valid refresh_token | `invalid_grant` | 삭제 유예 차단 |
| `refresh-003` | `disabled` 또는 `deleted` | valid refresh_token | `invalid_grant` | 비활성 차단 |
| `refresh-004` | same token concurrent 2회 (유예 끔) | `/oauth/token` | 1회 성공 + 1회 실패 | row lock/원자성 |
| `refresh-004b` | same token 2회 (유예 5초) | `/oauth/token` | 2회 성공, 두 토큰 모두 rotation 가능, reuse 감사 0 | 동시 갱신 클라이언트 보호 |
| `refresh-005` | revoked token 재사용 | `/oauth/token` | family revoke + `invalid_grant` | 탈취 의심 처리 |
| `refresh-006` | 교환된 토큰을 유예 안에 재제출 | `Storage` | 같은 family에 새 토큰, tombstone 없음 | 유예 발급 |
| `refresh-007` | 교환된 토큰을 유예 밖에 재제출 | `Storage` | family revoke + tombstone | 유예 만료 |
| `refresh-008` | `/oauth/revoke`한 토큰을 유예 안에 재제출 | `Storage` | family revoke + tombstone | 폐기 토큰은 유예 없음 |
| `refresh-009` | 유예 안에서 상한(3개) 초과 재제출 | `Storage` | `invalid_grant`, family 유지 | 재생 발급 제한 |
| `refresh-010` | tombstone된 family 토큰을 유예 안에 재제출 | `Storage` | `invalid_grant` | 폐기 family 부활 금지 |
| `refresh-011` | 제출 10회가 모두 잠정 판정을 통과한 뒤 insert | `Storage` | 자식 총 3개, family 유지 | 잠금 하 상한 |
| `refresh-012` | 자식을 id로 revoke한 뒤 부모를 유예 안에 재제출 | `Storage` | `invalid_grant`, 살아있는 토큰 0, tombstone | 끝낸 세션 부활 금지 |
| `refresh-013` | 사용자 전체 revoke 뒤 부모를 유예 안에 재제출 | `Storage` | `invalid_grant`, 살아있는 토큰 0 | 〃 |
| `refresh-014` | 유예 형제가 있는 상태에서 한 토큰을 `/oauth/revoke`(hash·id) | `Storage` | 형제도 rotation 불가, 살아있는 토큰 0, tombstone `reason=revoked` | revoke = grant 전체 |
| `refresh-015` | 정상 교환과 유예 재생이 insert 순서를 바꿈 | `Storage` | `outcome=issued` 감사는 재생 IP 1건 | 감사 귀속 |
| `refresh-016` | insert 단계에서 상한 거부 | `Storage` | `invalid_grant`(→ 400), `ErrInvalidRefreshToken` 래핑 | 500 금지 |
| `refresh-017` | 교환된 토큰 행이 insert 전 삭제됨 | `Storage` | `invalid_grant`, 토큰 발급 없음 | 무관한 family 생성 금지 |
| `refresh-019` | 다른 클라이언트가 같은 family의 토큰(원문·id)으로 revoke | `Storage` | grant 유지, tombstone·감사 없음 | RFC 7009 클라이언트 바인딩 |
| `refresh-020` | 잠정 판정 뒤 계정 비활성화 / 토큰 만료 후 insert | `Storage` | `invalid_grant`, 자식 없음 | 잠금 하 재검증 |
| `refresh-018` | 교환 안 된 토큰에 20개 동시 요청 × 5회 | `Storage` | 자식 ≤ 3, 거부는 전부 `ErrInvalidRefreshToken`, 교착 없음 | 실제 동시성 |

## Logout

`/end_session` (OIDC RP-Initiated Logout 1.0). 통합 테스트는 `internal/integration/integration_logout_test.go`, 핸들러 단위 테스트는 `internal/handler/logout_test.go`.

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|------------|
| `logout-001` | 세션 없음 | `GET /end_session` (hint 없음) | 200 로그아웃 완료 페이지, 리다이렉트 없음, `auth.logout` 0 | 종료할 것 없음 |
| `logout-002` | 유효 세션 | `GET /end_session` (hint 없음) | 200 확인 페이지 + `csrf_token`, 세션 유지 | §2 확인 필수 |
| `logout-003` | 유효 세션 | 확인 POST (CSRF 일치) | 세션 폐기, 세션 쿠키(운영 `__Host-authgate_session`, dev `authgate_session`) 만료, `auth.logout` 1, 다음 `/login`은 IdP로 | 계정 전환 경로 |
| `logout-004` | 유효 세션 | 확인 POST (CSRF 누락/불일치) | 403, 세션 유지, `auth.logout` 0 | CSRF 방어 |
| `logout-005` | 유효 세션 | `id_token_hint` = 세션 사용자 | 확인 없이 종료, 쿠키 만료, `auth.logout.client_id` = hint `azp` | hint가 확인을 대신 |
| `logout-006` | 사용자 B 세션 | `id_token_hint` = 사용자 A | 확인 페이지, 확인 POST 후 B 세션만 폐기(A 유지), `auth.logout` 1 | 다른 사용자 hint는 증거가 아님 |
| `logout-007` | 유효 세션 | 서명 불일치/형식 오류 `id_token_hint` | 400, 세션 유지 | hint 검증 |
| `logout-008` | 사용자 세션(다른 브라우저) | 쿠키 없이 유효한 `id_token_hint` | 완료 페이지, 세션 유지, `auth.logout` 0 | hint만으로 로그아웃 불가 |
| `logout-009` | — | 쿠키 없는 POST | 200, 세션/로그아웃 CSRF Set-Cookie 없음 | 교차 사이트 POST 강제 로그아웃 차단 |
| `logout-010` | 유효 세션 | `confirm` 없는 POST | 확인 페이지, 세션 유지 | RP의 POST 요청은 확인이 아님 |
| `logout-011` | 유효 세션 | 세션 사용자 hint + 미등록 `post_logout_redirect_uri` | 로그아웃 완료 페이지, 리다이렉트 없음, 세션 폐기 | 미등록 URI는 버리고 로그아웃 계속 |
| `logout-012` | 유효 세션 | hint + `azp`와 다른 `client_id` | 400, 세션 유지 | 클라이언트 일치 |
| `logout-013` | 비활성화된 계정 세션 | 확인 POST | 세션 폐기, 쿠키 만료 | 비활성 계정도 로그아웃 |
| `logout-014` | 유효 세션 | 같은 hint로 3회 | `auth.logout` 1 | 종료한 것이 없으면 감사 없음 |
| `max-age-001` | 활성 세션(10분 전) | `max_age=3600` 로그인 | 세션 재사용, 완료 | 신선한 세션 |
| `max-age-002` | 활성 세션(2시간 전) | `max_age=300` 로그인 | 상위 IdP 리다이렉트(`select_account`), 완료 안 함 | Core 3.1.2.1 재인증 |
| `max-age-003` | 활성 세션(1초 전) | `max_age=0` (prompt=login 유도) | 상위 IdP 리다이렉트 | 0 ≠ 없음 |
| `max-age-004` | 활성 세션(1시간 전) | `max_age=60` + `prompt=none` | `error=login_required` 리다이렉트 | Core 3.1.2.6 |
| `max-age-005` | 활성 세션(30일 전) | `max_age` 없음 | 세션 재사용 | 미요청 시 무영향 |
| `max-age-006` | 활성 세션(6시간 전) | 일반 로그인 | `auth_time` = 세션 생성 시각 | 재사용은 재인증이 아님 |
| `max-age-007` | — | `max_age`=2^62 | 1년 된 세션도 재사용 | Duration 오버플로 방지 |
| `max-age-008` | — | 미래 `auth_time` | 재사용 | 시계 역행 |
| `max-age-009` | 세션 조회 실패 | `prompt=none` | `error=login_required` (IdP 리다이렉트 아님) | Core 3.1.2.6 |
| `device-auth-time-001` | 4시간 전 로그인 세션 | 디바이스 승인 | device code `auth_time` = 세션 생성 시각 | 승인은 재인증이 아님 |
| `logout-016` | 유효 세션 | 형제 서브도메인 확인 POST (`Sec-Fetch-Site: same-site`, 토큰 일치) | 403, 세션 유지, `auth.logout` 없음 | 서브도메인 쿠키 주입 차단 |
| `logout-015` | 세션 1개 | `Storage.TerminateSession` 3회 | `auth.logout` 1 | 영향 행 0이면 감사 없음 |
| `logout-unit-001` | 유효 세션 | `GET` (hint 없음) | 확인 페이지, CSRF 쿠키 `Strict`/`HttpOnly`/`Secure`/Path=`/`/Domain 없음 (`__Host-` 요건) | 쿠키 속성 |
| `logout-unit-002` | 유효 세션 | 확인 POST (폼 토큰 누락/쿠키 누락/불일치) | 403, 종료 호출 없음, 세션 쿠키 미변경 | CSRF 가드 |
| `logout-unit-003` | 유효 세션 | 확인 POST (CSRF 일치) | 종료 1회, 세션·CSRF 쿠키 만료 | 쿠키 삭제 |
| `logout-unit-004` | — | 등록된 `post_logout_redirect_uri` + `client_id` + `state` | 302 `…?state=` | §3 리다이렉트 |
| `logout-unit-005` | — | `client_id` 없이 `post_logout_redirect_uri` + `state` | 200 완료 페이지, 리다이렉트 없음 | 미검증 URI·빈 URL 리다이렉트 금지 |
| `logout-unit-006` | 유효 세션 | 미등록 `post_logout_redirect_uri` + `client_id` | 확인 페이지, 리다이렉트·종료 없음 | open redirect 차단, 로그아웃은 계속 |
| `logout-unit-007` | 세션 조회 오류 | GET → 확인 POST | 확인 페이지 → 세션 쿠키 만료 | 장애 시에도 이 브라우저 로그아웃 |
| `logout-unit-008` | — | 쿠키 없는 POST | Set-Cookie 없음 | 가져오지 않은 쿠키는 지우지 않음 |
| `session-cookie-004` | 운영 / dev | 발급·조회·삭제 | 운영 `__Host-authgate_session`, dev `authgate_session`; 운영에서 기존 이름만 있으면 세션 없음, 기존 이름이 앞에 있어도 호스트 쿠키 값만 조회 | Secure·Path·Domain·SameSite 및 폴백 금지 |
| `logout-unit-009` | 운영, 기존 이름의 유효한 공격자 세션 / 뒤에 호스트 세션 있음 | 실제 `HandleEndSession` 호출 | 기존 이름만 있으면 조회·삭제·종료 없음; 호스트 쿠키가 있으면 그 세션만 조회 후 확인 화면 | handler의 devMode 전달·쿠키 순서 회귀 |
| `session-cookie-003` | — | `clearSessionCookie` | 발급과 같은 속성 + `Max-Age<0` | 브라우저가 같은 쿠키로 인식 |
| `csrf-unit-001` | — | 쿠키 이름 계산 | 운영은 `__Host-` 접두사, dev는 접두사 없음 | 접두사 요건(Secure)과 localhost 비호환 |
| `csrf-unit-002` | — | 발급/삭제 쿠키 | Path=`/`, Domain 없음, HttpOnly, Strict, Secure=!dev, 삭제 쿠키 속성 일치 | `__Host-` 요건·삭제 누락 방지 |
| `csrf-unit-003` | 운영 모드 | 접두사 없는 쿠키 + 일치하는 폼 토큰 | 거부 (접두사 쿠키만 인정) | 형제 서브도메인 쿠키 주입 |
| `csrf-unit-004` | — | `Sec-Fetch-Site`/`Origin` 조합 | `same-origin`·일치 Origin만 허용, `same-site`/`cross-site`/`null`/스킴 불일치 거부 | same-origin 판정 |
| `csrf-unit-005` | dev 모드 | 형제 서브도메인 POST (CSRF 쿠키·토큰 일치, `Sec-Fetch-Site: same-site`) | 403 | 토큰을 아는 공격자도 차단 |

## Delete / Recover

| ID | 초기 상태 | 입력 | 기대 결과 | 검증 포인트 |
|----|----------|------|----------|-------------|
| `account-001` | `active` | `Storage.RequestDeletion` | `pending_deletion` | 상태 전이 |
| `account-002` | `pending_deletion` | `Storage.RequestDeletion` | 멱등 성공 | 재요청 무시 |
| `account-003` | `pending_deletion` | Browser 로그인 | active 복구 | 복구 경로 |
| `account-004` | `pending_deletion` | Device/MCP 로그인 | `account_inactive` | Browser만 복구 |
| `account-005` | `disabled` 또는 `deleted` | `Storage.RequestDeletion` | `ErrUserAccountClosed` | 비활성 계정 삭제 차단 |

## 검증 포인트

```text
1. Browser만 pending_deletion을 복구할 수 있는가?
2. Device/MCP는 active 사용자만 통과하는가?
3. Refresh는 active 상태에서만 허용되는가?
4. Delete/Recover가 상태기계를 깨지 않는가?
5. 로그아웃은 증거(일치하는 id_token_hint) 또는 사용자 확인이 있을 때만 세션을 끝내는가?
```
