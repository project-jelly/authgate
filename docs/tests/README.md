# authgate 테스트 문서

## 개요

이 디렉토리는 authgate의 상태기계와 로그인/토큰/계정 lifecycle을 검증하기 위한 테스트 설계 문서를 담는다.
목표는 "어떤 상태에서 어떤 채널로 진입하면 무엇이 되어야 하는가"를 고정하는 것이다.

## 문서 목록

| # | 문서 | 목적 |
|---|------|------|
| 001 | [상태 매트릭스](001-state-matrix.md) | `user.Status` 기반 상태 판정과 채널별 접근 제어 검증 |
| 002 | [채널 플로우 테스트](002-channel-flows.md) | Browser / Device / MCP / Refresh / Logout / Delete 플로우별 검증 (OIDC `prompt` 포함) |
| 003 | [E2E 사이클 테스트](003-e2e-cycles.md) | 가입 → 사용 → 탈퇴 → 복구/삭제 → 재가입 전체 사이클 검증 |
| 004 | [감사 이벤트 테스트](004-audit-events.md) | `audit_log.event_type`와 metadata 기록 검증 |
| 005 | [Upstream Provider 테스트](005-upstream-provider.md) | OIDCProvider discovery/exchange/userinfo 검증 |

클라이언트 접근 정책(`access`) 테스트는 002의 "클라이언트 접근 정책" 절에 모았다. 파일:
`internal/clientaccess/clientaccess_test.go`, `internal/service/client_access_unit_test.go`,
`internal/storage/client_access_integration_test.go`, `internal/integration/integration_client_access_test.go`.

보안/컴플라이언스 관점의 evidence mapping은
[Security 001 Audit Evidence Matrix](../security/001-audit-evidence-matrix.md)를
참조한다.

## 구조

```text
1. 상태 판정이 맞는가?
   -> 001-state-matrix.md

2. 각 채널이 같은 규칙을 따르는가?
   -> 002-channel-flows.md

3. 시작부터 끝까지 사이클이 닫히는가?
   -> 003-e2e-cycles.md

4. 중요한 보안/운영 이벤트가 빠짐없이 기록되는가?
   -> 004-audit-events.md
```

## 실행 메모

기본 검증 경로는 `main` 대상 PR의 [GitHub Actions CI](../../.github/workflows/ci.yml)다.
빌드·단위/통합 테스트·race·포맷·vet·lint·SQLC·취약점 검사는 CI에서 실행하고,
실패한 job의 로그를 확인한 뒤 수정 커밋으로 다시 검증한다.
명시적인 로컬 재현 요청이 없으면 CI용 검사를 로컬에서 반복하거나 도구를 설치하지 않는다.

`cmd/authgate/healthcheck_test.go`는 healthcheck 명령의 HTTP 200 성공,
오류 응답·리디렉션·잘못된 포트·연결 실패·취소 처리를 검증한다.
CI의 `Image Smoke`는 amd64와 arm64에서 실제 Docker 이미지를 빌드하고 Compose의
PostgreSQL·mock IdP와 함께 기동한다. 비루트 사용자, healthcheck 성공/실패,
DB readiness, OIDC discovery/JWKS, CA 인증서 및 셸 없는 실행 이미지를 확인한다.

`internal/integration/integration_grant_contract_test.go`는 실제 HTTP와
PostgreSQL 잠금으로 인증 코드 동시 소비(최대 1회), 잘못된 요청 뒤 정상
재시도, refresh INSERT 실패 시 code 소비 rollback을 검증한다.

```text
문서 = 테스트 설계
코드 = internal/*_test.go

- config/clock/idgen 일부는 일반 unit test로 바로 실행 가능
- service/storage/integration 테스트 다수는 `//go:build integration`
- integration 테스트는 testcontainers-go를 사용하므로 Docker 접근 권한이 필요
```

## 테스트 원칙

구조 리팩토링의 HTTP/서비스 계약 회귀 테스트:

- `internal/handler/login_response_test.go`: upstream state/prompt 전달,
  성공한 callback에서만 세션 쿠키 발급, production 쿠키 속성,
  오류 redirect/HTML 응답 및 미지원 action의 채널별 처리 경계.
- `internal/service/login_request_test.go`: Browser/MCP 양쪽의 인증 요청 조회 오류,
  특히 login entry(400)와 callback(500)의 기존 만료 응답 차이 유지.
- 기존 `max_age_unit_test.go`, `login_unit_test.go`, `client_access_unit_test.go`와
  storage의 refresh/grace/revocation 통합 테스트는 그대로 유지한다.

구조와 트랜잭션 책임은 [Code Structure](../architecture/README.md)를 참조한다.

1. 각 테스트는 **초기 상태**, **입력**, **기대 결과**, **검증 포인트**를 반드시 가진다.
2. `user.Status` 기반 상태 판정은 모든 채널 테스트의 source of truth다.
3. Browser / Device / MCP / Refresh는 서로 다른 구현이 아니라 **동일 상태기계의 다른 진입점**으로 검증한다.
4. `pending_deletion`은 Browser에서만 복구 가능함을 반드시 검증한다.
5. `deleted`는 종단 상태이며, 재가입은 반드시 신규 가입으로 다시 시작해야 한다.

`integration_access_token_validation_test.go`는 실제 발급/refresh 토큰으로
UserInfo의 용도·서명·필수 claims·audience·scope와 introspection의 client 결합을
검증한다. `access_token_validation_test.go`는 검증되지 않은 Storage callback과
재서명 실패 시 토큰 노출을 막는다. app route 테스트는 UserInfo adapter 연결도 확인한다.
`app/routes_integration_test.go`는 실제 app 라우트 등록 함수에 real provider와
PostgreSQL Storage를 연결해 `at+jwt` 허용·`JWT` 거부·openid-only 반환을 확인한다.

`integration_refresh_contract_test.go`는 잘못된 요청 뒤 재시도, access/refresh
scope 분리, INSERT rollback, revoke DB 오류의 HTTP 계약을 검증한다.
`refresh_consumption_integration_test.go`는 조회의 비소비성과 별도 Storage instance의
발급/폐기 양쪽 순서를 DB 잠금 barrier로 검증한다. 기존 재사용 감사 테스트는
lookup과 issuance 두 callback을 모두 실행하며, grace 테스트는 confidential client를 사용한다.

인증 코어 리팩토링의 표준 조항·회귀 테스트·호환 정책·종료 기준은
[005-token-contracts.md](005-token-contracts.md)에 연결한다.
