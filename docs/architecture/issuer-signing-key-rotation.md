# Issuer signing-key rotation implementation design

> 2026-10-15 설계 결정. **미구현**이며 현재 실행할 운영 명령이나 완료된 테스트가 아니다.
> 정책은 [ADR-003](../adr/003-issuer-signing-key-rotation.md), 현재 런타임은
> [Operations](../spec/009-operations.md#키-로테이션)을 따른다.

## 확인한 책임 경계

| 경계 | 현재 근거 | 설계 영향 |
|------|-----------|-----------|
| 시작 시 키 로드 | [`app/storage_wiring.go`](../../internal/app/storage_wiring.go), [`storage/keys.go`](../../internal/storage/keys.go) | provider 생성 전에 묶음 전체를 검증한다. |
| JWT 서명·JWKS | [`signing_key_provider.go`](../../internal/storage/signing_key_provider.go), [`storage_oidc_device.go`](../../internal/storage/storage_oidc_device.go) | 기존 `op.Storage` 인터페이스를 유지한다. |
| access token 재서명과 ID token `at_hash` 보정 | [`access_token_typ.go`](../../internal/storage/access_token_typ.go) | 한 응답에서 키를 여러 번 조회하므로 첫 구현은 실행 중 키 교체를 하지 않는다. |
| hint 검증 | zitadel `WithIDTokenHintKeySet`, authorize와 [`handler/logout.go`](../../internal/handler/logout.go) | 별도 public-only `oidc.KeySet`을 provider 생성 시 주입한다. |
| 키 보관·배포 | Osaka Vault → ESO → Secret → read-only `subPath` mount, Reloader | 파일 watcher 대신 새 묶음으로 Pod를 교체한다. 앱에 쓰기 권한을 추가하지 않는다. |

zitadel/oidc **v3.51.14**는 access/ID token마다 `Storage.SigningKey`를 호출하고,
JWKS 및 자체 access 검증에는 `Storage.KeySet`을 사용한다. hint verifier의 키는
`op.WithIDTokenHintKeySet`으로 따로 지정할 수 있다. 이 기능은 이미 사용하는
라이브러리에 있으므로 새 upstream 릴리스를 기다릴 필요가 없다.

현재 GitOps는 `apps/authgate/helm/values-oci-prod-osaka.yaml` 및
`apps/authgate/manifests/oci-prod-osaka/externalsecret.yaml`이 소유한다.
2026-10-15 읽기 전용 확인에서 replicas=1, RollingUpdate, Secret refresh=24h,
`/signing_key.pem` read-only `subPath` mount였다. 이는 조사 당시의 상태이며
전환 시 다시 확인한다. Secret의 `subPath`는 기존 Pod에 자동 갱신되지 않는다.

## 묶음 형식과 시작 검증

추가할 설정은 `SIGNING_KEY_BUNDLE_PATH`다. 설정이 없으면 기존
`SIGNING_KEY_PATH` 동작을 유지한다. bundle path와 **명시적으로 설정한** legacy
path가 함께 있으면 구성 오류다. legacy path의 기본값은 bundle 모드에 적용하지 않는다.
bundle 모드에서는 파일 누락·파싱 오류에 대해 새 키를 생성하거나 legacy로 폴백하지 않는다.

하나의 UTF-8 JSON 파일에 아래 필드를 둔다. 이 표는 형식 정의이며 실제 키 예제가 아니다.

| 필드 | 계약 |
|------|------|
| `schema_version` | 정수 `1` |
| `revision` | 운영자가 부여한 고유한 변경 ID. rollback도 새 ID를 사용한다. 자동 증가·전환 권한을 뜻하지 않는다. |
| `active_kid` | 아래 공개 키 하나를 가리키는 ID |
| `active_private_key_pem` | active 키의 PKCS#1 RSA private PEM 하나. 기존 키 형식과 호환한다. |
| `verification_keys` | `{jwk, publish}` 목록. `jwk`는 public RSA JWK, `publish`는 필수 boolean |

`publish=true`인 키만 일반 `/keys`와 자체 access 검증에 제공한다. hint verifier는
목록의 모든 공개 키를 사용한다. active 키는 반드시 `publish=true`여야 한다.
새 공개 키만 추가한 사전 공개 묶음에도 active 개인 키는 하나뿐이다. 다음 개인 키는
활성화할 때까지 Vault 운영 경계에 보관하고 Pod에는 제공하지 않는다.

시작 검증은 다음을 모두 거부한다.

- 알 수 없는 schema/필드, 중복 JSON 멤버, trailing JSON, 누락된 필드, 빈 목록·ID.
- 중복 `kid`, 같은 키 재료의 여러 ID, active 키 누락·비공개 상태,
  active private/public 불일치, 손상된 RSA private key.
- RSA 2048–4096비트 범위 밖의 키, `alg!=RS256`, `use!=sig`, 원격 키 참조 또는 private RSA
  멤버가 들어간 공개 JWK. public JWK 허용 필드는 `kty,n,e,kid,alg,use`로 제한한다.
- 전체 파일 256 KiB 초과 또는 공개 키 128개 초과. 한도 도달은 새 배포 중단이며
  과거 hint 키를 자동 삭제하는 사유가 아니다. 96개부터 운영 경고를 낸다.

새 `kid`는 public JWK의 **RFC 7638 SHA-256 thumbprint를 base64url(no padding)**로
계산한다. 예외는 기존 키의 `authgate-key-1`뿐이며, 최초 이관 때 현재 `/keys`의
공개 키 fingerprint와 동일함을 운영 게이트로 확인한다. 정적 파일 하나만으로 과거의
키 재할당을 알아낼 수 없으므로 이후 revision 비교에서도 기존 ID→fingerprint가
바뀌지 않았는지 검사한다. `revision`만으로 이 안전성을 보장하지 않는다.
RSA 상한은 사용하는 go-jose v4.1.6의 JWK 파서 제한에도 맞춘다.

Vault 변경을 수행하는 운영자는 직전 버전의 **전체** ID→fingerprint 집합이 새 묶음에
포함되는지 비교한다. 정상 회전은 키 추가·active 변경·publish 상태 변경만 허용하며,
hint 이력을 누락하지 않는다. 최초 legacy 이관은 현재 JWKS가 비교 기준이다.
이 검사는 stateless startup parser가 대신할 수 없다. 유출 사고의 키 제거는 명시적
예외로 기록하고, 이후 변경·롤백에서도 해당 ID/fingerprint를 다시 넣지 않는다.

`storage`는 입력 DTO를 검증한 뒤 active `*rsa.PrivateKey`와 불변의
`*rsa.PublicKey` 목록을 갖는다. `KeySet()`에 private key가 들어갈 수 없게 별도
타입을 사용한다. zitadel JWKS handler는 전달받은 `Key()`를 그대로 직렬화하므로
serializer가 private 필드를 알아서 제거한다고 가정하면 안 된다.

## 앱 연결과 관측

기존 패키지 경계를 유지한다. 범용 키 관리 서비스·DB 테이블·회전 scheduler는 추가하지 않는다.

| 위치 | 구현할 변경 |
|------|-------------|
| `config` | 경로 선택 및 상충 설정 검사 |
| `storage/keys.go` 또는 같은 패키지의 bundle 파일 | 제한 있는 단일 읽기, 엄격한 JSON/PEM/JWK 검증 |
| `storage/signing_key_provider.go` | active private + published/all public 키 목록. 시작 시 한 번 구성하고 setter는 실행 중 호출하지 않는다. |
| `app/storage_wiring.go` | legacy/bundle 선택. 검증 실패 시 서버를 열기 전에 종료 |
| `app/oidc.go` | hint 전용 `oidc.KeySet`을 `WithIDTokenHintKeySet`으로 연결하고 RS256을 명시적으로 제한 |

hint key set도 단일 서명·비어 있지 않은 `kid`·RS256을 검사한 뒤 정확한 `kid`로 선택한다.
`WithIDTokenHintVerifierOpts(WithSupportedIDTokenHintSigningAlgorithms("RS256"))`도
함께 설정한다. JWK의 `alg` 필드만으로 라이브러리의 허용 알고리즘을 제한하지 않는다.
서명이 안 맞으면
다른 키를 무차별 시도하거나 검증을 생략하지 않는다. issuer·claims·expiry 처리와
로그인/세션·logout 확인·CSRF 정책은 기존 라이브러리/서비스 경계에 남긴다.
hint 키를 access verifier에 연결하지 않는다.

시작 로그에 `revision`, `active_kid`, public fingerprint 목록과 publish 상태만 남긴다.
PEM·토큰·JSON 원문은 오류 로그에도 남기지 않는다. 별도 관리 HTTP API는 만들지 않는다.
각 Pod의 시작 로그와 직접 `/keys` 응답을 비교해 **같은 revision/키 집합**인지 확인한다.
필요한 로그를 확보할 수 없으면 발급자 전환 게이트는 통과하지 못한다.

## 저장·배포 소유권

Vault의 기존 `secret/data/authgate/osaka`에 새 단일 property
`signing_key_bundle_json`을 추가하는 방식을 사용한다. 이는 **향후 변경안**이며 현재
property가 존재한다고 가정하지 않는다. 기존 다른 credential을 지우지 않는
CAS 기반 변경으로 묶음 전체를 한 버전에 저장한다.

GitOps에는 전용 ExternalSecret/Secret `authgate-signing-keys`를 추가하고,
그 property를 파일 `signing-keys.json` 하나로 전달한다. 앱은 read-only로 mount한다.
Reloader 대상에 새 Secret을 추가한다. 기존 credential Secret의 수동 수정으로
ESO와 경쟁하지 않는다. 새 묶음을 준비하는 동안에는 기존 PEM 경로를 계속 사용한다.

각 단계는 Vault 변경 ID/버전 → ESO sync → Secret resourceVersion → 새 Pod의
bundle revision/active kid → 모든 Pod의 JWKS → 소비자 결과를 기록한 뒤 다음으로 간다.
24h refresh가 지났다고 추정하지 말고 실제 sync를 확인한다. 조기 갱신이 필요하면
ESO 운영 절차로 요청한다. sync나 Reloader 실패 시 다음 단계를 진행하지 않는다.
같은 순간 모든 Pod가 전환된다는 원자성은 보장하지 않는다. 원자성 단위는 파일과
프로세스이며, 서로 다른 revision의 Pod가 공존해도 안전하도록 단계 사이에 게이트를 둔다.

기존 `signing_key_pem` property·Secret entry는 초기 이관 복구 기간에만 보존하고,
새 경로 안정화 및 구버전 롤백 종료 후 별도 변경으로 제거한다. 활성화 뒤에는 구 개인
키를 새 Pod에 mount하지 않는다. Vault의 과거 버전·백업은 그 뒤에도 남을 수 있으며,
폐기 여부는 Vault 관리자가 별도 증거로 기록한다.

## 전환 상태와 완료 기준

`A`는 기존 키, `B`는 신규 키, `H`는 과거 hint 전용 공개 키 집합이다.
상태는 운영자가 작성한 묶음 revision으로 표현하며, 앱은 타이머로 다음 상태에 진입하지 않는다.

| 단계 | active private | 일반 JWKS / access 검증 | hint 검증 | 다음 단계의 필수 증거 |
|------|----------------|------------------------|-----------|----------------------|
| 이관 | A (`authgate-key-1`) | A | H+A | 모든 발급자가 bundle 지원 버전·동일 A로 실행. 기존 토큰/로그인/refresh 유지 |
| 사전 공개 | A | A+B | H+A+B | **모든** Pod·JWKS 경로가 A+B. 소비자의 cache/unknown-kid/fetch-failure 검증 완료 |
| 활성화 | B | A+B | H+A+B | 모든 새 Pod active=B, 구 발급자 종료, Browser/Device/MCP/refresh의 실제 발급·검증 |
| 공개 종료 | B | B | H+A+B | 아래 수명·소비자 게이트 충족. 구 hint는 계속 동작하고 구 access는 허용되지 않음 |

다음 회전은 C를 같은 방식으로 추가한다. 2-slot을 덮어쓰는 방식으로 H나 아직
유효한 키를 잃지 않는다. bundle 미지원 구버전과의 혼합 배포는 **이관 단계에서만**
허용하며, 단일 키 버전 Pod가 하나라도 남아 있으면 B 사전 공개·활성화를 진행하지 않는다.

공개 종료 시점은 다음보다 빨라서는 안 된다.

```text
t_stop_old = 구 키로 서명할 수 있는 모든 프로세스가 종료된 시각의 보수적 상한
L_old      = 구 키 토큰에 실제 적용했던 최대 access/ID token 수명
S          = 관련 소비자 검증기의 최대 허용 clock skew (확인된 값)
T_unpublish >= t_stop_old + L_old + S
```

Pod Ready/Deployment rollout 완료만으로 마지막 서명 시각을 추정하지 않는다.
구 ReplicaSet·Pod의 실제 종료와 진행 중 요청 종료까지 확인하고, 외부 발급자·유지보수
인스턴스가 없는지 조사한다. 발급 종료를 입증할 수 없으면 A를 공개 상태로 유지한다.
서버 clock 오차를 포함해 신뢰 가능한 UTC 기준으로 상한을 잡고 그 증거를 보존한다.
구 키를 다시 active로 돌리면 기준 시각과 수명 게이트를 다시 계산한다.

소비자 캐시는 별도 게이트다. 사전 공개 후 실제 소비자가 B를 받아들였는지 확인하고,
공개 종료 후 남아 있는 A 캐시·fetch 실패도 확인한다. JWT 수명에 임의의 JWKS TTL을
더한 숫자 하나로 성공을 판정하지 않는다. 정상 회전은 자동 주기로 실행하지 않으며,
소비자와 발급자 증거가 준비된 운영 변경 단위로 진행한다.

## 소비자 준비 상태와 전환 게이트

아래는 2026-10-15 코드 조사 결과다. 실제 전환 전 해당 배포 버전과 설정을 재확인한다.

| 소비 경로 | 확인한 동작 | 전환 전 필요한 작업 |
|-----------|-------------|---------------------|
| AuthGate 자체 UserInfo/introspection | 로컬 `Storage.KeySet` 기반 | A/B 혼합 Pod에서 양쪽 토큰의 서명·purpose/scope 검사. hint-only A는 access 검증에서 제외 |
| NoteGate / OpsGate API Bearer | 각 저장소 `backend/crates/api/src/auth/jwt.rs`의 aliri JWKS cache. 기본 300초 주기 및 unknown kid 즉시 재조회 1회. 같은 kid 서명 실패에는 즉시 재조회하지 않음. 주기 조회 실패 시 기존 키 유지 | 실제 배포 설정 확인, cold/warm cache와 조회 실패·회복·304 동작, A/B 실제 MCP/API 호출 |
| NoteGate / OpsGate Browser ID token | 같은 `auth/oidc.rs`의 metadata/JWKS snapshot 3600초 캐시. `oauth_exchange.rs`는 snapshot 검증, unknown kid 즉시 재조회 경로 없음. discovery/JWKS 실패 시 stale snapshot을 기한 없이 사용 | **활성화 선행 과제**: snapshot 갱신/실패 처리 보완 또는 모든 프로세스의 B 포함 snapshot 확보를 증명하는 제어된 갱신. 1시간 경과만으로 통과 불가. B 활성화 직후 실제 로그인 검증 |
| Gitea / Cloudflare Access / CLI·외부 MCP 도구 | 현재 배포 소비자별 키 캐시 동작 미확인 | 각 경로의 새 키 검증·장애/재시도 증거 확보. 확인되지 않은 소비자가 있으면 전환 보류 |

Cloudflare 관리 로그인이 불가능한 현재 상태에서는 Access 측 설정/캐시 검증을 완료했다고
할 수 없다. 현재 Go 요청 200과 Python 요청 403의 경계 문제도 별도 해결 대상이다.
소비자 수정은 해당 저장소의 별도 변경이며 이 설계 문서가 이를 구현한 것은 아니다.

조사 기준은 NoteGate `v0.1.100` (`7a16b375`), OpsGate `v0.1.12` (`b79e8b3e`)다.
소스는 각 버전의
[NoteGate OIDC cache](https://github.com/project-jelly/notegate/blob/v0.1.100/backend/crates/api/src/auth/oidc.rs),
[NoteGate token exchange](https://github.com/project-jelly/notegate/blob/v0.1.100/backend/crates/api/src/auth/oauth_exchange.rs),
[OpsGate OIDC cache](https://github.com/project-jelly/opsgate/blob/v0.1.12/backend/crates/api/src/auth/oidc.rs),
[OpsGate token exchange](https://github.com/project-jelly/opsgate/blob/v0.1.12/backend/crates/api/src/auth/oauth_exchange.rs)를 따른다.
두 저장소의 기존 고정 JWKS fixture 테스트만으로 실제 HTTP 키 회전·stale cache·조회 실패가
검증되었다고 할 수 없다. Browser ID token과 resource-bound access token을 각각 올바른
소비 경로에서 검증해야 한다. resource-bound MCP token을 AuthGate UserInfo에 보내는
검사는 audience 계약상 회전 성공 증거가 아니다.

활성화 전에는 별도 테스트 키로 소비자의 회전·실패 시나리오를 검증하고, 운영에서는
사전 공개된 B가 모든 실제 verifier의 캐시에 들어갔다는 증거를 확보한다. 운영 B로
서명한 실제 로그인/API 검증은 B 활성화 직후 수행한다. 이 검사를 준비하기 위해
운영 개인 키를 임의의 스크립트나 테스트 fixture로 복사하지 않는다.

## 롤백과 사고 대응

기본 복구는 **키 묶음을 이해하는 이미지 + 최신 공개 키·hint 이력**을 유지하며 앱을
복구하는 것이다. B로 발급을 시작한 뒤 A만 공개하는 과거 Secret/이미지를 복원하지 않는다.
과거 묶음의 revision 자체를 재적용하지 말고 필요한 active 키와 최신 검증 이력을 합친
새 revision을 만든다. 모든 Pod가 보유한 published 키의 합집합을 최소한 유지한다.
단, 사고 대응으로 신뢰를 철회한 키는 합집합·과거 버전 복원에서도 제외한다.

B가 이미 사전 공개된 상태에서 활성화가 일부만 성공해도 A+B를 계속 공개하면 양쪽의
서명 검증은 가능하다. 실패한 rollout을 중단하고 compatible image/bundle로 복구한다.
구 개인 키가 폐기되었다면 A로 재서명하는 롤백은 선택할 수 없다. 공개 키만 복원하는
것과 개인 키로 발급을 재개하는 것은 다른 권한·작업이다.

키 유출이면 발급 중단과 새 신뢰 키 전환, 유출 키의 published/hint 목록 제거,
각 소비자의 강제 재조회·신뢰 철회를 조율한다. 캐시가 유출 키를 신뢰하는 동안의 위조
JWT 가능성을 JWKS 삭제만으로 없앴다고 보고하지 않는다. 정상 토큰과 오래된 hint가
실패할 수 있으며 이는 사고 대응에서 수용할 호환성 손실이다. 관련 세션/grant 조치는
기존 token/session 경계에 따라 별도로 판단한다.

## 구현 및 검증 순서

1. bundle parser/provider/config와 hint key set을 구현한다. 기존 legacy 모드와 JWT
   alg·claims·`typ=at+jwt`·`at_hash`·refresh/session 계약을 보존한다. 같은 PR에서
   Operations 환경변수·이관 설명과 테스트 문서를 실제 구현에 맞춘다.
2. GitHub Actions에서 parser 거부 사례, private key 미노출, 3개 이상 공개 키,
   같은 묶음의 재시작 복원, 두 독립 프로세스 A/B 혼합 상태를 검증한다. Browser·Device·
   MCP·refresh와 UserInfo/introspection, expired hint authorize/logout를 실제 HTTP로
   확인한다. `publish=false` A가 hint에서는 성공하고 access에서는 실패해야 한다.
   RSA 4096비트 초과 입력, 같은 RSA 키로 서명한 PS256 hint, missing/unknown `kid`를
   거부하고, 사고 키를 published/hint 양쪽에서 제거한 뒤 양쪽 검증이 실패하는지 확인한다.
3. 소비자 캐시 과제를 별도 처리하고, 새 `kid`·JWKS fetch 실패·회복 시나리오를 검증한다.
4. bundle 지원 버전을 릴리스·배포하되 처음에는 기존 A로만 발급한다. 전용 ESO/Secret과
   기존 키 이관은 별도 GitOps 변경으로 수행하고 실제 key fingerprint 일치를 확인한다.
5. 사전 공개·활성화·공개 종료를 각각 증거가 있는 별도 운영 변경으로 진행한다.
   전체 흐름의 rollback과 재시작 검증까지 끝나야 회전 기능의 운영 검증 완료다.

현재 `authgate key rotate/list/remove`와 관리 API는 구현 대상에 포함하지 않는다.
Vault 변경을 대신 실행하는 앱 권한이나 무조건 키를 제거하는 명령을 먼저 만들지 않는다.

## References

- [OIDC Core 10.1.1 — 키 추가, 새 kid와 검증 키 보존](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
- [RFC 7638 — JWK thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
- [Kubernetes Secret subPath 갱신 제약](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod)
- [zitadel/oidc v3.51.14 provider와 hint key set option](https://github.com/zitadel/oidc/blob/v3.51.14/pkg/op/op.go)
- [zitadel/oidc v3.51.14 서명 호출](https://github.com/zitadel/oidc/blob/v3.51.14/pkg/op/token.go)
- [zitadel/oidc v3.51.14 JWKS 직렬화](https://github.com/zitadel/oidc/blob/v3.51.14/pkg/op/keys.go)
