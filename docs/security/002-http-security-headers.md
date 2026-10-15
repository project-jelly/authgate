# HTTP 보안 응답 헤더

authgate는 모든 HTTP 응답에 기본 보안 헤더를 설정한다. 구현은
`internal/middleware/security_headers.go`의 `SecurityHeaders` 미들웨어이며,
미들웨어 체인의 **가장 바깥**(`internal/app/app.go`)에 배치되어 에러 응답과
CORS preflight 응답에도 헤더가 포함된다.

## 설정되는 헤더

| 헤더 | 값 | 목적 |
|------|-----|------|
| `X-Content-Type-Options` | `nosniff` | MIME 스니핑 차단 |
| `X-Frame-Options` | `DENY` | 클릭재킹 차단 (프레임 임베드 금지) |
| `Referrer-Policy` | `no-referrer` | URL의 code/token이 Referer로 유출되는 것 방지 |
| `Content-Security-Policy` | 아래 참조 | 스크립트 실행 전면 차단 + 리소스 출처 제한 + `frame-ancestors 'none'` |
| `Strict-Transport-Security` | `max-age=31536000` | HTTPS 강제. **`DEV_MODE=false`일 때만** 전송 |

## 토큰 응답의 캐시 금지

`/oauth/token`에는 `middleware.NoStore`를 rate limiter 바깥에 추가해
`Cache-Control: no-store`, `Pragma: no-cache`를 설정한다 (RFC 6749 §5.1).
code·refresh·device 성공 응답과 provider·resource 검증 오류, HTTP 429가 대상이다.
토큰 응답의 `at+jwt`/`at_hash` 재서명은 이 헤더를 제거하지 않는다.
이는 전체 사이트의 캐시 정책을 바꾸는 설정이 아니다.
실제 provider·PostgreSQL·production route를 연결한
`TestProviderRoutes_TokenResponsesAreNotCacheable`이 이 경계를 검증한다.

## CSP 정책

```
default-src 'none';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
form-action 'self';
frame-ancestors 'none';
base-uri 'none'
```

`internal/pages/templates/*.html`은 공유 레이아웃의 인라인 `<style>` 하나만
사용하고 스크립트도, 외부에서 가져오는 리소스도 없다. `default-src 'none'`로
스크립트 출처를 상속 차단(script-src 미지정 → 어떤 JS도 실행 불가)하고, 허용
목록에는 실제로 쓰는 것만 남긴다. JSON API 응답에도 동일 헤더가 붙지만 브라우저가
JSON 본문에서 하위 리소스를 로드하지 않으므로 무해하다.

**외부 오리진을 하나도 허용하지 않는다.** 이전에는 Google Fonts를 위해
`fonts.googleapis.com`과 `fonts.gstatic.com`을 열어두었는데, 이 페이지들은 로그인
플로우의 일부이므로 렌더링할 때마다 방문자 IP가 제3자에게 전달됐다. 시스템 폰트로
전환하면서 그 허용을 제거했다. `security_headers_test.go`는 정책에 `https://`가
다시 나타나면 실패하고, `internal/pages/renderer_test.go`는 렌더링된 HTML에 외부
URL이 없는지 검사한다.

## 비고

- HSTS는 dev 모드(평문 HTTP)에서 무의미하므로 생략한다. `includeSubDomains`는
  authgate가 제어하지 않는 형제 서브도메인에 HTTPS를 강제할 수 있어 기본값에서
  제외했다. 더 강한 정책은 프록시 계층에서 추가할 수 있다.
- 테스트: `internal/middleware/security_headers_test.go`
