# WaaS OAS 만들기 / WaaS 문서 피드백

## Issues

### GET /uath/secure/channel/create

GET 에는 request body 가 들어갈 수 없음

GET -> POST ?

### GET /auth/auth-service/v2/{social-network-name}/login

302, 200 http status 불명료.

특히 200 이 URL 을 입력하지 않은 경우와 입력한 경우 response 가 없거나 json 인 경우 표현이 안됨.

### POST /auth/auth-service/v2/finalize

'서버에서 연동 시 생성된 토큰 발급 받는 방법' : 적절한 제목이 있을까요?

서버에서 연동 시 생성된 토큰 발급 받는 방법 -> 서버에서 연동 시 생성된 토큰 발급

POST -> GET ?

### POST /auth/auth-service/v2/token/login

POST -> GET ?

status code 618 허용 안됨

#### POST /auth/auth-service/v2/refresh

전반적인 설명 필요

#### POST /jwk/key-service/{userPoolId}/.well-known/jwks.json

POST -> GET ?

URL 이 너무 복잡함. 사용자 입장에서 .well-known/jwks.json 이후의 값이 왜 필요한지?

response 값 의미 불명료.

성공이라면 별다른 response 가 필요없음 큰 json 값을 사용자가 받아야 하는지?
