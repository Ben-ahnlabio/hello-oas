# WaaS OAS 만들기 / WaaS 문서 피드백

## Issues

### 예제코드

https://docs.waas.myabcwallet.com/ko/getting-started/guide/secure-channel/#encryptdecrypt-secret-data

python code indent 안맞음

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

#### GET /member/user-management/users/{email}/login

empty response 에 대한 설명

#### POST /member/user-management/users/{email}

설명 부족

#### POST /member/user-management/v2/join

설명 부족

socialtype 에 google apple 말고 다른것?

#### PUT /member/user-management/users/ext/update

join 할때 username 이 update 할때는 userid?

어떤 상황에서 사용되는지 설명이 있으면 좋을것 같습니다.

키 발급 여부를 수정한다?

사용자 지갑 주소를 수정한다?

회원정보 추가 업데이트는 인증 불필요?

#### GET /wapi/v2/mpc/wallets/info
