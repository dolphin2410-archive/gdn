# Pkt
HTTP 패킷 분석

## Note
- 개발중...
- 아직 `x-www-urlencoded` 만 지원합니다
- 아직 라이브러리로 사용 불가능합니다(샘플 기능이 하드코딩 됨).

## .env
컴파일 하기 위해서는 .env 파일이 필요합니다.

| Name | Description|
|------|------------|
|IP_ADDRESS|분석할 ip 주소|
|PARAM_START|HTTP 패킷이 데이터로 시작할 경우의 앞부분|
|METHOD_START|HTTP 패킷이 메소드로 시작할 경우의 앞부분|
|DATA_TARGET|타깃 인수|