# report-deauth
● BoB 9기 공통교육 네트워크 과제

● DeAuth 공격을 수행할 수 있는 프로그램임.

## 기능
● 랜카드 Monitor Mode (모니터 모드) 자동 전환

● 2.4Ghz, 5.Ghz 대역에 대한 Channel Hopping (채널 변경) 기능

● all 옵션이 입력되면 모든 채널의 AP에 대해 DeAuth 공격 수행.

	list 방식 : 프로그램 시작시, 검색되는 AP를 리스트하여 해당 AP만 공격합니다.

		(속도 빠름, 새로운 AP 반영 불가)

	beacon 방식 : Beacons 패킷이 잡히는 모든 AP를 공격합니다.

		(속도 느림, 새로운 AP 반영 가능)


● ap 옵션만 입력되면 AP Broadcast 방식으로 DeAuth 공격을 수행.

● ap와 stn옵션이 입력되면 해당 STATION만 Station Unicast 방식으로 DeAuth 공격을 수행.

● 추가로 ch 옵션이 입력되면, 해당 채널로 변경.


## 사용법
![use](https://user-images.githubusercontent.com/12112214/106763853-97937a00-667a-11eb-99e9-6bad31cc73d0.png)

    ./deauth <interface> <option>
        -all [list/beacon]
        -ap <AP MAC> [-stn <STN MAC>] [-ch <CH NUM>]

## AP Broadcast 공격
![ap](https://user-images.githubusercontent.com/12112214/106764734-6a939700-667b-11eb-91f2-6eb678967097.png)

## Station Unicast 공격
![stn-ap](https://user-images.githubusercontent.com/12112214/106764210-eb05c800-667a-11eb-951d-1c191f68a736.png)

## ALL LIST 공격
![all_list0](https://user-images.githubusercontent.com/12112214/106764245-f48f3000-667a-11eb-831f-9d8e98cca60d.png)

![all_list](https://user-images.githubusercontent.com/12112214/106764283-fd800180-667a-11eb-84e3-156e0d3a37b2.png)

## ALL BEACON 공격
![all_beacon](https://user-images.githubusercontent.com/12112214/106764311-053fa600-667b-11eb-953e-4c96945c422f.png)

