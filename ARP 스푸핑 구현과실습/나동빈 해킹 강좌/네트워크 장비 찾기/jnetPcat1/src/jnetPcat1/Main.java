package jnetPcat1;

import java.util.ArrayList;
import java.util.Date;

import javax.security.auth.login.FailedLoginException;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>() ; //우리 컴퓨터에 접속한 ip 정보를 저장하기 위해 생성
	    StringBuilder errbuf = new StringBuilder();
	    
	    
	    int r = Pcap.findAllDevs(allDEVS, errbuf);
	    if(r == Pcap.NOT_OK || allDEVS.isEmpty())
	    {
	    	System.out.println("네트워크를 찾을 수 없습니다." + errbuf.toString());	    	
	    }
	    System.out.println("네트워크 장비 탐색 성공");
	    int i = 0 ;
	    for(PcapIf device : allDEVS) {
	    	String description = (device.getDescription() != null)? device.getDescription() : "장비에 대한 설명이 없습니다.";
	    	System.out.printf("[%d번] %s [%s]\n", i++, device.getName(),description);

	    }
		PcapIf device = allDEVS.get(1);
    	System.out.printf("선택한 장치 : %S\n",(device.getDescription() != null) ? device.getDescription() : device.getName())    ;
	    
    	int snaplen = 64* 1024;
    	int flags = Pcap.MODE_PROMISCUOUS;
    	int timeout = 1*1000;
    	
    	Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    	
    			if(pcap == null) {
    				
    				System.out.printf("패킷 캡처에 실패 했습니다." + errbuf.toString());
    				return ;
    				
    			}
    			
    			
	    PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>() {
			
			@Override
			public void nextPacket(PcapPacket packet, String user) {
			 System.out.printf("캡쳐 시각  : %S \n패킷의 길이 : %-4d \n",
				new Date(packet.getCaptureHeader().timestampInMillis()),
					 packet.getCaptureHeader().caplen());
			}
		};
		pcap.loop(10, jPacketHandler,"jNetPcap");
		pcap.close();
	    
	    
	}

}
