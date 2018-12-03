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

		ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>() ; //�츮 ��ǻ�Ϳ� ������ ip ������ �����ϱ� ���� ����
	    StringBuilder errbuf = new StringBuilder();
	    
	    
	    int r = Pcap.findAllDevs(allDEVS, errbuf);
	    if(r == Pcap.NOT_OK || allDEVS.isEmpty())
	    {
	    	System.out.println("��Ʈ��ũ�� ã�� �� �����ϴ�." + errbuf.toString());	    	
	    }
	    System.out.println("��Ʈ��ũ ��� Ž�� ����");
	    int i = 0 ;
	    for(PcapIf device : allDEVS) {
	    	String description = (device.getDescription() != null)? device.getDescription() : "��� ���� ������ �����ϴ�.";
	    	System.out.printf("[%d��] %s [%s]\n", i++, device.getName(),description);

	    }
		PcapIf device = allDEVS.get(1);
    	System.out.printf("������ ��ġ : %S\n",(device.getDescription() != null) ? device.getDescription() : device.getName())    ;
	    
    	int snaplen = 64* 1024;
    	int flags = Pcap.MODE_PROMISCUOUS;
    	int timeout = 1*1000;
    	
    	Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    	
    			if(pcap == null) {
    				
    				System.out.printf("��Ŷ ĸó�� ���� �߽��ϴ�." + errbuf.toString());
    				return ;
    				
    			}
    			
    			
	    PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>() {
			
			@Override
			public void nextPacket(PcapPacket packet, String user) {
			 System.out.printf("ĸ�� �ð�  : %S \n��Ŷ�� ���� : %-4d \n",
				new Date(packet.getCaptureHeader().timestampInMillis()),
					 packet.getCaptureHeader().caplen());
			}
		};
		pcap.loop(10, jPacketHandler,"jNetPcap");
		pcap.close();
	    
	    
	}

}
