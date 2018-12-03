package jnetPcat3;

import java.util.ArrayList;
import java.util.Date;

import javax.security.auth.login.FailedLoginException;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>(); // 우리 컴퓨터에 접속한 ip 정보를 저장하기 위해 생성
		StringBuilder errbuf = new StringBuilder(); // 오류메서지를 담기위해서 생성

		int r = Pcap.findAllDevs(allDEVS, errbuf); // 네트워크 장비를 담어준다.
		if (r == Pcap.NOT_OK || allDEVS.isEmpty()) {
			System.out.println("네트워크를 찾을 수 없습니다." + errbuf.toString());
		}
		System.out.println("네트워크 장비 탐색 성공");
		int i = 0;
		for (PcapIf device : allDEVS) { // 모든네트워크를 디바이스를 통해서 탐색해 각가의 장치에 대해 널값이 아닌것을 현재 장치의 설명을 담아준다.
			String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
			System.out.printf("[%d번] %s [%s]\n", i++, device.getName(), description);

		}
		PcapIf device = allDEVS.get(1);
		System.out.printf("선택한 장치 : %S\n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1 * 1000;

		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {

			System.out.printf("패킷 캡처에 실패 했습니다." + errbuf.toString());
			return;

		}

		Ethernet eth = new Ethernet(); // 2계층
		Ip4 ip = new Ip4(); // 3계층
		Tcp tcp = new Tcp(); // 4계층

		Payload payload = new Payload(); // 데이터를 주고받을때 데이터의 공간

		PcapHeader header = new PcapHeader(JMemory.POINTER); // 캡처한 패킷의 헤더값을 담기위해

		JBuffer buf = new JBuffer(JMemory.POINTER); // 패킷관련버퍼
		int id = JRegistry.mapDLTToId(pcap.datalink()); // JRegistry에서 매핑된 값을 가져온다. 피캣의 데이터링크 타입을 ......
														// 패킷을 캡처하고 다룬다.
														// 하나의 패킷 캡처값을 담아준다.
		while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			System.out.printf("[#%d]\n", packet.getFrameNumber());
			if (packet.hasHeader(eth)) {
				System.out.printf("출발지 Mac 주소 = %s \n 도착지 Mac 주소 = %s\n", FormatUtils.mac(eth.source()),
						FormatUtils.mac(eth.destination()));

			}
			if (packet.hasHeader(ip)) {
				System.out.printf("출발지 ip 주소 = %s \n 도착지 ip 주소 = %s\n", FormatUtils.ip(ip.source()),
						FormatUtils.ip(ip.destination()));
			}
			if (packet.hasHeader(tcp)) {
				System.out.printf("출발지 Mac 주소 = %d \n 도착지 Mac 주소 = %d\n", tcp.source(), tcp.destination());
			}
			if (packet.hasHeader(payload)) {
				System.out.printf("페이로드의 길이= %d", payload.getLength());
				System.out.printf(payload.toHexdump()); // 실질적인 데이터
			}

		}
		pcap.close();
	}
}