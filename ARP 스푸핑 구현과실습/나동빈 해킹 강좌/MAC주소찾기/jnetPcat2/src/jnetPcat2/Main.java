package jnetPcat2;

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

		ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>(); // 우리 컴퓨터에 접속한 ip 정보를 저장하기 위해 생성
		StringBuilder errbuf = new StringBuilder(); // 오류메서지를 담기위해서 생성

		int r = Pcap.findAllDevs(allDEVS, errbuf); // 네트워크 장비를 담어준다.
		if (r == Pcap.NOT_OK || allDEVS.isEmpty()) {
			System.out.println("네트워크를 찾을 수 없습니다." + errbuf.toString());
		}
		System.out.println("네트워크 장비 탐색 성공");
		try {
			for (final PcapIf i : allDEVS) {       //모든장치를 하나씩 방문
				final byte[] mac = i.getHardwareAddress(); 
				if (mac == null) {
					continue;

				}
				System.out.printf("장치주소 : %s\n 맥주소 : %s\n", i.getName(), asString(mac));

			}
		} catch (Exception e) {
			e.getStackTrace();
		}

	}
  //byte 형을 문자형으로 바꾸기 위해서 필요
	public static String asString(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for (byte b : mac) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			if (b >= 0 && b < 16) { //한자리 수 있다 앞에 0을 표시하기 위해 ex 16:02 같이 02를 만들기 위해
				buf.append('0');
			}

			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase()); // 2자리씩 출력

		}
		return buf.toString();r
	}

}
