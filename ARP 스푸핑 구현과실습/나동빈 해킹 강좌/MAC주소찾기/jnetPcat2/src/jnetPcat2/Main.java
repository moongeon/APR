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

		ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>(); // �츮 ��ǻ�Ϳ� ������ ip ������ �����ϱ� ���� ����
		StringBuilder errbuf = new StringBuilder(); // �����޼����� ������ؼ� ����

		int r = Pcap.findAllDevs(allDEVS, errbuf); // ��Ʈ��ũ ��� ����ش�.
		if (r == Pcap.NOT_OK || allDEVS.isEmpty()) {
			System.out.println("��Ʈ��ũ�� ã�� �� �����ϴ�." + errbuf.toString());
		}
		System.out.println("��Ʈ��ũ ��� Ž�� ����");
		try {
			for (final PcapIf i : allDEVS) {       //�����ġ�� �ϳ��� �湮
				final byte[] mac = i.getHardwareAddress(); 
				if (mac == null) {
					continue;

				}
				System.out.printf("��ġ�ּ� : %s\n ���ּ� : %s\n", i.getName(), asString(mac));

			}
		} catch (Exception e) {
			e.getStackTrace();
		}

	}
  //byte ���� ���������� �ٲٱ� ���ؼ� �ʿ�
	public static String asString(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for (byte b : mac) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			if (b >= 0 && b < 16) { //���ڸ� �� �ִ� �տ� 0�� ǥ���ϱ� ���� ex 16:02 ���� 02�� ����� ����
				buf.append('0');
			}

			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase()); // 2�ڸ��� ���

		}
		return buf.toString();r
	}

}
