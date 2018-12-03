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

		ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>(); // �츮 ��ǻ�Ϳ� ������ ip ������ �����ϱ� ���� ����
		StringBuilder errbuf = new StringBuilder(); // �����޼����� ������ؼ� ����

		int r = Pcap.findAllDevs(allDEVS, errbuf); // ��Ʈ��ũ ��� ����ش�.
		if (r == Pcap.NOT_OK || allDEVS.isEmpty()) {
			System.out.println("��Ʈ��ũ�� ã�� �� �����ϴ�." + errbuf.toString());
		}
		System.out.println("��Ʈ��ũ ��� Ž�� ����");
		int i = 0;
		for (PcapIf device : allDEVS) { // ����Ʈ��ũ�� ����̽��� ���ؼ� Ž���� ������ ��ġ�� ���� �ΰ��� �ƴѰ��� ���� ��ġ�� ������ ����ش�.
			String description = (device.getDescription() != null) ? device.getDescription() : "��� ���� ������ �����ϴ�.";
			System.out.printf("[%d��] %s [%s]\n", i++, device.getName(), description);

		}
		PcapIf device = allDEVS.get(1);
		System.out.printf("������ ��ġ : %S\n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1 * 1000;

		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {

			System.out.printf("��Ŷ ĸó�� ���� �߽��ϴ�." + errbuf.toString());
			return;

		}

		Ethernet eth = new Ethernet(); // 2����
		Ip4 ip = new Ip4(); // 3����
		Tcp tcp = new Tcp(); // 4����

		Payload payload = new Payload(); // �����͸� �ְ������ �������� ����

		PcapHeader header = new PcapHeader(JMemory.POINTER); // ĸó�� ��Ŷ�� ������� �������

		JBuffer buf = new JBuffer(JMemory.POINTER); // ��Ŷ���ù���
		int id = JRegistry.mapDLTToId(pcap.datalink()); // JRegistry���� ���ε� ���� �����´�. ��Ĺ�� �����͸�ũ Ÿ���� ......
														// ��Ŷ�� ĸó�ϰ� �ٷ��.
														// �ϳ��� ��Ŷ ĸó���� ����ش�.
		while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			System.out.printf("[#%d]\n", packet.getFrameNumber());
			if (packet.hasHeader(eth)) {
				System.out.printf("����� Mac �ּ� = %s \n ������ Mac �ּ� = %s\n", FormatUtils.mac(eth.source()),
						FormatUtils.mac(eth.destination()));

			}
			if (packet.hasHeader(ip)) {
				System.out.printf("����� ip �ּ� = %s \n ������ ip �ּ� = %s\n", FormatUtils.ip(ip.source()),
						FormatUtils.ip(ip.destination()));
			}
			if (packet.hasHeader(tcp)) {
				System.out.printf("����� Mac �ּ� = %d \n ������ Mac �ּ� = %d\n", tcp.source(), tcp.destination());
			}
			if (packet.hasHeader(payload)) {
				System.out.printf("���̷ε��� ����= %d", payload.getLength());
				System.out.printf(payload.toHexdump()); // �������� ������
			}

		}
		pcap.close();
	}
}