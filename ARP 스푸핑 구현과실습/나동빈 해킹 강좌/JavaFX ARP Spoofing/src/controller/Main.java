package controller;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class Main extends Application {
	
	
	public static Pcap pcap = null ;
	public static PcapIf device = null;
	
	public static byte[] myIP = null;
	public static byte[] senderIP = null;
	public static byte[] targetIP = null;
	public static byte[] myMac = null;
	public static byte[] senderMAC = null;
	public static byte[] targetMAC = null;
	
	
	private Stage primaryStage;
	AnchorPane layout; // ��Ŀ���� ��Ī������

	@Override
	public void start(Stage primaryStage) {
		this.primaryStage = primaryStage;
		this.primaryStage.setTitle("JavaFX ARP Spoofing");
		this.primaryStage.setOnCloseRequest(e->System.exit(0)); //�ݱ��ư�� ������ ������� ���ư��� �����.
		setLayout();
	}
	// ȭ�� �ҷ������Լ�
	public void setLayout() {
		try {
			FXMLLoader loader = new FXMLLoader(); // fxȭ�� ����ֱ� ���� ��ü ����
			loader.setLocation(getClass().getResource("/view/View.fxml")); // �����Ͼȿ� �ִ� fxml ��������
			layout = (AnchorPane)loader.load(); // �������� �о�ͼ� ���̾ƿ��� �����ش�.			
			Scene scene = new Scene(layout); // ���̾ƿ��� ���� ���� ����
			primaryStage.setScene(scene); // ���� ����ش�.
			primaryStage.show();
		} catch (Exception e) {
			e.getStackTrace();
		}
	}

	public Stage getPrimaryStage() {
		return primaryStage;

	}

	public static void main(String[] args) {
            launch(args);  //�ڹ�fx�⺻�Լ�
	}

}
