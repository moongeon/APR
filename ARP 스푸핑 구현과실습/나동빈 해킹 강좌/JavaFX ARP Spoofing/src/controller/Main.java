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
	AnchorPane layout; // 행커팬을 매칭시켜줌

	@Override
	public void start(Stage primaryStage) {
		this.primaryStage = primaryStage;
		this.primaryStage.setTitle("JavaFX ARP Spoofing");
		this.primaryStage.setOnCloseRequest(e->System.exit(0)); //닫기버튼을 누르면 어떤동작이 돌아가도 멈춘다.
		setLayout();
	}
	// 화면 불러오는함수
	public void setLayout() {
		try {
			FXMLLoader loader = new FXMLLoader(); // fx화면 띄어주기 위해 객체 생성
			loader.setLocation(getClass().getResource("/view/View.fxml")); // 뷰파일안에 있는 fxml 가져오기
			layout = (AnchorPane)loader.load(); // 뷰파일을 읽어와서 레이아웃에 씌워준다.			
			Scene scene = new Scene(layout); // 레이아웃을 담을 신을 만듬
			primaryStage.setScene(scene); // 신을 띄워준다.
			primaryStage.show();
		} catch (Exception e) {
			e.getStackTrace();
		}
	}

	public Stage getPrimaryStage() {
		return primaryStage;

	}

	public static void main(String[] args) {
            launch(args);  //자바fx기본함수
	}

}
