import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

	private BufferedReader reader;
	private ServerSocket server = null;
	private Socket socket;

	public void start() {
		try {
			server = new ServerSocket(12345);
			System.out.println("������ Ȱ��ȭ �Ǿ����ϴ�.");
			while (true) {
				socket = server.accept();
				reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				getmessage();
			}

		} catch (Exception e) {
			e.getStackTrace();
		} finally {
			try {
				if (reader != null)
					reader.close();
				if (socket != null)
					socket.close();
			} catch (Exception e2) {
				e2.getStackTrace();
			}
		}
	}
	public void getmessage() {
		try {
			while (true) {
				System.out.println("Ŭ���̾�Ʈ������ �޼��� ��� :" + reader.readLine());
			}
		} catch (Exception e) {
			e.getStackTrace();
		}
	}
}
