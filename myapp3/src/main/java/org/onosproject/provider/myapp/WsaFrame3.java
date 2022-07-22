package org.onosproject.provider.myapp3;

import org.onlab.packet.BasePacket;
import org.onlab.packet.MacAddress;
import java.nio.ByteBuffer;
import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

public class WsaFrame3 extends BasePacket {
	
	private final Logger log = getLogger(getClass());
	private MacAddress source;
	protected final byte protocolVersion = 0;
	
	protected WsaFrame3() {
	}
	
	private WsaFrame3(MacAddress mac) {
		this.source = mac;
	}
	
	public MacAddress getSourceMac() {
		return this.source;
	}
	
	@Override
	public byte[] serialize() {
		byte[] wsa_copied = {(byte)0x03,(byte)0x00,(byte)0x80,(byte)0x07,(byte)0x7c,(byte)0x03,(byte)0x00,(byte)0x79,(byte)0x3f,(byte)0x11,(byte)0x03,(byte)0x11,(byte)0x01,(byte)0x64,(byte)0x06,(byte)0x18,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07,(byte)0x05,(byte)0x04,(byte)0x4a,(byte)0x4d,(byte)0x43,(byte)0x52,(byte)0x01,(byte)0xef,(byte)0xff,(byte)0xff,(byte)0xfe,(byte)0x08,(byte)0x01,(byte)0x0b,(byte)0xac,(byte)0x9e,(byte)0x0c,(byte)0x01,(byte)0x02,(byte)0x0c,(byte)0x04,(byte)0x06,(byte)0xa4,(byte)0x00,(byte)0x00,(byte)0x15,(byte)0x01,(byte)0x02,(byte)0x07,(byte)0x08,(byte)0x12,(byte)0x34,(byte)0x0d,(byte)0xb8,(byte)0xf0,(byte)0x0d,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x40,(byte)0xfe,(byte)0x80,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x02,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xfe,(byte)0x00,(byte)0x00,(byte)0x08,(byte)0x10,(byte)0x80,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x08,(byte)0x08,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x01,(byte)0x01,(byte)0x0e,(byte)0x06,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x08};
		ByteBuffer buf = ByteBuffer.allocate(wsa_copied.length);
		buf.put(wsa_copied);

		return buf.array();
	}
}