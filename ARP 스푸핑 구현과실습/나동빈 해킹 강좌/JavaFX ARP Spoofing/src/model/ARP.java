package model;

import java.util.Arrays;

public class ARP {
private byte[] destinationMac = new byte[6];
private byte[] sourceMac = new byte[6];
private byte[] eternetType   =  {0x08, 0x06}; // ARP
private byte[] hardwareType  =  {0x00, 0x01}; // Ethernet
private byte[] protocolType  =  {0x08, 0x00}; // IPv4
private byte   harewareSize  =  0x06; // MAC SIZE
private byte   protocolSize  =  0x04; // 
private byte[]   opcode      =  new byte[2]; // 
private byte[]   senderMAC   =  new byte[6]; // 
private byte[]   senderIP    =  new byte[4]; // 
private byte[]   targerMAC   =  new byte[6]; // 
private byte[]   targerIP    =  new byte[4]; // 

public void makeARPRequest(byte[] sourceMAC ,  byte[] senderIP,byte[] targerIP)
{	
	Arrays.fill(destinationMac,(byte)0xff); //브로드캐스트
//	destinationMac[0] = (byte) 0xe4;
//	destinationMac[1] = (byte) 0xbe;
//	destinationMac[2] = (byte) 0xed;
//	destinationMac[3] = (byte) 0xa8;
//	destinationMac[4] = (byte) 0x74;
//	destinationMac[5] = (byte) 0x3e;
	System.arraycopy(sourceMAC, 0, this.sourceMac, 0, 6);
	opcode[0] = 0x00; opcode[1] = 0x01; //Request
	System.arraycopy(sourceMAC, 0, this.senderMAC, 0, 6);
	System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
	Arrays.fill(targerMAC,(byte)0x00); //브로드캐스트
	System.arraycopy(targerIP, 0, this.targerIP, 0, 4);
	
}

public void makeARPReply(byte[] destinationMac,byte[] sourceMAC , byte[] senderMAC, byte[] senderIP,byte[] targerMAC,byte[] targerIP)
{	
	
    System.arraycopy(destinationMac, 0, this.destinationMac, 0, 6);
	System.arraycopy(sourceMAC, 0, this.sourceMac, 0, 6);
	opcode[0] = 0x00; opcode[1] = 0x02; //Reply
	System.arraycopy(senderMAC, 0, this.senderMAC, 0, 6);
	System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
	System.arraycopy(targerMAC, 0, this.targerMAC, 0, 6);
	System.arraycopy(targerIP, 0, this.targerIP, 0, 4);	
}

public byte[] getPacket() {
	byte[] bytes = new byte[42];
	
	System.arraycopy(destinationMac, 0, bytes, 0  , destinationMac.length);
	System.arraycopy(sourceMac ,     0, bytes, 6  , sourceMac.length);
	System.arraycopy(eternetType,    0, bytes, 12 , eternetType.length);
	System.arraycopy(hardwareType,   0, bytes, 14 , hardwareType.length);
	System.arraycopy(protocolType,   0, bytes, 16 , protocolType.length);
	bytes[18] = harewareSize;
	bytes[19] = protocolSize;
	System.arraycopy(opcode,    0 , bytes , 20 , opcode.length);
	System.arraycopy(senderMAC, 0 , bytes , 22  , senderMAC.length);
	System.arraycopy(senderIP,  0 , bytes , 28 , senderIP.length);
	System.arraycopy(targerMAC, 0 , bytes , 32 , targerMAC.length);
	System.arraycopy(targerIP,  0 , bytes , 38 , targerIP.length);
	return bytes;
}





}
