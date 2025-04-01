package net.floodlightcontroller.packet;

import java.nio.ByteBuffer;

/**
 * Represents a single entry in a RIPv2 routing table
 */
public class RIPv2Entry 
{
    public static final short IPV4_ADDRESS_FAMILY = 2;
    public static final int INFINITY_METRIC = 16;
    public static final long ENTRY_TIMEOUT_MS = 30000;

    private short familyIdentifier;
    private short tagValue;
    private int networkAddr;
    private int maskValue;
    private int gatewayAddr;
    private int hopCount;
    private long timestamp;

    public RIPv2Entry()
    { }

    public RIPv2Entry(int networkAddr, int maskValue, int hopCount, long timestamp)
    {
        this.familyIdentifier = IPV4_ADDRESS_FAMILY;
        this.networkAddr = networkAddr;
        this.maskValue = maskValue;
        this.hopCount = hopCount;
        this.timestamp = timestamp;
    }

    public String toString()
    {
        return String.format("RIPv2Entry : {family=%d, tag=%d, network=%s, mask=%s, gateway=%s, distance=%d, updated=%d}", 
                this.familyIdentifier, this.tagValue, 
                IPv4.fromIPv4Address(this.networkAddr), 
                IPv4.fromIPv4Address(this.maskValue),
                IPv4.fromIPv4Address(this.gatewayAddr), 
                this.hopCount,
                this.timestamp);
    }

    public short getAddressFamily()
    { return this.familyIdentifier; }

    public void setAddressFamily(short addressFamily)
    { this.familyIdentifier = addressFamily; }

    public short getRouteTag()
    { return this.tagValue; }

    public void setRouteTag(short routeTag)
    { this.tagValue = routeTag; }

    public int getAddress()
    { return this.networkAddr; }

    public void setAddress(int address)
    { this.networkAddr = address; }

    public int getSubnetMask()
    { return this.maskValue; }

    public void setSubnetMask(int subnetMask)
    { this.maskValue = subnetMask; }

    public int getNextHopAddress()
    { return this.gatewayAddr; }

    public void setNextHopAddress(int nextHopAddress)
    { this.gatewayAddr = nextHopAddress; }

    public int getMetric()
    { return this.hopCount; }

    public void setMetric(int metric)
    { this.hopCount = Math.min(metric, INFINITY_METRIC); }

    public long getTime()
    { return this.timestamp; }

    public void setTime(long currentTime)
    { this.timestamp = currentTime; }

    public boolean isExpired(long currentTime)
    { 
        if ((currentTime - this.timestamp) > ENTRY_TIMEOUT_MS) {
            this.hopCount = INFINITY_METRIC;
            return true;
        }
        return false;
    }

    public void expireEntry()
    { /* Empty implementation - cleanup not in project scope */ }

    public byte[] serialize() 
    {
        int entrySize = 2*2 + 4*4;
        byte[] serialData = new byte[entrySize];
        ByteBuffer buffer = ByteBuffer.wrap(serialData);

        buffer.putShort(this.familyIdentifier);
        buffer.putShort(this.tagValue);
        buffer.putInt(this.networkAddr);
        buffer.putInt(this.maskValue);
        buffer.putInt(this.gatewayAddr);
        buffer.putInt(this.hopCount);
        
        return serialData;
    }

    public RIPv2Entry deserialize(byte[] data, int offset, int length) 
    {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        this.familyIdentifier = buffer.getShort();
        this.tagValue = buffer.getShort();
        this.networkAddr = buffer.getInt();
        this.maskValue = buffer.getInt();
        this.gatewayAddr = buffer.getInt();
        this.hopCount = buffer.getInt();
        
        return this;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj) {
            return true;
        }
        
        if (obj == null || !(obj instanceof RIPv2Entry)) {
            return false;
        }
        
        RIPv2Entry other = (RIPv2Entry)obj;
        
        return this.familyIdentifier == other.familyIdentifier &&
               this.tagValue == other.tagValue &&
               this.networkAddr == other.networkAddr &&
               this.maskValue == other.maskValue &&
               this.gatewayAddr == other.gatewayAddr &&
               this.hopCount == other.hopCount;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + familyIdentifier;
        result = prime * result + tagValue;
        result = prime * result + networkAddr;
        result = prime * result + maskValue;
        result = prime * result + gatewayAddr;
        result = prime * result + hopCount;
        return result;
    }
}
