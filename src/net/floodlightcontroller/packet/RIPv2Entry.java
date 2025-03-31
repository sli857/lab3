package net.floodlightcontroller.packet;

import java.nio.ByteBuffer;

/**
 * Represents a single entry in a RIPv2 routing table
 */
public class RIPv2Entry 
{
    public static final short ADDRESS_FAMILY_IPv4 = 2;

    protected short afIdentifier;
    protected short tagValue;
    protected int networkAddress;
    protected int maskValue;
    protected int gatewayAddress;
    protected int distanceValue;
    protected long timestamp;

    public RIPv2Entry()
    { }

    public RIPv2Entry(int networkAddress, int maskValue, int distanceValue, long timestamp)
    {
        this.afIdentifier = ADDRESS_FAMILY_IPv4;
        this.networkAddress = networkAddress;
        this.maskValue = maskValue;
        this.distanceValue = distanceValue;
        this.timestamp = timestamp;
    }

    public String toString()
    {
        return String.format("RIPv2Entry : {addressFamily=%d, routeTag=%d, address=%s, subnetMask=%s, nextHopAddress=%s, metric=%d, lastUpdateTime=%d}", 
                this.afIdentifier, this.tagValue, 
                IPv4.fromIPv4Address(this.networkAddress), 
                IPv4.fromIPv4Address(this.maskValue),
                IPv4.fromIPv4Address(this.gatewayAddress), 
                this.distanceValue,
                this.timestamp);
    }

    public short getAddressFamily()
    { return this.afIdentifier; }

    public void setAddressFamily(short addressFamily)
    { this.afIdentifier = addressFamily; }

    public short getRouteTag()
    { return this.tagValue; }

    public void setRouteTag(short routeTag)
    { this.tagValue = routeTag; }

    public int getAddress()
    { return this.networkAddress; }

    public void setAddress(int address)
    { this.networkAddress = address; }

    public int getSubnetMask()
    { return this.maskValue; }

    public void setSubnetMask(int subnetMask)
    { this.maskValue = subnetMask; }

    public int getNextHopAddress()
    { return this.gatewayAddress; }

    public void setNextHopAddress(int nextHopAddress)
    { this.gatewayAddress = nextHopAddress; }

    public int getMetric()
    { return this.distanceValue; }

    public void setMetric(int metric)
    { this.distanceValue = metric; }

    public long getTime()
    { return this.timestamp; }

    public void setTime(long millTime)
    { this.timestamp = millTime; }

    /**
     * Checks if this entry has expired based on the current timestamp
     * If expired, marks the entry as unreachable
     * 
     * @param currentTime Current system time in milliseconds
     * @return true if the entry was marked as expired
     */
    public boolean isExpired(long currentTime)
    { 
        long ageInMillis = currentTime - this.timestamp;
        if (ageInMillis > 30000) {
            this.distanceValue = 16; // Set to infinity (unreachable)
            return true;
        }
        return false;
    }

    /**
     * Marks this entry as expired
     * Note: Actual removal from routing table handled elsewhere
     */
    public void expireEntry()
    { 
        // Implementation not required per project scope
    }

    public byte[] serialize() 
    {
        int entryLength = 2*2 + 4*4; // 2 shorts (2 bytes each) + 4 ints (4 bytes each)
        byte[] serialized = new byte[entryLength];
        ByteBuffer buffer = ByteBuffer.wrap(serialized);

        buffer.putShort(this.afIdentifier);
        buffer.putShort(this.tagValue);
        buffer.putInt(this.networkAddress);
        buffer.putInt(this.maskValue);
        buffer.putInt(this.gatewayAddress);
        buffer.putInt(this.distanceValue);
        return serialized;
    }

    public RIPv2Entry deserialize(byte[] data, int offset, int length) 
    {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        this.afIdentifier = buffer.getShort();
        this.tagValue = buffer.getShort();
        this.networkAddress = buffer.getInt();
        this.maskValue = buffer.getInt();
        this.gatewayAddress = buffer.getInt();
        this.distanceValue = buffer.getInt();
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
        
        return this.afIdentifier == other.afIdentifier &&
               this.tagValue == other.tagValue &&
               this.networkAddress == other.networkAddress &&
               this.maskValue == other.maskValue &&
               this.gatewayAddress == other.gatewayAddress &&
               this.distanceValue == other.distanceValue;
    }
}