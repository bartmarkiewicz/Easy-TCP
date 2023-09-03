package easytcp.model.packet;

import java.util.Objects;

public class ConnectionAddresses {
    private InternetAddress addressOne;
    private InternetAddress addressTwo;

    public ConnectionAddresses(InternetAddress addressOne, InternetAddress addressTwo) {
        this.addressOne = addressOne;
        this.addressTwo = addressTwo;
    }

    public ConnectionAddresses(ConnectionAddresses connectionAddresses) {
        this.addressOne = connectionAddresses.getAddressOne();
        this.addressTwo = connectionAddresses.getAddressTwo();
    }

    public InternetAddress getAddressOne() {
        return addressOne;
    }

    public void setAddressOne(InternetAddress addressOne) {
        this.addressOne = addressOne;
    }

    public InternetAddress getAddressTwo() {
        return addressTwo;
    }

    public void setAddressTwo(InternetAddress addressTwo) {
        this.addressTwo = addressTwo;
    }

    public boolean containsAddress(InternetAddress address) {
        return Objects.equals(address, addressOne) || Objects.equals(address, addressTwo);
    }

    @Override
    public String toString() {
        return "ConnectionAddresses{" +
                "addressOne=" + addressOne +
                ", addressTwo=" + addressTwo +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConnectionAddresses that = (ConnectionAddresses) o;
        return (Objects.equals(addressOne, that.addressOne) && Objects.equals(addressTwo, that.addressTwo))
                || (Objects.equals(addressTwo, that.addressOne) && Objects.equals(addressOne, that.addressTwo));
    }

    @Override
    public int hashCode() {
        //order of address one or two doesn't matter
        int result = 17;
        result += Objects.hashCode(addressOne);
        result += Objects.hashCode(addressTwo);
        return result;
    }
}
