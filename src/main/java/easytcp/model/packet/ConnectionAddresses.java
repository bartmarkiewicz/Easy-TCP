package easytcp.model.packet;

import java.util.Objects;

/*A pair of addresses used to identify a unique TCP connection
 */
public record ConnectionAddresses(InternetAddress addressOne, InternetAddress addressTwo) {

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
