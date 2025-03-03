# Easy TCP

A Java Swing application used for TCP packet capture, visualisation and analysis. A clone of Wireshark. 

# Features
- Viewing of a PCAP (packet capture) file
- Live capturing of packets and their features
- Easy filtering and splitting by particular TCP connection and provides information about individual connections
- Arrow diagram, clicking on a packet shows arrow diagram.
![image](https://github.com/user-attachments/assets/56b92e68-5a11-40b8-b886-dcf80777b00d)
- Detecting of TCP features such as nagle, slow start, delayed acknowledgement
- Arrow diagram exports as images

# Limitations
- Detection of TCP features could use improvement in accuracy albeit most of the features we look at cannot be detected with 100% accuracy by looking at just the client.
- Could check native client TCP settings to get at least accurate TCP settings for the client
- Limited unit and integration tests
- Only captures and looks at TCP packets - albeit expanding the protocol suite should be relatively easy

# Installation Guide
- Download and install latest [Npcap](https://npcap.com/) with default settings and at least [Java 17](https://adoptium.net/en-GB/temurin/releases/)
- Pull project
- Build project using Gradle
- Run from Application.java

# Usage Guide
- Read through the help screen.
- Remember to select the right network interface - most of them won't get any TCP traffic with the exception of the one you use for your Wi-Fi/ethernet connection

![image](https://github.com/user-attachments/assets/a7bda713-6b9f-4c62-8cbc-38442322016c)

