# Hack-Astrophe

Hack-Astrophe is a penetration testing challenge designed to simulate challenge cybersecurity enthusiasts and professionals through a range of puzzles and vulnerabilities. The challenge features multiple servers configured with various priviledge escalation pathways those looking to hone and challenge their exploitation and thinking skills. Read our full writeup [here](hackastrophe-writeup.pdf)

## Challenge Overview

Hack-Astrophe immerses you in a vulnerable environment consisting of several independent servers, each hosting distinct services. These servers are interconnected on a private network, mimicking real-world scenarios where attackers must pivot between different services and exploit multiple layers to achieve their objectives.

The setup includes:

- **Web Server**: A server hosting a vulnerable web application.
- **API Server**: A server that manages backend API services, connecting the web application with other system components.
- **Database Server**: A server that handles all database operations.

Each server is configured with its own unique set of vulnerabilities and puzzles, making the challenge non-trivial and designed to test a range of penetration testing skills. Participants will encounter misconfigurations, coding flaws, and other security weaknesses that must be exploited to gain privileged access.

## Setup Instructions
1. **Download and Extract the Archive**
  - Download and extract the archive containing the `.ova` and `.vdi` disk image.
2. **Open the OVA file:**
   - Import the virtual appliance into VirtualBox.

3. **Configure Host-only Network in VirtualBox:**
   - Go to `Tools > Host-only Networks`, and create a new network with the following settings (this **MUST** use the 192.168.57.1/24 subnet):
     - **Subnet:** `192.168.57.1/24`
     - **DHCP:** `Disabled`
     - **IP Address:** `192.168.57.1`
     - **Netmask:** `255.255.255.0`
       
4. **Import the Virtual Disk Image:**
   - In VirtualBox, navigate to `Tools > Media`.
   - Click `Add` and select the extracted `.vdi`.
   - **IMPORTANT** Select `Properties > Attributes > Type` and set to `Immutable` (hit apply).
     
5. **Attach Disk to VM:**
   - In VirtualBox, navigate to `Settings > Storage`.
   - On the right of the `SATA` controller click `Add Hard Disk`
   - Select the disk you just added.

6. **Configure Network Settings on the VM:**
   - **Adapter 1:** `NAT`
   - **Adapter 2:** `Host-only Adapter` (ensure it uses the network created above)
     - **Adapter 2 (Advanced):** Promiscuous Mode `Allow All`

## Additional Configuration for Other VMs on the Network

If you are using other VMs on the Host-only network (e.g., Kali Linux for penetration testing), you might encounter issues recognizing the `vboxnet` adapter. To resolve this an IP may need to be statically assigned.
