
---

# Simple Firewall

A simple firewall application built using Python and Tkinter. This firewall allows you to block specific IP addresses and ports, and monitor network traffic using Scapy.

## Features

- **Block IP Addresses**: Block specific IPs from sending or receiving traffic.
- **Block Ports**: Block specific TCP/UDP ports to prevent communication.
- **Real-time Traffic Monitoring**: Uses Scapy to sniff and filter packets in real-time.
- **User-friendly GUI**: Built with Tkinter, providing an intuitive interface for managing the firewall.

## Requirements

- Python 3.x
- `scapy` library (for packet sniffing and filtering)
- `tkinter` (for GUI)

You can install the necessary dependencies using:

```bash
pip install scapy
```

### Installing Tkinter
`Tkinter` is usually included with Python. If it's not installed, you can install it by running:

- **For Ubuntu/Debian**:
  ```bash
  sudo apt-get install python3-tk
  ```
- **For Windows**: Tkinter should be included with the default Python installation.

## How to Use

1. **Run the Application**:
   After cloning or downloading the repository, navigate to the project folder and run the `firewall_gui.py` file:

   ```bash
   python firewall_gui.py
   ```

2. **Block IPs**:
   - Enter an IP address in the input field and click the **Block IP** button to block that IP.
   - The blocked IP addresses will appear in the list below the input field.

3. **Block Ports**:
   - Enter a port number (e.g., 80 for HTTP, 443 for HTTPS) and click the **Block Port** button.
   - The blocked ports will appear in the list below the input field.

4. **Start/Stop the Firewall**:
   - Click the **Start Firewall** button to begin filtering network traffic. The firewall will start monitoring and blocking packets based on your IP and port filters.
   - Click the **Stop Firewall** button to disable the firewall.

5. **Firewall Status**:
   - The status label shows whether the firewall is **ON** or **OFF**.
   - The firewall runs in a separate thread, so it can be toggled without freezing the GUI.

## GUI Components

- **Blocked IP Listbox**: Displays the list of blocked IPs.
- **Blocked Port Listbox**: Displays the list of blocked ports.
- **Input Fields**: Allow users to enter an IP or port to block.
- **Start/Stop Button**: Toggles the firewall on and off.

## Code Explanation

- **Tkinter GUI**: The application uses Tkinter to create a user-friendly interface where users can input data (IP/Port), view blocked IPs/Ports, and control the firewall.
- **Scapy Sniffing**: The firewall uses Scapy to sniff network packets and filter them based on blocked IPs and ports. It uses the `sniff()` function to capture packets in real-time, and the `packet_filter()` function to block packets that match the blocked IPs or ports.
- **Multi-threading**: The firewall runs in a separate thread to avoid blocking the GUI's responsiveness.

## Example Output

When the firewall is active, any packets matching the blocked IPs or ports will be logged in the console. For example:

```
Blocked packet from/to 192.168.1.100 -> 192.168.1.101
Blocked packet on port 80 -> 443
```

## Future Enhancements

- Implement more advanced filtering techniques (e.g., block specific protocols, limit by subnet).
- Add logging to keep track of blocked packets.
- Improve error handling for invalid IPs or ports.
- Allow saving and loading of blocked IPs/ports.

## 👤 Author

Ndaedzo Austin Mukhuba
- GitHub: [@ndaedzo](https://github.com/ndaedxo)
- LinkedIn: [Ndaedzo Austin Mukhuba](https://linkedin.com/in/ndaedzo-mukhuba-71759033b)
- Email: [ndaemukhuba](ndaemukhuba@gmail.com)
  
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
