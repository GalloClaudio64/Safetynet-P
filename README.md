SafetyNet-P Wireshark Dissector

Welcome to the SafetyNet-P Wireshark Dissector! This dissector is designed to decode and analyze network traffic generated by the SafetyNet-P protocol.
Installation

To use this dissector, you'll need to have Wireshark installed on your computer. You can download the latest version of Wireshark from the official website:

https://www.wireshark.org/download.html

Once you have Wireshark installed, you can install the SafetyNet-P dissector by following these steps:

    Clone the SafetyNet-P dissector repository to your local machine:

On Windows:

Copy the .lua file to the following location:

C:\Program Files\Wireshark\plugins

On macOS:

/Applications/Wireshark.app/Contents/PlugIns

On Linux:

bash

/usr/lib/wireshark/plugins/

    Restart Wireshark.

Usage

Once you've installed the dissector, you can use it to analyze network traffic that uses the SafetyNet-P protocol. Simply open Wireshark and load a packet capture file that contains SafetyNet-P traffic. Wireshark should automatically recognize the protocol and decode the packets accordingly.

If you encounter any issues or have any questions about using the SafetyNet-P dissector, please feel free to open an issue on the project's GitHub page.
Contributing

This is my first project and I'm still learning, so any feedback, suggestions or improvements are welcome! If you find a bug, have an idea for a new feature, or just want to improve the code, please feel free to submit a pull request or open an issue on the project's GitHub page.

If you're not sure where to start, check out the issues page for a list of known issues and feature requests. If you'd like to contribute but aren't sure how, you can also reach out to me via email or through the project's GitHub page.

Thanks for your interest in the SafetyNet-P Wireshark Dissector! I hope you find it useful and I look forward to your contributions

I added an example of a Wireshark trace, if you find anything that can be improved please let me know.
