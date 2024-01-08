# UMAS Wireshark Dissector

Wireshark dissector for UMAS protocol used in Schneider Electric Modicon PLC.

## Usage

Just copy umas.lua to Wireshark plugin directory `path/to/wireshark/plugins`, then open your capture file using Wireshark.

This dissector will try to parse communications on TCP port 502 as UMAS message. If a packet is not a valid UMAS message, it will call Wireshark's built-in Modbus dissector.

## License

See [LICENSE](LICENSE).

## Acknowledgments

* [The Unity (UMAS) protocol (Part I)](https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html)
* [The Unity (UMAS) protocol (Part II)](https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-ii.html)
* [The Unity (UMAS) protocol (Part III)](https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-iii.html)
* [The Unity (UMAS) protocol (Part IV)](https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-iv.html)