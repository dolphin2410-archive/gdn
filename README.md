# GDN
## GDN Packet Analyzer

### How to use this program
1. Download from the releases tab
2. Flags
    - **No Capture**

    Doesn't capture packets. Instead analyzes `capture.pcapng` file or the one specified
    ```
    pkt.exe --nocapture
    ```

    - **Save**

    Saves the captured packet as `pcapng`
    ```
    pkt.exe --save
    ```

    - **File**

    Specify a file to analyze. Must be used with the `--nocapture` flag
    ```
    pkt.exe --file my.pcapng
    ```
3. `Ctrl+Q` to listen to the parsed data