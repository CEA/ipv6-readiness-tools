===================
= v6App v0.3.beta =
===================

v6App v0.3.beta is a beta release of the v6App.  The application performs two main tasks: determine IPv6-Readiness of the local host, and identify IPv4/6 nodes on the local network.  Data from the application is printed to the screen and persisted to disk as an XML document.

Requirements:

  * Java 6 or later JRE
  * WinPcap for Windows (included)
  * libpcap for Linux

New Features:

  * IPv6 addresses are labeled with scope identifiers (e.g., Link-Local, ULA, Global, etc.).
    - Teredo and 6to4 addresses are parsed further to expose tunnel attributes (e.g., client/server IPv4 address, port, etc.)
  * Added support for pinging IPv6 routers (ff02::2) and parsing the response.
  * Added support for injecting Router Solicitation packets and identifying Router Advertisement responses.
  * Added support for identifying IPv4 routers based on the localhost's default gateway.
  * Added support for global address detection if the local host is assigned a global IPv6 address.
    - For every link-local IPv6 address discovered, inject a
      Neighbor Solicitation and ping6 packet to the theoretical global address ([64 bit global prefix] + [lower 64 bits of link-local])
    - Parse Neighbor Advertisement and ping6 responses to identify global addresses
  * Added user configurable properties file (config/v6app.properties)
  
Bug Fixes:

  * Several small bug fixes

Known Deficiencies:

  * No auto-installer provided.
  * Windows users may see a firewall warning as a result of the
    application joining multicast groups.
  * Limited number of discovery protocols implemented.
  * Device name detection is not performed

Windows (32-bit/64-bit) Installation Instructions:

  * Ensure Java 6 or later JRE is installed
  * Unzip v6App.zip archive to the filesystem (assume C:\)
  * Install WinPcap (run C:\v6App\WinPcap_4_1_2.exe)
    - Be sure to select the 'Automatically start the WinPcap driver at boot time' option.
  * Open a cmd window and navigate to the v6App directory
    - cd C:\v6App
  * Run the Windows batch file
    - run-win.bat

Linux (x86/x64) Installation Instructions:

  * Ensure Java 6 or later JRE is installed
  * Unzip v6App.zip archive to the filesystem (assume $HOME/)
  * Install the libpcap version appropriate for your linux distribution
    - (e.g., Ubuntu 12.10): sudo apt-get install libpcap0.8
  * Open a terminal and navigate to the v6App directory
    - cd $HOME/v6App
  * Determine which start script is appropriate for your distribution
    - run-ubuntu.sh: Ubuntu distributions
    - run-rhel.sh:   Red Hat Enterprise Linux distributions
    - run-linux.sh:  Generic linux distributions
  * Ensure script is executable:
    - chmod a+x *.sh
  * Run start script:
    - (e.g., Ubuntu): ./run-ubuntu.sh
 
 Properties File:
 
   User configurable properties are located in config/v6app.properties.
   See this file for a list of properties and their descriptions.