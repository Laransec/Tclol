
# SOCKS4 Proxy Server for Cisco TCL 8.3.4
# Author: Gemini Security Researcher Assistant
# WARNING: For educational use in isolated lab environments ONLY.
# SOCKS4 is insecure and transmits all data in plaintext.

# Main procedure to start the proxy server
proc start_socks_proxy {listen_port} {
    # Open a server socket on the specified port.
    # When a client connects, the 'accept_connection' proc is called.
    puts "Starting SOCKS4 proxy on port $listen_port..."
    socket -server accept_connection $listen_port
    
    # Enter the Tcl event loop to wait for connections.
    vwait forever
}

# Procedure called when a new client connects to our server socket
proc accept_connection {client_sock client_addr client_port} {
    puts "Accepted connection from $client_addr:$client_port"
    
    # Set the client socket to binary mode and non-blocking.
    fconfigure $client_sock -translation binary -blocking 0
    
    # Set up a file event. When the client socket becomes readable,
    # call the 'handle_socks_request' procedure.
    fileevent $client_sock readable [list handle_socks_request $client_sock]
}

# Procedure to read and parse the SOCKS4 request from the client
proc handle_socks_request {client_sock} {
    # The SOCKS4 request has a minimum length of 9 bytes.
    # We read up to 1024 to get the request and the UserID string.
    set data [read $client_sock 1024]
    
    # If we read 0 bytes, the client closed the connection prematurely.
    if {[string length $data] == 0} {
        close $client_sock
        return
    }
    
    # Parse the fixed-length part of the SOCKS4 request.
    # c1: Version (VN), c1: Command (CD), S1: Dest Port, l1: Dest IP
    binary scan $data ccl req_vn req_cd dest_port_net dest_ip_net
    
    # The SOCKS version must be 4, and we only support command 1 (CONNECT).
    if {$req_vn != 4 || $req_cd != 1} {
        puts "Error: Unsupported SOCKS version or command."
        # Send a "request rejected or failed" response and close.
        send_socks_reply $client_sock 91 $dest_port_net $dest_ip_net
        close $client_sock
        return
    }
    
    # Convert the destination IP from a 32-bit integer to the dotted-decimal format.
    set dest_ip [format "%d.%d.%d.%d" [expr {$dest_ip_net >> 24 & 0xFF}] \
        [expr {$dest_ip_net >> 16 & 0xFF}] [expr {$dest_ip_net >> 8 & 0xFF}] \
        [expr {$dest_ip_net & 0xFF}]]
        
    # Convert the destination port from network byte order to host byte order.
    set dest_port $dest_port_net
    
    puts "Client requests connection to $dest_ip:$dest_port"
    
    # Attempt to open a TCP connection to the destination server.
    # The 'catch' command prevents the script from crashing if the connection fails.
    if {[catch {socket $dest_ip $dest_port} dest_sock]} {
        puts "Error: Could not connect to destination $dest_ip:$dest_port"
        send_socks_reply $client_sock 91 $dest_port_net $dest_ip_net
        close $client_sock
        return
    }
    
    puts "Successfully connected to destination."
    
    # Send the "request granted" reply back to the client.
    send_socks_reply $client_sock 90 $dest_port_net $dest_ip_net
    
    # Set the destination socket to binary and non-blocking.
    fconfigure $dest_sock -translation binary -blocking 0
    
    # Set up the bidirectional relay.
    # When client is readable, call 'relay_data' to send to destination.
    # When destination is readable, call 'relay_data' to send to client.
    fileevent $client_sock readable [list relay_data $client_sock $dest_sock]
    fileevent $dest_sock readable [list relay_data $dest_sock $client_sock]
}

# Procedure to send a SOCKS4 reply to the client
proc send_socks_reply {client_sock reply_code port ip} {
    # The reply format is: VN (1 byte), CD (1 byte), DSTPORT (2 bytes), DSTIP (4 bytes)
    # VN is always 0 for a reply.
    set reply_packet [binary format ccl 0 $reply_code $port $ip]
    puts -nonewline $client_sock $reply_packet
    flush $client_sock
}

# Procedure to relay data from one socket to another
proc relay_data {from_sock to_sock} {
    # If a read returns an error or 0 bytes (EOF), the connection is closed.
    if {[catch {read $from_sock} data] || [eof $from_sock]} {
        puts "Connection closed. Shutting down relay."
        close $from_sock
        close $to_sock
        return
    }
    
    # Write the data read from the source socket to the destination socket.
    puts -nonewline $to_sock $data
    flush $to_sock
}

# Example of how to start the server.
# Change 1080 to your desired port.
# start_socks_proxy 1080


How to Use on a Cisco IOS Device
 * Copy the Script: Copy the code above into a text file and save it to your router's flash memory (e.g., flash:socks4.tcl).
 * Enter TCL Shell: Access your router's command line and enter the Tcl shell.
   router# tclsh

 * Source the Script: Load the script file into the shell environment.
   router(tcl)# source flash:socks4.tcl

 * Start the Proxy: Execute the main procedure with the port you want the proxy to listen on. Port 1080 is the standard for SOCKS.
   router(tcl)# start_socks_proxy 1080

   You should see the output: Starting SOCKS4 proxy on port 1080...
The script is now running. It will occupy your terminal session because of the vwait forever command, which keeps the Tcl event loop active. To stop it, you can press Ctrl+C or close the session.
To configure a client (like a web browser or command-line tool) to use the proxy, you would point it to the IP address of your Cisco router and the port you specified (e.g., 192.168.1.1:1080).
