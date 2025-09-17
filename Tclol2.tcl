# SOCKS4 Proxy Server for Cisco TCL 8.3.4
# With Graceful Shutdown Capability

# <--- MODIFICATION: Declare global variables to hold state
set ::server_sock ""
set ::proxy_running 0

# Main procedure to start the proxy server
proc start_socks_proxy {listen_port} {
    # <--- MODIFICATION: Use global variables
    global server_sock proxy_running
    
    puts "Starting SOCKS4 proxy on port $listen_port..."
    puts "To stop, open another terminal and run: tclsh -> stop_socks_proxy"
    
    # <--- MODIFICATION: Store the server socket in the global variable
    set server_sock [socket -server accept_connection $listen_port]
    
    # <--- MODIFICATION: Wait on a variable instead of 'forever'
    # The loop will break when 'proxy_running' is set.
    vwait ::proxy_running
}

# <--- MODIFICATION: New procedure to gracefully stop the server
proc stop_socks_proxy {} {
    global server_sock proxy_running
    
    if {$server_sock == ""} {
        puts "Proxy is not running."
        return
    }
    
    puts "Shutting down SOCKS4 proxy..."
    
    # Close the main listening socket to prevent new connections.
    # The 'catch' prevents an error if the socket is already closed.
    catch {close $server_sock}
    
    # Reset the global variable
    set server_sock ""
    
    # This sets the variable that 'vwait' is waiting on, which
    # causes the event loop in start_socks_proxy to terminate.
    set proxy_running 1
    
    puts "SOCKS4 proxy stopped."
}


# --- (The rest of the procedures are unchanged) ---

# Procedure called when a new client connects
proc accept_connection {client_sock client_addr client_port} {
    puts "Accepted connection from $client_addr:$client_port"
    fconfigure $client_sock -translation binary -blocking 0
    fileevent $client_sock readable [list handle_socks_request $client_sock]
}

# Procedure to read and parse the SOCKS4 request
proc handle_socks_request {client_sock} {
    set data [read $client_sock 1024]
    if {[string length $data] == 0} {
        close $client_sock
        return
    }
    binary scan $data ccl req_vn req_cd dest_port_net dest_ip_net
    if {$req_vn != 4 || $req_cd != 1} {
        send_socks_reply $client_sock 91 $dest_port_net $dest_ip_net
        close $client_sock
        return
    }
    set dest_ip [format "%d.%d.%d.%d" [expr {$dest_ip_net >> 24 & 0xFF}] \
        [expr {$dest_ip_net >> 16 & 0xFF}] [expr {$dest_ip_net >> 8 & 0xFF}] \
        [expr {$dest_ip_net & 0xFF}]]
    set dest_port $dest_port_net
    if {[catch {socket $dest_ip $dest_port} dest_sock]} {
        send_socks_reply $client_sock 91 $dest_port_net $dest_ip_net
        close $client_sock
        return
    }
    send_socks_reply $client_sock 90 $dest_port_net $dest_ip_net
    fconfigure $dest_sock -translation binary -blocking 0
    fileevent $client_sock readable [list relay_data $client_sock $dest_sock]
    fileevent $dest_sock readable [list relay_data $dest_sock $client_sock]
}

# Procedure to send a SOCKS4 reply
proc send_socks_reply {client_sock reply_code port ip} {
    set reply_packet [binary format ccl 0 $reply_code $port $ip]
    puts -nonewline $client_sock $reply_packet
    flush $client_sock
}

# Procedure to relay data
proc relay_data {from_sock to_sock} {
    if {[catch {read $from_sock} data] || [eof $from_sock]} {
        close $from_sock
        close $to_sock
        return
    }
    puts -nonewline $to_sock $data
    flush $to_sock
}
