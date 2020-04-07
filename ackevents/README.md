With ackevents we expect to discover with precision which packet was
first lost on each connection. The BPF program probes the function
`tcp_rate_skb_delivered`; it looks for the first packet lost and counts
the amount of spurious retransmissions and DSACKs in the connection.
Data is exported in a CSV file.

