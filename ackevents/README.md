With ackevents we expect to discover with precision which packet was first lost on each connection. The bpf program probe the function _tcp_rate_skb_delivered_ and looks for the first packet lost and count the amount of spurious retransmission's and dsack's and export to _ackevents.csv_.

You can check every experiment we did for testing purpose at this [spreedsheet](https://docs.google.com/spreadsheets/d/1wTxFay6Dh9Hw51UDohZ3tFXL_HRNnI7gwDqAEa95jOY/edit?usp=sharing). 

The client/server .pcaps and .csv can be found at this [gdrive folder](https://drive.google.com/drive/folders/1HAQMsbe_FO-T0U_L1vR6II2uzG_IvYqx?usp=sharing   ).

