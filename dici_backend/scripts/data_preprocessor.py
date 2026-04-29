import pandas as pd

# Load your new raw dataset
df = pd.read_csv("data/raw/dataset.csv")

# 1. Define the mapping (Old Name: New Name)
mapping = {
    'FLOW_DURATION_MILLISECONDS': 'duration',      #-----                                              
    'PROTOCOL': 'protocol',                        #    |
    'L4_SRC_PORT': 'src_port',                     #    |----- Gives  improvement on ids vs cti - 72% to 72.20%
    'L4_DST_PORT': 'dest_port',                    #    |   
    'IN_PKTS': 'ingress_packet_count',             #-----
    'IN_BYTES': 'ingress_byte_count',
    'IPV4_SRC_ADDR': 'src_ip',
    'Label': 'label',  # Adjust to 'Attack' if that is your primary target column

    # # Ingress (Inbound) Traffic
    # 'IN_PKTS': 'ingress_packet_count',     #-----                                              
    # 'IN_BYTES': 'ingress_byte_count',      #    |
    # # Egress (Outbound) Traffic            #    |----- Gives no improvement on ids vs cti - 72%
    # 'OUT_PKTS': 'egress_packet_count',     #    |   
    # 'OUT_BYTES': 'egress_byte_count',      #-----
                                           

}

mapping_3 ={
    'FLOW_DURATION_MILLISECONDS': 'duration',
    'PROTOCOL': 'protocol',
    'L4_SRC_PORT': 'src_port',
    'L4_DST_PORT': 'dest_port',
    'TCP_FLAGS': 'tcp_flags',

    # Ingress (Inbound) Traffic
    'IN_PKTS': 'ingress_packet_count',
    'IN_BYTES': 'ingress_byte_count',

    # Egress (Outbound) Traffic
    'OUT_PKTS': 'egress_packet_count',
    'OUT_BYTES': 'egress_byte_count',

    # Throughput (Volume per second)
    'SRC_TO_DST_AVG_THROUGHPUT': 'src_to_dst_throughput',
    'DST_TO_SRC_AVG_THROUGHPUT': 'dst_to_src_throughput',

    # Packet Sizes (Payload Analysis)
    'MIN_IP_PKT_LEN': 'min_packet_len',
    'MAX_IP_PKT_LEN': 'max_packet_len',

    # IAT (Inter-Arrival Time - Timing Analysis)
    'SRC_TO_DST_IAT_AVG': 'src_to_dst_iat_avg',
    'DST_TO_SRC_IAT_AVG': 'dst_to_src_iat_avg',

    # Reliability (Retransmissions)
    'RETRANSMITTED_IN_PKTS': 'retransmitted_in_pkts',
    'RETRANSMITTED_OUT_PKTS': 'retransmitted_out_pkts',

    # Hop Count (TTL Analysis)
    'MIN_TTL': 'min_ttl',
    'MAX_TTL': 'max_ttl'
}

mapping_2_best_performance = {
    # 1. THE KEY (For VirusTotal Lookup)
    'IPV4_SRC_ADDR': 'src_ip',

    # 2. STRUCTURAL (Intent & Context)
    'PROTOCOL': 'protocol',
    'L4_DST_PORT': 'dest_port',
    'TCP_FLAGS': 'tcp_flags',

    # # 3. BEHAVIORAL (Timing is the best way to catch bots)
    # 'FLOW_DURATION_MILLISECONDS': 'duration',
    # 'SRC_TO_DST_IAT_AVG': 'src_to_dst_iat_avg',
    # 'DST_TO_SRC_IAT_AVG': 'dst_to_src_iat_avg',

    # 4. VOLUMETRIC (Detecting Exfiltration & Floods)
    'IN_BYTES': 'ingress_byte_count',
    'OUT_BYTES': 'egress_byte_count',
    'SRC_TO_DST_AVG_THROUGHPUT': 'src_to_dst_throughput',

    # 5. ANOMALY INDICATORS (Signs of network stress)
    'RETRANSMITTED_IN_PKTS': 'retransmitted_in_pkts',
    'MAX_IP_PKT_LEN': 'max_packet_len',
    'MAX_TTL': 'max_ttl',

    # TARGET
    'Label': 'label' 
}

# 2. Filter for only the columns we need
df_filtered = df[list(mapping.keys())]

# 3. Rename them to the pipeline-friendly names
df_filtered = df_filtered.rename(columns=mapping)

# 4. Save for use in run_pipeline.py
df_filtered.to_csv("data/raw/new_sighting_data.csv", index=False)