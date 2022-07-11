import argparse
from asyncore import write

import pandas as pd
from scapy.all import *
from sklearn import preprocessing
from sklearn.ensemble import IsolationForest


def get_dns_packets(pcap_file: str) -> pd.DataFrame:
    dns_packets = []

    for packet in PcapReader(pcap_file):
        try:
            if packet.haslayer(DNS):
                dns_layer = packet.getlayer(DNS)
                fields = dns_layer.fields
                dns_attributes = {}
                for field in fields:
                    value = fields.get(field)
                    if isinstance(value, int):
                        dns_attributes[field] = value
                    if value is None:
                        dns_attributes[field] = 0
                    if field == "qd":
                        dns_attributes["qname"] = value.fields.get(
                            "qname").decode("utf-8")
                        dns_attributes["qtype"] = value.fields.get("qtype")
                        dns_attributes["qclass"] = value.fields.get("qclass")

                data_frame = pd.DataFrame(dns_attributes, index=[0])
                dns_packets.append(data_frame)
        except Exception as e:
            print(e)

    return pd.concat(dns_packets)


def get_args():
    parser = argparse.ArgumentParser(
        description='Detect anomalous DNS traffic')
    parser.add_argument('--file', required=True, type=str,
                        help='The pcap file to traverse')
    parser.add_argument('--output', required=False, default="results.csv", type=str,
                        help='The name of the results file containing any found anomalous data information')
    args = parser.parse_args()
    return args


def transform_category_values(data_frame: pd.DataFrame) -> pd.DataFrame:
    label_encoder = preprocessing.LabelEncoder()

    category_values = data_frame[['qr', 'opcode', 'aa',
                                  'tc', 'rd', 'ra', 'z', 'ad', 'cd', 'rcode', 'qdcount', 'ancount', 'nscount', 'arcount', 'qtype', 'qclass']]
    for (column_name, column) in category_values.iteritems():
        category_values[column_name] = label_encoder.fit_transform(
            column.values)

    label_encoder.fit(data_frame["qname"])
    category_values["qname"] = label_encoder.transform(
        data_frame["qname"])

    return category_values, label_encoder


def run_isolation_forest(data_frame: pd.DataFrame) -> pd.DataFrame:
    clf = IsolationForest().fit(data_frame)
    predictions = clf.predict(data_frame)
    data_frame["prediction"] = predictions
    return data_frame


def print_logo():
    logo = '''

  _____  _   _  _____                                       _           ______ _           _           
 |  __ \| \ | |/ ____|    /\                               | |         |  ____(_)         | |          
 | |  | |  \| | (___     /  \   _ __   ___  _ __ ___   __ _| |_   _    | |__   _ _ __   __| | ___ _ __ 
 | |  | | . ` |\___ \   / /\ \ | '_ \ / _ \| '_ ` _ \ / _` | | | | |   |  __| | | '_ \ / _` |/ _ \ '__|
 | |__| | |\  |____) | / ____ \| | | | (_) | | | | | | (_| | | |_| |   | |    | | | | | (_| |  __/ |   
 |_____/|_| \_|_____/ /_/    \_\_| |_|\___/|_| |_| |_|\__,_|_|\__, |   |_|    |_|_| |_|\__,_|\___|_|   
                  ______                                       __/ |_____                              
                 |______|                                     |___/______|                             

'''
    print(logo)


def write_results(data_frame: pd.DataFrame, label_encoder, file_name: str, ):
    results = data_frame[data_frame.prediction > -1]
    qname_values = results["qname"]

    final_df = pd.DataFrame(results["id"])
    final_df["qname"] = label_encoder.inverse_transform(qname_values)
    final_df.to_csv(file_name, index=False)


def main():
    print_logo()
    args = get_args()
    dns_packets_data_frame = get_dns_packets(args.file)
    transformed_category_df, label_encoder = transform_category_values(
        dns_packets_data_frame)
    results = run_isolation_forest(transformed_category_df)
    total_anomalies = results[results.prediction > -1].count()["prediction"]
    print(f"{total_anomalies} anomalies were found!")
    results['id'] = dns_packets_data_frame['id']
    write_results(results, label_encoder, args.output)
    print(f"Results printed to {args.output}")


main()
