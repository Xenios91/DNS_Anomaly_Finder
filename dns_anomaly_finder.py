import argparse
from multiprocessing.sharedctypes import Value

import pandas as pd
from scapy.all import DNS
from scapy.utils import PcapReader
from sklearn import preprocessing
from sklearn.ensemble import IsolationForest


def get_dns_packets(pcap_file: str) -> pd.DataFrame:
    print("Processing packets please wait...")

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
        except:
            pass  # dont care, lets skip it

    return pd.concat(dns_packets)


def check_args(args):
    contamination = args.contamination

    if contamination is not None:
        if contamination <= 0 or contamination >= 1.0:
            raise ValueError(
                "Invalid contamination value, must be greater than 0 and less than 1.0")


def get_args():
    parser = argparse.ArgumentParser(
        description='Detect anomalous DNS traffic')
    parser.add_argument('--file', required=True, type=str,
                        help='The pcap file to traverse')
    parser.add_argument('--output', required=False, default="results", type=str,
                        help='The name of the results file containing any found anomalous data information')
    parser.add_argument('--html', required=False, default=False, type=bool, action=argparse.BooleanOptionalAction,
                        help='Set to have an HTML table produced')
    parser.add_argument('--contamination', required=False, default=None, type=float,
                        help='The amount of contamination of the data set, i.e. the proportion of outliers in the data set.')
    parser.add_argument('--threads', required=False, default=1, type=int,
                        help='The amount of threads to use, set to -1 for all available.')

    args = parser.parse_args()
    check_args(args)

    return args


def transform_category_values(data_frame: pd.DataFrame) -> pd.DataFrame:
    print("Preparing data for processing, please wait...")

    label_encoder = preprocessing.LabelEncoder()
    category_values = data_frame.loc[:, ['qr', 'opcode', 'aa',
                                         'tc', 'rd', 'ra', 'z', 'ad', 'cd', 'rcode', 'qdcount', 'ancount', 'nscount', 'arcount', 'qtype', 'qclass']]
    for (column_name, column) in category_values.iteritems():
        category_values.loc[:, column_name] = label_encoder.fit_transform(
            column.values)

    label_encoder.fit(data_frame["qname"])
    category_values.loc[:, "qname"] = label_encoder.transform(
        data_frame["qname"])

    return category_values, label_encoder


def run_isolation_forest(data_frame: pd.DataFrame, contamination: float, threads: int) -> pd.DataFrame:
    print("Looking for outliers, please wait...")

    if contamination is None:
        clf = IsolationForest().fit(data_frame)
    else:
        clf = IsolationForest(
            n_jobs=threads, contamination=contamination).fit(data_frame)
    predictions = clf.predict(data_frame)
    data_frame.loc[:, "prediction"] = predictions
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


def write_results(data_frame: pd.DataFrame, label_encoder, file_name: str, to_html: bool):
    results = data_frame[data_frame.prediction > -1]
    qname_values = results["qname"]

    final_df = pd.DataFrame(results["id"])
    final_df["qname"] = label_encoder.inverse_transform(qname_values)
    if to_html:
        final_df.to_html(f"{file_name}.html", index=False)
    else:
        final_df.to_csv(f"{file_name}.csv", index=False)


def main():
    print_logo()
    args = get_args()
    dns_packets_data_frame = get_dns_packets(args.file)
    transformed_dns_data_frame, label_encoder = transform_category_values(
        dns_packets_data_frame)
    results = run_isolation_forest(
        transformed_dns_data_frame, args.contamination, args.threads)
    total_anomalies = results[results.prediction > -1].count()["prediction"]
    print(f"{dns_packets_data_frame.size} total DNS packets processed...")
    print(f"{total_anomalies} anomalies were found!")
    results.loc[:, 'id'] = dns_packets_data_frame['id']
    write_results(results, label_encoder, args.output, args.html)
    print(f"Results printed to {args.output}")


main()
