# DNS_Anomaly_Finder

## General Information
- Author: Corey Hartman
- Language: Python 3.10
- Description: An ML tool for performing anomaly detection in DNS requests

## Installation/Compilation
- Requires Python 3.10
- Just run pip install -r requirements.txt

## Utilization
To run a general check of a pcap file, run the following: 
```python3 ./dns_anomaly_finder.py --file=packetCapture.pcap --output=results.csv```

#### Notes
- The ```--output``` argument is not required, results will automatically output to a file called results.csv
- The ```--html``` flag is not required, if set, the output will be an html table instead of a CSV file.

## Additional Information

- Algorithms utilized: IsolationForest (Outlier Detection)

## Warning

- Machine learning is a memory and CPU intensive task with enough data, this may take a while with a large dataset and if system resources are exhausted, it is recommended to reduce the dataset size.
