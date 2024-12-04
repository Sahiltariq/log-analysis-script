import re
from collections import Counter
import csv
import pandas as pd


LOG_FILE = "sample.log"
CSV_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10



def parse_log_file(file_path):
    with open(file_path, "r") as file:
        logs = file.readlines()
    return logs



def count_requests_by_ip(logs):
    ip_pattern = r"^(\d+\.\d+\.\d+\.\d+)"
    ip_counts = Counter(re.match(ip_pattern, log).group(1) for log in logs if re.match(ip_pattern, log))
    return ip_counts



def find_most_accessed_endpoint(logs):
    endpoint_pattern = r"\"[A-Z]+ (/[^\s]*)"
    endpoints = [re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log)]
    endpoint_counts = Counter(endpoints)
    most_accessed = endpoint_counts.most_common(1)[0]
    return most_accessed



def detect_suspicious_activity(logs, threshold):
    suspicious_ips = Counter()
    for log in logs:
        if "401" in log:  # HTTP status code for unauthorized access
            ip = re.match(r"^(\d+\.\d+\.\d+\.\d+)", log).group(1)
            suspicious_ips[ip] += 1
    flagged_ips = {ip: count for ip, count in suspicious_ips.items() if count > threshold}
    return flagged_ips



def save_to_csv(ip_counts, most_accessed, flagged_ips, output_file):
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        writer.writerow([])


        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  # Blank row


        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in flagged_ips.items():
            writer.writerow([ip, count])



def main():
    logs = parse_log_file(LOG_FILE)

    # Analysis
    ip_counts = count_requests_by_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    flagged_ips = detect_suspicious_activity(logs, FAILED_LOGIN_THRESHOLD)


    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip: <20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in flagged_ips.items():
        print(f"{ip: <20} {count}")


    save_to_csv(ip_counts, most_accessed, flagged_ips, CSV_FILE)
    print(f"\nResults saved to {CSV_FILE}")


if __name__ == "__main__":
    main()
