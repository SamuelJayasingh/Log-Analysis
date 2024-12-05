import re
import csv
from collections import defaultdict

# Constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 3

def parse_log_file(file_path):
    """Reads the log file and returns lines."""
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []

def count_requests_per_ip(log_lines):
    """Counts the number of requests made by each IP address."""
    ip_counts = defaultdict(int)
    for line in log_lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip_counts[match.group(1)] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def most_frequent_endpoint(log_lines):
    """Identifies the most frequently accessed endpoint."""
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        match = re.search(r'\"[A-Z]+\s(\/[^\s]*)', line)
        if match:
            endpoint_counts[match.group(1)] += 1
    return max(endpoint_counts.items(), key=lambda x: x[1], default=(None, 0))

def detect_suspicious_activity(log_lines, threshold=FAILED_LOGIN_THRESHOLD):
    """Detects IPs with failed login attempts exceeding the threshold."""
    failed_attempts = defaultdict(int)
    for line in log_lines:
        if "401" in line or "Invalid credentials" in line:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def save_results_to_csv(ip_requests, most_accessed, suspicious_activity, output_file):
    """Saves the analysis results to a CSV file."""
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed)
        
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        writer.writerows(suspicious_activity.items())

def main():
    log_lines = parse_log_file(LOG_FILE)
    if not log_lines:
        print("No log data to process. Exiting.")
        return
    
    ip_requests = count_requests_per_ip(log_lines)
    most_accessed = most_frequent_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)
    
    save_results_to_csv(ip_requests, most_accessed, suspicious_activity, OUTPUT_CSV)
    
    print("IP Address           Request Count")
    for ip, count in ip_requests:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed[0]:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No endpoints found.")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()
