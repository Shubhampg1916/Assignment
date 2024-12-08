import re
from collections import Counter
import csv,json

DEFAULT_CONFIG = {
    "FAILED_LOGIN_THRESHOLD": 10,
    "LOG_FILE": "sample.log",
    "OUTPUT_CSV": "log_analysis_results.csv"
}

try:
    # Attempt to open and load the configuration file
    with open("config.json", "r") as config_file:
        config = json.load(config_file)

    # Extract configurations
    FAILED_LOGIN_THRESHOLD = config.get("FAILED_LOGIN_THRESHOLD", DEFAULT_CONFIG["FAILED_LOGIN_THRESHOLD"])
    LOG_FILE = config.get("LOG_FILE", DEFAULT_CONFIG["LOG_FILE"])
    OUTPUT_CSV = config.get("OUTPUT_CSV", DEFAULT_CONFIG["OUTPUT_CSV"])

except FileNotFoundError:
    print("Error: Configuration file 'config.json' not found. Using default configuration.")
    config = DEFAULT_CONFIG
    FAILED_LOGIN_THRESHOLD = config["FAILED_LOGIN_THRESHOLD"]
    LOG_FILE = config["LOG_FILE"]
    OUTPUT_CSV = config["OUTPUT_CSV"]

def process_log_data(log_file):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()
    try:
        with open(log_file, "r") as file:
            for line in file:
                # Extract IP address from each line of log file
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if not ip_match:
                    continue
                ip = ip_match.group(1)
                ip_requests[ip] += 1

                # Extract endpoint from each line of log file
                endpoint_match = re.search(r'"(?:GET|POST) (.*?) HTTP/1\.\d"', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_requests[endpoint] += 1

                # Check for failed login attempts
                if "401" in line or "Invalid credentials" in line:
                    failed_logins[ip] += 1
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return None, None, None  

    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, output_file):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip,count])

def main():
    # process log file
    ip_requests, endpoint_requests, failed_logins = process_log_data(LOG_FILE)

    # Find most accessed endpoint
    if endpoint_requests:
       most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    else:
       most_accessed_endpoint = ("None", 0)  

    # Print results on terminal
    print("\nIP Address Request Counts:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts'}")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count}")

    # Save results to CSV log_analysis_result.csv
    save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
