Log Analysis Script
This Python script processes a log file (sample.log), analyzes it for IP request counts, 
the most frequently accessed endpoint, and any suspicious activity (failed login attempts). 
The results are displayed in the terminal and saved into a CSV file (log_analysis_results.csv).

# Features:
IP Request Count: Counts how many requests each IP address made.
Most Accessed Endpoint: Finds which endpoint (like /login, /home) was accessed the most.
Suspicious Activity: Detects IP addresses that attempted too many failed logins.

# How to Use:
Prepare the Files:

Make sure you have a sample.log file that contains your server logs.
Optionally, you can create a config.json file to customize the settings (like log file name, threshold for failed logins, and output CSV file name).
Default Configurations: If config.json is not found, the script will use default values:
Failed login threshold: 10
Log file: sample.log
Output CSV: log_analysis_results.csv

# Running the Script: 
Simply run the script in your terminal:
python script.py

# Results:
The script will print the results in the terminal, including:
Requests per IP address
Most frequently accessed endpoint
Suspicious activity (failed logins)
It will also save these results to a CSV file (log_analysis_results.csv).
