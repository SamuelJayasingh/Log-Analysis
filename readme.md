# **Log Analysis Tool**

A Python-based log analysis script designed to parse and analyze server log files. This tool provides insights such as the number of requests per IP, the most frequently accessed endpoints, and detection of suspicious activities like failed login attempts.

---

## **Features**

1. **Count Requests per IP Address**
   - Parses the log file to extract IP addresses and counts the number of requests made by each.
   - Results are sorted in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**
   - Analyzes log entries to determine which resource (e.g., `/home`, `/login`) was accessed the most.
   - Displays the endpoint and its access count.

3. **Detect Suspicious Activity**
   - Identifies IP addresses with failed login attempts (e.g., HTTP status code `401` or "Invalid credentials") exceeding a configurable threshold (default: 3).
   - Flags these IPs for potential brute-force or unauthorized access attempts.

4. **CSV Output**
   - Generates a structured CSV file containing the analysis results:
     - Requests per IP
     - Most accessed endpoint
     - Suspicious activity (failed login attempts)

---

## **Requirements**

- Python 3.6 or above

---

## **Installation**

1. Clone the repository:
   ```bash
   git clone https://github.com/SamuelJayasingh/Log-Analysis.git
   cd Log-Analysis
   ```

2. Ensure Python is installed:
   ```bash
   python --version
   ```

---

## **Usage**

1. Place your server log file in the same directory as `main.py`. A sample log file (`sample.log`) is provided for testing.

2. Run the script:
   ```bash
   python main.py
   ```

3. Check the terminal for analysis results.

4. View the CSV file (`log_analysis_results.csv`) generated in the same directory for detailed outputs.

---

## **Output**

### Terminal Output:
#### Example:
```bash
IP Address           Request Count
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7
10.0.0.2             6
192.168.1.100        5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
203.0.113.5          9
192.168.1.100        6
```

### CSV File:
#### Example (`log_analysis_results.csv`):
```csv
IP Address,Request Count
203.0.113.5,8
198.51.100.23,8
192.168.1.1,7
10.0.0.2,6
192.168.1.100,5

Most Accessed Endpoint,Access Count
/login,13

IP Address,Failed Login Attempts
203.0.113.5,9
192.168.1.100,6
```

---

## **Configuration**

### **Threshold for Failed Login Attempts**
To change the threshold for detecting suspicious activity, modify the `FAILED_LOGIN_THRESHOLD` constant in `main.py`:
```python
FAILED_LOGIN_THRESHOLD = <desired_threshold>
```

---

## **Project Structure**

```
.
├── main.py              # Log analysis script
├── sample.log           # Sample log file for testing
├── log_analysis_results.csv # Generated CSV file with results
├── README.md            # Project documentation
```

---

## **Contributing**

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your message here"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-branch
   ```
5. Open a pull request.

---

## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## **Contact**

For any questions or feedback, please feel free to reach out via GitHub issues.

