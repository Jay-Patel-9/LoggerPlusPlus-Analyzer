# Burp Suite Logger++ Analysis & Reporting Tool

A powerful Python script to analyze and visualize web security testing activity from Burp Suite's Logger++ extension. This tool parses one or more Logger++ CSV export files, provides a detailed summary in the console, and generates a comprehensive, interactive HTML report to help you gain insights into your testing process.

## Key Features

* **Comprehensive Analysis**: Get statistics on total requests per target, per endpoint, and per day.
* **Productivity Insights**: Automatically calculates metrics like total active testing days, average requests per day, and peak activity days.
* **Tool Usage Breakdown**: Visualizes how many requests were sent from each Burp Suite tool (Proxy, Repeater, Scanner, etc.).
* **Interactive HTML Report**: Generates a clean, modern, and interactive single-file HTML report with charts and searchable tables.
* **Flexible Input**: Analyze a single Logger++ CSV file or an entire folder of them at once.
* **Intelligent Parsing**:
    * Automatically detects if the CSV has a header row and handles it accordingly.
    * Includes a robust fallback mechanism to parse timestamps from response headers if the primary `Request.Time` column is malformed or missing.
* **Advanced Filtering**: Dynamically exclude requests based on file extensions or the originating Burp tool to reduce noise.
* **Secure**: Sanitizes all data before rendering it in the HTML report to prevent Cross-Site Scripting (XSS) vulnerabilities from logged request URLs.

## HTML Report
1. Overview of the requests
![[Overview]([https://github.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/tree/main/Screenshots/Report-1.png](https://raw.githubusercontent.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/refs/heads/main/Screenshots/Report-1.png))](https://raw.githubusercontent.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/refs/heads/main/Screenshots/Report-1.png)
2. Request Time Chart
![Request Time Chart](https://raw.githubusercontent.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/refs/heads/main/Screenshots/Report-2.png)
3. Request Summary
![Request Summary](https://raw.githubusercontent.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/refs/heads/main/Screenshots/Report-3.png)
4. Requests Per Endpoint
![Requests Per Endpoint](https://raw.githubusercontent.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/refs/heads/main/Screenshots/Report-4.png)
5. Daily Request Summary
![Daily Request Summary](https://raw.githubusercontent.com/Jay-Patel-9/LoggerPlusPlus-Analyzer/refs/heads/main/Screenshots/Report-5.png)

## Requirements

* Python 3.x
* Pandas Library:
    ```bash
    pip install pandas
    ```

## How to Use

1.  **Run from the command line:**
    ```bash
    python Analyze-LoggerPlusPlus.py
    ```

2.  **Provide Input Path**: The script will first prompt you for the path to your data. You can provide:
    * A path to a single CSV file (e.g., `C:\burp_logs\log.csv`).
    * A path to a folder containing multiple CSV files (e.g., `C:\burp_logs\`).

    Alternatively, you can provide the path as a command-line argument:
    ```bash
    python Analyze-LoggerPlusPlus.py /path/to/your/logs/
    ```

3.  **Set Filters (Optional)**: You will be prompted to enter optional filters.
    * **Exclude Extensions**: Enter a comma-separated list of file extensions to ignore (e.g., `js,css,woff2,svg,png`). This is useful for filtering out static content.
    * **Exclude Tools**: Enter a comma-separated list of Burp Suite tools to ignore (e.g., `Scanner,Extensions`).

4.  **Specify Output Path (Optional)**: You can provide a full path, including the desired filename, to save the report.
    * Example: `/Users/test/Documents/reports/july_report.html`
    * If you press Enter without providing a path, the report will be saved as `burp_analysis_report.html` in the same directory where the script is located.

5.  **View Results**:
    * A summary will be printed directly to your console.
    * The full HTML report will be generated and automatically opened in your default web browser.

## Example Workflow

```bash
$ python Analyze-LoggerPlusPlus.py

Enter the path to the Logger++ CSV file or a folder containing CSVs: /Users/Name/pentest_project/logs/
Found 3 CSV files. Processing...
 - Successfully loaded Burp_LoggerPlusPlus_Autosave_2207.csv
 - Successfully loaded Burp_LoggerPlusPlus_Autosave_2307.csv
 - Successfully loaded Burp_LoggerPlusPlus_Autosave_2407.csv

Enter file extensions to exclude (comma-separated, e.g., js,css,woff2) or press Enter to skip: js,css,woff2,svg,png,gif,ico
Filtered out requests with extensions: js, css, woff2, svg, png, gif, ico

Enter Burp tools to exclude (comma-separated, e.g., Scanner,Extensions) or press Enter to skip: Scanner
Filtered out requests from tools: Scanner

Enter output file path (e.g., /path/to/report.html) or press Enter for default: /Users/Name/pentest_project/reports/final_report.html

--- Burp Suite Log Analysis ---
Analysis Period: 22/07/2025 10:00:00 to 24/07/2025 18:30:00

--- Productivity Summary ---
- Total Requests: 1578
- Analysis Period (Days): 3
- Average Requests per Day: 526.00
- Peak Activity Day: 23/07/2025
- Requests on Peak Day: 812

... (console output continues) ...

HTML report generated: /Users/Name/pentest_project/reports/final_report.html
