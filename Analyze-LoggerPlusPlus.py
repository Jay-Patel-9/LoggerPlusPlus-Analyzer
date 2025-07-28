import csv
import pandas as pd
from collections import defaultdict
import webbrowser
import os
from urllib.parse import urlparse
import sys
import json
import re
from email.utils import parsedate_to_datetime
import html

# --- Default Headers for Logger++ CSV when header is missing ---
DEFAULT_HEADERS = [
    'Entry.Tool','Entry.Tags','Entry.InScope','Entry.ListenInterface','Entry.ClientIP','Request.AsBase64','Request.Headers','Request.Body','Request.BodyLength','Request.Time','Request.Length','Request.Tool','Request.Comment','Request.Complete','Request.URL','Request.Method','Request.Path','Request.Query','Request.PathQuery','Request.Protocol','Request.IsSSL','Request.UsesCookieJar','Request.Hostname','Request.Host','Request.Port','Request.ContentType','Request.RequestHttpVersion','Request.Extension','Request.Referrer','Request.HasParams','Request.HasGetParam','Request.HasPostParam','Request.HasSentCookies','Request.CookieString','Request.ParameterCount','Request.Parameters','Request.Origin','Response.AsBase64','Response.Headers','Response.Body','Response.BodyLength','Response.hash','Response.Time','Response.Length','Response.Redirect','Response.Status','Response.StatusText','Response.ResponseHttpVersion','Response.RTT','Response.Title','Response.ContentType','Response.InferredType','Response.MimeType','Response.HasSetCookies','Response.Cookies','Response.ReflectedParams','Response.Reflections'
]

def has_header(file_path):
    """
    Checks if the CSV file likely contains a header row.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline()
            return 'Entry.Tool' in first_line and 'Request.URL' in first_line
    except Exception:
        return False

def load_csv_safely(file_path):
    """
    Safely loads a CSV file into a pandas DataFrame, handling potential commas in fields
    and automatically detecting if a header is present.
    """
    try:
        if has_header(file_path):
            df = pd.read_csv(file_path, low_memory=False, on_bad_lines='warn')
        else:
            print(f"Warning: No header found in {os.path.basename(file_path)}. Applying default headers.")
            df = pd.read_csv(file_path, header=None, names=DEFAULT_HEADERS, low_memory=False, on_bad_lines='warn')
        return df
    except Exception as e:
        print(f"Error reading CSV file {file_path}: {e}")
        return pd.DataFrame()

def extract_date_from_headers(headers_str):
    """
    Extracts the date from the 'Date:' line in raw HTTP headers.
    """
    if not isinstance(headers_str, str):
        return None
    
    match = re.search(r'^Date:\s*(.*)', headers_str, re.IGNORECASE | re.MULTILINE)
    if match:
        date_str = match.group(1).strip()
        try:
            return parsedate_to_datetime(date_str)
        except (TypeError, ValueError):
            return None
    return None

def analyze_burp_log(df, exclude_extensions=None, exclude_tools=None):
    """
    Analyzes a DataFrame of Burp Suite Logger++ data to provide insights on web security testing activity.
    """
    if df.empty:
        print("The initial data is empty. No analysis to perform.")
        return None, None
    
    # --- Apply Filters ---
    if exclude_extensions:
        extensions_tuple = tuple(f".{ext.lower()}" for ext in exclude_extensions)
        df = df[~df['Request.URL'].str.lower().str.endswith(extensions_tuple, na=False)]
        print(f"Filtered out requests with extensions: {', '.join(exclude_extensions)}")

    if exclude_tools:
        df = df[~df['Request.Tool'].isin(exclude_tools)]
        print(f"Filtered out requests from tools: {', '.join(exclude_tools)}")

    if df.empty:
        print("All data was filtered out. No analysis to perform.")
        return None, None
        
    required_columns = ['Request.URL', 'Request.Tool']
    for col in required_columns:
        if col not in df.columns:
            print(f"Error: Required column '{col}' not found. The CSV might be malformed or not from Logger++.")
            return None, None

    # --- Timestamp Parsing Logic ---
    if 'Request.Time' in df.columns:
        df['Time'] = pd.to_datetime(df['Request.Time'], format='%m/%d/%Y %I:%M:%S %p', errors='coerce')
    else:
        df['Time'] = pd.NaT

    if df['Time'].isnull().all():
        print("Warning: Could not parse 'Request.Time'. Falling back to 'Response.Headers' for timestamps.")
        if 'Response.Headers' in df.columns:
            df['Time'] = df['Response.Headers'].apply(extract_date_from_headers)
            if 'Time' in df.columns and df['Time'].notna().any():
                 df['Time'] = df['Time'].dt.tz_localize(None)
        else:
            print("Error: 'Response.Headers' column not found. Cannot determine request times.")
            return None, None
            
    df.dropna(subset=['Time'], inplace=True)
    
    if df.empty:
        print("Error: No valid timestamps could be determined from 'Request.Time' or 'Response.Headers'.")
        return None, None

    # --- Analysis ---
    min_date, max_date = df['Time'].min(), df['Time'].max()
    date_range_str = f"{min_date.strftime('%d/%m/%Y %H:%M:%S')} to {max_date.strftime('%d/%m/%Y %H:%M:%S')}"

    df['Target'] = df['Request.URL'].apply(lambda x: urlparse(x).hostname if isinstance(x, str) else None)
    
    endpoint_counts = df['Request.URL'].value_counts().to_dict()
    target_counts = df['Target'].value_counts().to_dict()

    tool_endpoint_counts = defaultdict(lambda: defaultdict(int))
    for _, row in df.iterrows():
        tool_endpoint_counts[row['Request.URL']][row['Request.Tool']] += 1

    df['Date'] = df['Time'].dt.date
    daily_summary = defaultdict(lambda: {'total': 0, 'tools': defaultdict(int)})
    for _, row in df.iterrows():
        date_str = row['Date'].strftime('%Y-%m-%d')
        daily_summary[date_str]['total'] += 1
        daily_summary[date_str]['tools'][row['Request.Tool']] += 1
        
    tool_summary = df['Request.Tool'].value_counts().to_dict()

    # --- Productivity Analysis ---
    total_requests = len(df)
    active_days = df['Date'].nunique()
    avg_req_per_day = total_requests / active_days if active_days > 0 else 0
    peak_day = df['Date'].value_counts().idxmax().strftime('%d/%m/%Y') if not df.empty and not df['Date'].value_counts().empty else "N/A"
    peak_day_count = df['Date'].value_counts().max() if not df.empty and not df['Date'].value_counts().empty else 0
    
    productivity_metrics = {
        "Total Requests": total_requests,
        "Analysis Period (Days)": active_days,
        "Average Requests per Day": f"{avg_req_per_day:.2f}",
        "Peak Activity Day": peak_day,
        "Requests on Peak Day": peak_day_count
    }

    # --- Console Output ---
    print("\n--- Burp Suite Log Analysis ---")
    print(f"Analysis Period: {date_range_str}")
    print("\n--- Productivity Summary ---")
    for key, value in productivity_metrics.items():
        print(f"- {key}: {value}")
    
    print(f"\nTotal Requests per Target URL:")
    for target, count in sorted(target_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"- {target}: {count}")

    print(f"\nTop 10 Endpoints by Request Count:")
    for endpoint, count in sorted(endpoint_counts.items(), key=lambda item: item[1], reverse=True)[:10]:
        print(f"- {endpoint}: {count}")

    # --- HTML Report Generation ---
    sorted_daily_summary = sorted(daily_summary.items())
    daily_chart_labels = json.dumps([item[0] for item in sorted_daily_summary])
    daily_chart_data = json.dumps([item[1]['total'] for item in sorted_daily_summary])
    
    sorted_endpoints = sorted(endpoint_counts.items(), key=lambda item: item[1], reverse=True)
    
    escaped_endpoints_html = ''.join([f"<tr><td>{html.escape(str(endpoint))}</td><td>{count}</td></tr>" for endpoint, count in sorted_endpoints])
    escaped_daily_summary_html = ''.join([f"<tr><td>{pd.to_datetime(d).strftime('%d/%m/%Y')}</td><td>{v['total']}</td><td>{'<br>'.join([f'{html.escape(t)}: {c}' for t, c in v['tools'].items()])}</td></tr>" for d, v in sorted_daily_summary])


    html_content = f"""
    <html>
    <head>
        <title>Burp Suite Analysis Report</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; color: #333; }}
            .container {{ max-width: 1600px; margin: 20px auto; padding: 20px; }}
            .header {{ text-align: center; padding-bottom: 20px; border-bottom: 1px solid #dee2e6; margin-bottom: 20px; }}
            h1 {{ color: #0056b3; }} h2 {{ color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px; margin-top: 40px; }}
            .report-meta {{ text-align: center; margin-bottom: 30px; font-style: italic; color: #555; }}
            .card {{ background: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 20px; }}
            .grid-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }}
            .table-container {{ max-height: 500px; overflow-y: auto; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; table-layout: fixed; }}
            th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; word-wrap: break-word; }}
            th {{ background-color: #007bff; color: white; position: sticky; top: 0; z-index: 1; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            #endpointSearch {{ width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>Burp Suite Analysis Report</h1></div>
            <div class="report-meta"><p><strong>Analysis Period:</strong> {date_range_str}</p></div>

            <div class="card">
                <h2>Productivity Summary</h2>
                <div class="grid-container">
                    {''.join([f"<div><strong>{k.replace('_', ' ')}:</strong> {v}</div>" for k, v in productivity_metrics.items()])}
                </div>
            </div>

            <div class="card"><h2>Requests Over Time</h2><canvas id="dailyActivityChart"></canvas></div>

            <div class="card">
                <h2>Tool Usage Summary</h2>
                <div class="grid-container">
                    <div>
                        <table>
                            <tr><th>Tool</th><th>Total Requests</th></tr>
                            {''.join([f"<tr><td>{html.escape(tool)}</td><td>{count}</td></tr>" for tool, count in sorted(tool_summary.items(), key=lambda item: item[1], reverse=True)])}
                        </table>
                    </div>
                    <div><canvas id="toolChart"></canvas></div>
                </div>
            </div>
            
            <div class="card">
                <h2>All Endpoints by Request Count</h2>
                <input type="text" id="endpointSearch" onkeyup="filterTable()" placeholder="Search for endpoints..">
                <div class="table-container">
                    <table id="endpointsTable">
                        <tr><th style="width: 85%;">Endpoint</th><th style="width: 15%;">Request Count</th></tr>
                        {escaped_endpoints_html}
                    </table>
                </div>
            </div>

            <div class="card">
                <h2>Daily Request Summary</h2>
                <div class="table-container">
                    <table>
                        <tr><th>Date</th><th>Total Requests</th><th>Tool Breakdown</th></tr>
                        {escaped_daily_summary_html}
                    </table>
                </div>
            </div>
        </div>

        <script>
            const toolData = {json.dumps(list(tool_summary.items()))};

            new Chart('toolChart', {{ type: 'doughnut', data: {{ labels: toolData.map(item => item[0]), datasets: [{{ data: toolData.map(item => item[1]), backgroundColor: ['#3498db', '#e74c3c', '#9b59b6', '#f1c40f', '#2ecc71', '#1abc9c', '#34495e'] }}] }}, options: {{ responsive: true, maintainAspectRatio: false }} }});
            
            new Chart('dailyActivityChart', {{
                type: 'line',
                data: {{
                    labels: {daily_chart_labels},
                    datasets: [{{ label: 'Total Requests per Day', data: {daily_chart_data}, borderColor: '#28a745', backgroundColor: 'rgba(40, 167, 69, 0.1)', fill: true, tension: 0.1 }}]
                }},
                options: {{ scales: {{ x: {{ type: 'time', time: {{ unit: 'day', tooltipFormat: 'dd/MM/yyyy' }} }} }}, responsive: true }}
            }});

            function filterTable() {{
                let input, filter, table, tr, td, i, txtValue;
                input = document.getElementById("endpointSearch");
                filter = input.value.toUpperCase();
                table = document.getElementById("endpointsTable");
                tr = table.getElementsByTagName("tr");
                for (i = 1; i < tr.length; i++) {{ // Start from 1 to skip header
                    td = tr[i].getElementsByTagName("td")[0];
                    if (td) {{
                        txtValue = td.textContent || td.innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {{
                            tr[i].style.display = "";
                        }} else {{
                            tr[i].style.display = "none";
                        }}
                    }}
                }}
            }}
        </script>
    </body>
    </html>
    """
    
    analysis_data = {
        "endpoint_counts": endpoint_counts,
        "tool_endpoint_counts": tool_endpoint_counts,
        "daily_summary": daily_summary,
        "tool_summary": tool_summary,
        "target_counts": target_counts,
        "productivity_metrics": productivity_metrics
    }
    
    return html_content, analysis_data

def main():
    """
    Main function to drive the Burp Suite log analysis.
    """
    if len(sys.argv) > 1:
        path_input = sys.argv[1]
        print(f"Analyzing path provided via command-line argument: {path_input}")
    else:
        path_input = input("Enter the path to the Logger++ CSV file or a folder containing CSVs: ")

    if not os.path.exists(path_input):
        print(f"Error: The path '{path_input}' does not exist.")
        return

    # --- Get User Filter Preferences ---
    exclude_ext_str = input("Enter file extensions to exclude (comma-separated, e.g., js,css,woff2) or press Enter to skip: ")
    exclude_tools_str = input("Enter Burp tools to exclude (comma-separated, e.g., Scanner,Extensions) or press Enter to skip: ")
    output_path_str = input("Enter output file path (e.g., /path/to/report.html) or press Enter for default: ")

    exclude_extensions = [ext.strip().lower() for ext in exclude_ext_str.split(',') if ext.strip()]
    exclude_tools = [tool.strip() for tool in exclude_tools_str.split(',') if tool.strip()]

    all_dfs = []
    if os.path.isdir(path_input):
        csv_files = [f for f in os.listdir(path_input) if f.lower().endswith('.csv')]
        if not csv_files:
            print(f"No CSV files found in the directory: {path_input}")
            return
        
        print(f"Found {len(csv_files)} CSV files. Processing...")
        for filename in csv_files:
            file_path = os.path.join(path_input, filename)
            df = load_csv_safely(file_path)
            if not df.empty:
                all_dfs.append(df)
                print(f" - Successfully loaded {filename}")
        
    elif os.path.isfile(path_input):
        if not path_input.lower().endswith('.csv'):
            print("Error: The provided file is not a CSV file.")
            return
        df = load_csv_safely(path_input)
        if not df.empty:
            all_dfs.append(df)
    else:
        print(f"Error: The path '{path_input}' is not a valid file or directory.")
        return

    if not all_dfs:
        print("No valid CSV data could be loaded from the specified path.")
        return
    
    master_df = pd.concat([df.fillna(value=pd.NA) for df in all_dfs], ignore_index=True)

    html_report, analysis_data = analyze_burp_log(master_df, exclude_extensions, exclude_tools)

    if html_report:
        report_path = "burp_analysis_report.html" # Default value
        if output_path_str:
            # If user provides a path, use it.
            # Ensure the directory exists.
            output_dir = os.path.dirname(output_path_str)
            if output_dir and not os.path.exists(output_dir):
                print(f"Creating directory: {output_dir}")
                os.makedirs(output_dir)
            report_path = output_path_str

        with open(report_path, "w", encoding='utf-8') as f:
            f.write(html_report)
        print(f"\nHTML report generated: {os.path.abspath(report_path)}")
        try:
            webbrowser.open('file://' + os.path.realpath(report_path))
        except webbrowser.Error:
            print(f"Could not open web browser. Please open the report manually: {os.path.realpath(report_path)}")


if __name__ == "__main__":
    main()
