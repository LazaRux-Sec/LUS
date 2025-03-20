import tkinter as tk
from tkinter import messagebox, scrolledtext
from urllib.parse import urlparse
from base64 import urlsafe_b64encode
import threading
import virustotal_python
from virustotal_python import VirustotalError

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = 'c7f764c0cf5a6e7df0c3928dabf50a2e28ef776f312bffb9326a73132d89b986'

# Function to scan URL using VirusTotal API
def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Please enter a URL!")
        return

    # Validate URL
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        messagebox.showerror("Error", "Invalid URL entered!")
        return

    # Clear previous results
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.config(state=tk.DISABLED)

    # Perform scan in a separate thread
    scan_thread = threading.Thread(target=perform_scan, args=(url,))
    scan_thread.start()

def perform_scan(url):
    try:
        with virustotal_python.Virustotal(API_KEY) as vtotal:
            # Submit URL for scanning
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            # Encode URL in base64 format
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            # Retrieve scan report
            report = vtotal.request(f"urls/{url_id}")

            # Extract analysis statistics
            stats = report.data['attributes']['last_analysis_stats']
            harmless = stats.get('harmless', 0)
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            timeout = stats.get('timeout', 0)
            undetected = stats.get('undetected', 0)

            # Calculate total number of scans
            total = harmless + malicious + suspicious + timeout + undetected

            # Calculate safety score
            if total > 0:
                safety_score = ((total - malicious) / total) * 100
            else:
                safety_score = 0

            # Display results
            update_result(f"URL: {url}\n")
            update_result(f"Safety Score: {safety_score:.2f}%\n")
            update_result("Scan Results:\n")

            for scanner, result in report.data['attributes']['last_analysis_results'].items():
                if result['category'] == 'malicious':
                    update_result(f"{scanner}: ❌ Detected as malicious\n")
                else:
                    update_result(f"{scanner}: ✅ No threats found\n")

    except VirustotalError as err:
        update_result(f"Error: {err}\n")

# Modified update_result to schedule UI updates on the main thread.
def update_result(message):
    def inner():
        result_text.config(state=tk.NORMAL)
        result_text.insert(tk.END, message)
        result_text.config(state=tk.DISABLED)
    root.after(0, inner)

# Function to clear results
def clear_results():
    url_entry.delete(0, tk.END)
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.config(state=tk.DISABLED)

# Create GUI
root = tk.Tk()
root.title("LazaRux URL Scanner v1.0")
root.geometry("600x400")

# URL entry
url_label = tk.Label(root, text="Enter URL:")
url_label.pack(pady=5)
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

# Scan button
scan_button = tk.Button(root, text="Scan URL", command=scan_url)
scan_button.pack(pady=5)

# Clear button
clear_button = tk.Button(root, text="Clear Results", command=clear_results)
clear_button.pack(pady=5)

# Result display
result_text = scrolledtext.ScrolledText(root, width=70, height=15, state=tk.DISABLED)
result_text.pack(pady=5)

# Run the GUI loop
root.mainloop()
