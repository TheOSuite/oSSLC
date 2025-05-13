# SSL Certificate Analyzer

This is a simple Python script that provides a graphical user interface (GUI) to analyze SSL certificates from websites. It can fetch certificate details, perform basic security checks, and potentially check for certificate revocation using Certificate Revocation Lists (CRLs).

**Please Note:** This is a beginner-friendly tool and may not perform all advanced certificate validation checks. The CRL checking functionality is a basic implementation and may have limitations.

## Features

*   **Fetch Certificate Details:** Connects to a given hostname and port (defaults to 443 for HTTPS) and retrieves the SSL certificate.
*   **Display Key Information:** Shows details like the certificate's Subject, Issuer, Validity Period, Serial Number, Public Key details, and Signature Algorithm.
*   **Subject Alternative Names (SANs):** Lists the alternative names the certificate is valid for.
*   **Basic Security Checks:**
    *   Checks if the certificate is currently valid based on its dates.
    *   Highlights certificates expiring soon or already expired.
    *   Checks for potentially weak public key sizes (e.g., RSA < 2048 bits).
    *   Checks for weak signature hash algorithms (e.g., MD5, SHA1).
    *   Verifies if the hostname matches the certificate's SANs or Common Name.
*   **CRL Checking (Basic):** Attempts to check if the certificate is listed in its associated Certificate Revocation List (CRL). **Note:** This is a basic check and may not cover all CRL scenarios or potential errors.
*   **GUI Interface:** Provides a user-friendly window to input hostnames and view results.
*   **Threading:** Performs analysis in the background to keep the GUI responsive.
*   **Export Results:** (Currently defined in code, but not fully implemented in GUI) Includes functions to export results to CSV and HTML formats.

## Prerequisites

Before running the script, you need to have Python installed on your system. You also need to install the required Python libraries.

1.  **Install Python:** Download and install the latest version of Python from [python.org](https://www.python.org/downloads/).
2.  **Install Libraries:** Open your terminal or command prompt and run the following command:

    ```bash
    pip install cryptography requests
    ```

    *   `cryptography`: Used for parsing and analyzing SSL certificates.
    *   `requests`: Used for fetching CRLs over HTTP.

## How to Run

1.  Save the provided Python code as a `.py` file (e.g., `cert_analyzer.py`).
2.  Open your terminal or command prompt.
3.  Navigate to the directory where you saved the file.
4.  Run the script using the command:

    ```bash
    python oSSLC.py
    ```

    This will open the GUI window.

## Using the GUI

1.  **Enter Hostnames:** In the text area labeled "Enter hostnames (one per line):", type the hostnames or IP addresses of the websites you want to analyze. Enter one hostname per line. You can optionally specify a port using `hostname:port` (e.g., `example.com:8443`).
2.  **Analyze Certificates:** Click the "Analyze Certificates" button. The script will connect to each hostname and fetch its certificate information.
3.  **View Results:** The analysis results will appear in the large text area below the button. The results for each hostname will be separated, and warnings or errors will be highlighted with different colors.

## Code Structure (For those interested)

*   **`check_crl(cert, crl_url)`:** A helper function to check if a certificate is revoked using a given CRL URL.
*   **`_fetch_certificate_info(hostname, port, queue)`:** Connects to a hostname, fetches the certificate, extracts details, performs basic checks, and puts the results into a queue. Runs in a separate thread.
*   **`export_to_csv(results, filename)`:** (Currently not linked to GUI) Writes the analysis results to a CSV file.
*   **`export_to_html(results, filename)`:** (Currently not linked to GUI) Writes the analysis results to an HTML table.
*   **`CertificateAnalyzerApp` Class:**
    *   `__init__`: Sets up the main Tkinter window and GUI elements.
    *   `_setup_gui`: Creates and arranges the widgets (labels, text areas, buttons).
    *   `_start_analysis`: Reads hostnames from the input, clears previous results, and starts a new thread for each hostname to fetch certificate info.
    *   `_process_queue`: Periodically checks the results queue and updates the GUI with the analysis results or errors.
    *   `_display_certificate_info`: Formats and inserts the certificate details into the results text area.

## Notes

*   The CRL checking functionality is a basic implementation. Real-world CRL validation involves more complex steps like checking the CRL's validity period, signature verification, and handling different CRL formats.
*   The export functions are defined but not currently accessible from the GUI. You would need to add buttons and connect them to these functions if you want to use them.
*   For analyzing a large number of hostnames, consider using a `concurrent.futures.ThreadPoolExecutor` for more efficient thread management.
*   Error handling is included, but complex network issues or certificate formats might still lead to unexpected behavior.

## Future

This is a beginner-friendly script. For the future we are considering:

*   Implementing the export functions in the GUI.
*   Adding more advanced certificate checks (e.g., OCSP stapling, certificate chain validation).
*   Improving the CRL checking robustness.
*   Adding a progress indicator.
*   Adding a "Cancel" button to stop analysis.

