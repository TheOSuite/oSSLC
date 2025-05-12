import socket
import ssl
import tkinter as tk
from tkinter import ttk
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
import datetime
import threading
import queue
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
import csv
import time


def check_crl(cert, crl_url):
    """Checks if a certificate is revoked using a CRL.

    Args:
        cert: The certificate object to check (e.g., obtained from ssl.getpeercert()).
        crl_url: The URL of the CRL.

    Returns:
        True if the certificate is revoked, False otherwise.  Returns None if there's an error.
    """
    try:
        response = requests.get(crl_url, verify=False, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        crl = x509.load_crl_der_bytes(response.content, default_backend())

        # Crucial: Check if the certificate's serial number is in the CRL.
        for revoked_cert in crl.revoked_certificates:
            if revoked_cert.serial_number == cert.serial_number:
                return True  # Certificate is revoked

        return False  # Certificate is not revoked

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CRL: {e}")
        return None  # Indicate a problem during fetching
    except x509.ExtensionError as e:
        print(f"Error parsing CRL: {e}")
        return None  # Indicate a problem parsing the CRL
    except ValueError as e:
        print(f"Error comparing serial numbers: {e}")
        return None  # Indicate a problem comparing serial numbers
    except AttributeError as e:
        print(f"Error accessing certificate attribute: {e}")
        return None  # Indicate a problem accessing certificate attribute

# Example usage (assuming you have a certificate object named 'cert' and a URL named 'crl_url'):
# result = check_crl(cert, crl_url)
# if result is True:
#     print("Certificate is revoked.")
# elif result is False:
#     print("Certificate is not revoked.")
# else:
#     print("Error checking certificate revocation.")

def _fetch_certificate_info(hostname, queue):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_details = {
                    "Hostname": hostname,
                    "Valid From": cert["notBefore"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Valid Until": cert["notAfter"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Issuer": cert["issuer"],
                    "Subject": cert["subject"],
                    # Add more certificate details as needed...
                }


        # CRL Check (Crucial error handling)
        crl_url = None  # Get the CRL URL from the certificate
        # ... (Code to extract CRL URL from cert, if available) ...
        if crl_url:
            is_revoked = check_crl(x509.load_pem_x509_certificate(cert["subject"].encode(), default_backend()), crl_url)
            cert_details["Revoked"] = "Yes" if is_revoked else "No"


        queue.put(cert_details)
    except Exception as e:
        queue.put({"Error": str(e)})

def export_to_csv(results, filename="cert_results.csv"):
    if not results:
        return
    keys = results[0].keys()
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

def export_to_html(results, filename="cert_results.html"):
    if not results:
        return
    html = "<html><head><style>table { border-collapse: collapse; } td, th { border: 1px solid #ccc; padding: 8px; }</style></head><body>"
    html += "<table><tr>" + "".join(f"<th>{k}</th>" for k in results[0].keys()) + "</tr>"
    for row in results:
        html += "<tr>" + "".join(f"<td>{v}</td>" for v in row.values()) + "</tr>"
    html += "</table></body></html>"
    with open(filename, 'w') as f:
        f.write(html)


def check_crl(cert):
    try:
        crl_distribution_points = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value

        for point in crl_distribution_points:
            for uri in point.full_name:
                if uri.value.lower().startswith("http"):
                    response = requests.get(uri.value)
                    crl = x509.load_der_x509_crl(response.content, default_backend())
                    for revoked_cert in crl:
                        if revoked_cert.serial_number == cert.serial_number:
                            return "Revoked"
                    return "Not Revoked"
    except Exception as e:
        return f"CRL check failed: {e}"

    return "No CRL info"


class CertificateAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSL Certificate Analyzer")
        self._setup_gui()
        self.cert_queue = queue.Queue()

    def _setup_gui(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Enter hostnames (one per line):").grid(row=0, column=0, sticky="w")
        self.hostnames_entry = tk.Text(frame, height=10, width=60)
        self.hostnames_entry.grid(row=1, column=0, sticky="ew")

        self.scan_button = ttk.Button(frame, text="Analyze Certificates", command=self._start_analysis)
        self.scan_button.grid(row=2, column=0, pady=10)

        self.results_text = tk.Text(frame, height=30, width=80)
        self.results_text.grid(row=3, column=0, pady=10)

        # Tag styles
        self.results_text.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))
        self.results_text.tag_configure("valid", foreground="green")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("error", foreground="red")

    def _start_analysis(self):
        hostnames = self.hostnames_entry.get("1.0", tk.END).strip().splitlines()
        self.results_text.delete("1.0", tk.END)
        for hostname in hostnames:
            if hostname:
                thread = threading.Thread(target=self._fetch_certificate_info, args=(hostname.strip(), 443))
                thread.start()

        self.root.after(100, self._process_queue)

    def _fetch_certificate_info(self, hostname, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert)

                    # Gather details
                    cert_details = {
                        "hostname": hostname,
                        "port": port,
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before_utc": cert.not_valid_before_utc,
                        "not_after_utc": cert.not_valid_after_utc,
                        "serial_number": cert.serial_number,
                        "public_key_algorithm": cert.signature_algorithm_oid._name,
                        "signature_hash_algorithm": cert.signature_hash_algorithm.name,
                        "public_key_size": getattr(cert.public_key(), "key_size", "N/A")
                    }

                    # SANs
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        cert_details["sans"] = ext.value.get_values_for_type(x509.DNSName)
                    except Exception:
                        cert_details["sans"] = []

                    # Days remaining
                    now = datetime.datetime.now(datetime.timezone.utc)
                    cert_details["days_remaining"] = (cert.not_valid_after_utc - now).days

                    # Warnings and checks
                    warnings = []

                    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                        warnings.append("⚠️ Certificate is expired or not yet valid.")

                    if cert_details["days_remaining"] < 0:
                        warnings.append(f"❌ Expired {-cert_details['days_remaining']} day(s) ago.")
                    elif cert_details["days_remaining"] < 30:
                        warnings.append(f"⚠️ Expires in {cert_details['days_remaining']} day(s).")
                    else:
                        warnings.append(f"✅ Valid for {cert_details['days_remaining']} more day(s).")

                    # Key strength
                    public_key = cert.public_key()
                    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048:
                        warnings.append("⚠️ RSA key is less than 2048 bits.")
                    elif isinstance(public_key, dsa.DSAPublicKey) and public_key.key_size < 2048:
                        warnings.append("⚠️ DSA key is less than 2048 bits.")
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        if public_key.curve.name in ["secp192r1", "sect163k1"]:
                            warnings.append(f"⚠️ Weak EC curve: {public_key.curve.name}")

                    # Signature algorithm
                    if cert_details["signature_hash_algorithm"].lower() in ["md5", "sha1"]:
                        warnings.append(f"⚠️ Weak signature hash: {cert_details['signature_hash_algorithm']}")

                    # SAN match
                    if hostname not in cert_details["sans"] and f"www.{hostname}" not in cert_details["sans"]:
                        warnings.append("⚠️ Hostname does not match any SAN entry.")

                    cert_details["warnings"] = warnings

                    self.cert_queue.put(cert_details)

        except Exception as e:
            self.cert_queue.put({"hostname": hostname, "error": str(e)})

    def _process_queue(self):
        try:
            while True:
                cert_details = self.cert_queue.get_nowait()
                if "error" in cert_details:
                    self.results_text.insert(tk.END, f"[{cert_details['hostname']}] Error: {cert_details['error']}\n", "error")
                else:
                    self._display_certificate_info(cert_details)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_queue)

    def _display_certificate_info(self, cert_details):
        text = self.results_text
        text.insert(tk.END, f"\n=== {cert_details['hostname']}:{cert_details['port']} ===\n", "bold")

        def insert_line(label, value, tag=None):
            if isinstance(value, datetime.datetime):
                value = value.strftime("%Y-%m-%d %H:%M:%S UTC")
            text.insert(tk.END, f"{label}: {value}\n", tag)

        insert_line("Subject", cert_details.get("subject"))
        insert_line("Issuer", cert_details.get("issuer"))
        insert_line("Valid From", cert_details.get("not_before_utc"))
        insert_line("Valid To", cert_details.get("not_after_utc"))
        insert_line("Days Remaining", cert_details.get("days_remaining"))
        insert_line("Serial Number", cert_details.get("serial_number"))
        insert_line("Public Key", f"{cert_details['public_key_algorithm']} ({cert_details.get('public_key_size')})")
        insert_line("Signature Algorithm", cert_details.get("signature_hash_algorithm"))

        sans = cert_details.get("sans", [])
        insert_line("Subject Alt Names", ", ".join(sans) if sans else "None")

        for warning in cert_details.get("warnings", []):
            tag = "valid" if warning.startswith("✅") else "warning" if "⚠️" in warning else "error"
            text.insert(tk.END, f"[!] {warning}\n", tag)

        text.insert(tk.END, "\n")
        text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CertificateAnalyzerApp(root)
    root.mainloop()
