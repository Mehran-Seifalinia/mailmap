from json import dump
from os import makedirs, path

class ReportGenerator:
    CSS_STYLE = """
    <style>
    body { font-family: Arial, sans-serif; background: #f9f9f9; color: #333; padding: 20px; }
    h1, h2, h3 { color: #005f73; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background-color: #0a9396; color: white; }
    tr:nth-child(even) { background-color: #e0f7fa; }
    </style>
    """

    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        makedirs(self.output_dir, exist_ok=True)

    def generate_json(self, data, filename="report.json"):
        filepath = path.join(self.output_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                dump(data, f, indent=4, ensure_ascii=False)
            print(f"[✅] JSON report saved to {filepath}")
        except Exception as e:
            print(f"[❌] Error saving JSON report: {e}")

    def generate_markdown(self, data, filename="report.md"):
        filepath = path.join(self.output_dir, filename)
        try:
            md = self._to_markdown(data)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"[✅] Markdown report saved to {filepath}")
        except Exception as e:
            print(f"[❌] Error saving Markdown report: {e}")

    def generate_html(self, data, filename="report.html"):
        filepath = path.join(self.output_dir, filename)
        try:
            html_content = self._to_html(data)
            full_html = f"<!DOCTYPE html><html lang='fa'><head><meta charset='UTF-8'><title>گزارش Mailmap</title>{self.CSS_STYLE}</head><body>{html_content}</body></html>"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(full_html)
            print(f"[✅] HTML report saved to {filepath}")
        except Exception as e:
            print(f"[❌] Error saving HTML report: {e}")

    def _to_markdown(self, data):
        md = "# گزارش Mailmap\n\n"
        for section, content in data.items():
            md += f"## {section}\n\n"
            if isinstance(content, dict):
                for key, value in content.items():
                    md += f"- **{key}**: {value}\n"
            elif isinstance(content, list):
                for item in content:
                    md += f"- {item}\n"
            else:
                md += f"{content}\n"
            md += "\n"
        return md

    def _to_html(self, data):
        html = "<h1>گزارش Mailmap</h1>"
        for section, content in data.items():
            html += f"<h2>{section}</h2>"
            if isinstance(content, dict):
                html += "<table>"
                html += "<tr><th>کلید</th><th>مقدار</th></tr>"
                for key, value in content.items():
                    html += f"<tr><td>{key}</td><td>{value}</td></tr>"
                html += "</table>"
            elif isinstance(content, list):
                html += "<ul>"
                for item in content:
                    html += f"<li>{item}</li>"
                html += "</ul>"
            else:
                html += f"<p>{content}</p>"
        return html
