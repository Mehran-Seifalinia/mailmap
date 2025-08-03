from json import dump
from os import makedirs, path
from html import escape
from typing import Any, Dict, List, Union
from logging import info, error, basicConfig, INFO

DataType = Union[Dict[str, Any], List[Any], str, int, float, None]

basicConfig(level=INFO, format='%(message)s')

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

    def __init__(self, output_dir: str = "output") -> None:
        self.output_dir = output_dir
        makedirs(self.output_dir, exist_ok=True)

    def generate_json(self, data: DataType, filename: str = "report.json") -> None:
        filepath = path.join(self.output_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                dump(data, f, indent=4, ensure_ascii=False)
            info(f"[✅] JSON report saved to {filepath}")
        except Exception as e:
            error(f"[❌] Error saving JSON report: {e}")

    def generate_markdown(self, data: DataType, filename: str = "report.md") -> None:
        filepath = path.join(self.output_dir, filename)
        try:
            md = self._to_markdown(data)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
            info(f"[✅] Markdown report saved to {filepath}")
        except Exception as e:
            error(f"[❌] Error saving Markdown report: {e}")

    def generate_html(self, data: DataType, filename: str = "report.html") -> None:
        filepath = path.join(self.output_dir, filename)
        try:
            html_content = self._to_html(data)
            full_html = (
                f"<!DOCTYPE html><html lang='fa'><head>"
                f"<meta charset='UTF-8'><title>گزارش Mailmap</title>"
                f"{self.CSS_STYLE}</head><body>{html_content}</body></html>"
            )
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(full_html)
            info(f"[✅] HTML report saved to {filepath}")
        except Exception as e:
            error(f"[❌] Error saving HTML report: {e}")

    def _to_markdown(self, data: DataType, level: int = 1) -> str:
        md = ""
        if isinstance(data, dict):
            for section, content in data.items():
                md += f"{'#' * level} {section}\n\n"
                md += self._to_markdown(content, level=level+1)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    md += self._to_markdown(item, level=level)
                else:
                    md += f"- {item}\n"
            md += "\n"
        else:
            md += f"{data}\n\n"
        return md

    def _to_html(self, data: DataType) -> str:
        if isinstance(data, dict):
            html_content = ""
            for section, content in data.items():
                html_content += f"<h2>{escape(str(section))}</h2>"
                html_content += self._to_html(content)
            return html_content
        elif isinstance(data, list):
            html_content = "<ul>"
            for item in data:
                html_content += f"<li>{self._to_html(item)}</li>"
            html_content += "</ul>"
            return html_content
        else:
            return f"<p>{escape(str(data))}</p>"
