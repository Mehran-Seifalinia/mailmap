from json import dump
from typing import Dict, Any, Optional, Union
from datetime import datetime
from os import makedirs, path

class ReportGenerator:
    def __init__(self, output_dir: str = "output"):
        """
        Initialize ReportGenerator with output directory.
        Creates the directory if it doesn't exist.
        """
        self.output_dir = output_dir
        makedirs(self.output_dir, exist_ok=True)

    def generate_json(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Save the report data as a JSON file.
        Returns the path to the saved file.
        """
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        file_path = path.join(self.output_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            dump(data, f, ensure_ascii=False, indent=4)
        return file_path

    def generate_markdown(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Convert the report data to Markdown format and save it.
        Returns the path to the saved file.
        """
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        file_path = path.join(self.output_dir, filename)
        md_content = self._convert_to_markdown(data)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        return file_path

    def generate_html(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Convert the report data to HTML format and save it.
        Returns the path to the saved file.
        """
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        file_path = path.join(self.output_dir, filename)
        html_content = self._convert_to_html(data)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return file_path

    def _convert_to_markdown(self, data: Union[Dict, list, str, bool, None], level: int = 1) -> str:
        """
        Recursively convert data to markdown.
        Supports dict, list, str, bool, None.
        """
        md = ""
        prefix = "#" * level + " " if level <= 6 else ""
        
        if isinstance(data, dict):
            for key, value in data.items():
                md += f"{prefix}{key}\n\n"
                md += self._convert_to_markdown(value, level + 1) + "\n"
        elif isinstance(data, list):
            for item in data:
                # If item is dict or list, recurse, else print as bullet
                if isinstance(item, (dict, list)):
                    md += self._convert_to_markdown(item, level + 1)
                else:
                    md += f"- {item}\n"
        elif isinstance(data, bool):
            md += "Yes\n" if data else "No\n"
        elif data is None:
            md += "N/A\n"
        else:
            md += f"{data}\n"
        return md

    def _convert_to_html(self, data: Union[Dict, list, str, bool, None], level: int = 1) -> str:
        """
        Recursively convert data to HTML.
        Supports dict, list, str, bool, None.
        """
        html = ""
        tag = f"h{level}" if level <= 6 else "h6"

        if isinstance(data, dict):
            for key, value in data.items():
                html += f"<{tag}>{key}</{tag}>\n"
                html += self._convert_to_html(value, level + 1)
        elif isinstance(data, list):
            html += "<ul>\n"
            for item in data:
                if isinstance(item, (dict, list)):
                    html += "<li>\n" + self._convert_to_html(item, level + 1) + "</li>\n"
                else:
                    html += f"<li>{item}</li>\n"
            html += "</ul>\n"
        elif isinstance(data, bool):
            html += "<p>Yes</p>" if data else "<p>No</p>"
        elif data is None:
            html += "<p>N/A</p>"
        else:
            html += f"<p>{data}</p>"
        return html
