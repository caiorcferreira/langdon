import requests
from bs4 import BeautifulSoup
from markdownify import markdownify as md
import re


def collapse_empty_lines(text):
    collapsed_text = re.sub(r'(\n\s*){3,}', '\n\n', text)
    return collapsed_text


def website_to_md(url):
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to retrieve the website.")

    # Parse the HTML
    soup = BeautifulSoup(response.text, 'html.parser')

    # Convert the parsed HTML to markdown
    markdown_content = md(str(soup))

    markdown_content = markdown_content.strip()
    markdown_content = collapse_empty_lines(markdown_content)

    return markdown_content
