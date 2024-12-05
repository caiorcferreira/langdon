import requests
from bs4 import BeautifulSoup
from markdownify import markdownify as md
import re
from streamlit.logger import get_logger


logger = get_logger(__name__)


def collapse_empty_lines(text):
    collapsed_text = re.sub(r'(\n\s*){3,}', '\n\n', text)
    return collapsed_text


def website_to_md(url):
    logger.info(f"Retrieving website: {url}")
    
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to retrieve the website.")

    logger.info("Successfully retrieved the website.")

    soup = BeautifulSoup(response.text, 'html.parser')

    logger.info("Successfully parsed the HTML.")

    markdown_content = md(str(soup))

    markdown_content = markdown_content.strip()
    markdown_content = collapse_empty_lines(markdown_content)

    logger.info("Successfully converted the HTML to markdown.")

    return markdown_content
