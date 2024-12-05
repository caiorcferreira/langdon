import fitz


def serialize_file(uploaded_file):
    if uploaded_file.type == "application/pdf":
        file_content = ""

        pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")
        for page_num in range(pdf_document.page_count):
            page = pdf_document.load_page(page_num)
            file_content += page.get_text()

        return file_content

    elif uploaded_file.type == "text/plain":
        return uploaded_file.getvalue().decode("utf-8")
    elif uploaded_file.type == "application/octet-stream" and uploaded_file.name.endswith(".md"):
        return uploaded_file.getvalue().decode("utf-8")
    else:
        raise Exception(f"Unsupported file type: {uploaded_file.type}")
