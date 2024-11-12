import re

# function that strips characters that are not allowed in filenames
def get_safe_filename(url):
    # Remove protocol and www
    url = re.sub(r"^https?://(www\.)?", "", url)
    # Remove characters not allowed in filenames
    filename = re.sub(r"[^\w\-_. ]", "_", url)
    return filename.strip("_ ")  # Remove leading/trailing whitespace and underscores