# External imports
import os
import socket
import requests
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Internal imports


shodan_API_key = os.getenv('SHODAN_API_KEY')

def create_pdf(site_name, info_dict, output_filename):
    # Create PDF 
    c = canvas.Canvas(output_filename, pagesize=letter)
    width, height = letter

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, height - 72, site_name)

    # Starting position for the info
    y_position = height - 100

    # Loop through the information dictionary
    for sub_header, info in info_dict.items():
        # Subheader
        c.setFont("Helvetica-Bold", 12)
        c.drawString(72, y_position, sub_header)
        y_position -= 20  # Move down

        # Input info
        c.setFont("Helvetica", 12)
        c.drawString(72, y_position, str(info))
        y_position -= 40  # Move down

        # Check if new page is needed
        if y_position < 72:  # Footer
            c.showPage()
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, height - 72, site_name)
            y_position = height - 100

    c.save()





def main():
    print('What type information would you like to gather?\n'
          '\n'
          '1. Basic information\n'
          '2. Detailed information\n'
          '3. A Site Map')

    userInput = input()

    if userInput.lower() == '1' or 'basic' or 'basic info' or 'basic information':
        # call function for
        pass
    elif userInput.lower() == '2' or 'detailed' or 'detailed info' or 'detailed information':
        pass
    elif userInput.lower() == '3' or 'site map' or 'map' or ' a site map':
        pass
    elif userInput.lower() == 'q' or 'quit' or 'exit':
        pass

    info_dict = {}
    userTarget = input('Enter target URL\n'
                       '> ')
    
    target_folder = userTarget
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    create_pdf(userTarget, info_dict, userTarget + "_site_info.pdf")


if __name__ == "__main__":
    main()