from Site_Info_Report import get_site_info_report, get_safe_filename
from Vulnerbility_Report import get_vulnerbility_report
from SiteMap import crawl_and_create_site_map
from OWASP_Top_10 import OWASP_Top_10_report

# main function to call all 
if __name__ == "__main__":
    # get user input on which site you wish to run the tools on
    Target = get_safe_filename(input("What webpage would you like to investigate?: \n"
                                    "(Use the format 'example.com')\n"
                                    "> "))

    # call functions to get reports
    get_site_info_report(Target)
    get_vulnerbility_report(Target)
    OWASP_Top_10_report(Target)
    crawl_and_create_site_map(Target)
    
