from Site_Info_Report import get_site_info_report, get_safe_filename
from Vulnerbility_Report import get_vulnerbility_Results
from SiteMap import crawl_and_create_site_map
from OWASP_Top_10 import OWASP_Top_10_tests


if __name__ == "__main__":
    Target = get_safe_filename(input("What webpage would you like to investigate?: \n"
                                    "(Use the format 'example.com')\n"
                                    "> "))

    get_site_info_report(Target)
    get_vulnerbility_Results(Target)
    OWASP_Top_10_tests(Target)
    crawl_and_create_site_map(Target)
    
