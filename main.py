from Site_Info_Report import get_site_info_report, get_safe_filename
from Vulnerbility_Report import get_vulnerbility_Results
from SiteMap import crawl_and_create_site_map

Target = get_safe_filename(input("What webpage would you like to investigate?: \n"
                                "(Use the format 'example.com')\n"
                                "> "))

get_site_info_report(Target)
get_vulnerbility_Results(Target)
crawl_and_create_site_map(Target)

