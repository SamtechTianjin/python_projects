# -*- coding:utf-8 -*-
__author__ = "Sam"

import requests
from lxml import etree
import re

# 获得腾讯招聘网站上所有关于python的招聘信息

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Referer": "https://hr.tencent.com/position.php?lid=&tid=&keywords=python&start=1",
}
PAGE_URL_BASE = "https://hr.tencent.com/position.php?lid=&tid=&keywords=python&start={}#a"
URL_BASE = "https://hr.tencent.com/"

# 首先获得最大页码数
def get_max_page():
    url = "https://hr.tencent.com/position.php?lid=&tid=&keywords=python&start=0#a"
    response = requests.get(url=url, headers=HEADERS)
    text = response.text
    html = etree.HTML(text=text)
    page_div = html.xpath("//div[@class='pagenav']")[0]
    page_max = page_div.xpath("./a")[-2].text
    return page_max

# 获得职位页面地址列表
def get_page_links(page_max):
    page_urls = []
    for i in range(0,(int(page_max)+1)*10, 10):
        url = PAGE_URL_BASE.format(i)
        page_urls.append(url)
    return page_urls

# 获得职位详细信息的链接
def get_jobs_info(page_urls):
    links = []
    jobs_info = []
    link_break = "=" * 50
    for page in page_urls:
        response = requests.get(url=page, headers=HEADERS)
        html= etree.HTML(text=response.text)
        table = html.xpath("//table[@class='tablelist']")[0]
        job_links = table.xpath(".//a[@target='_blank']/@href")
        for job_link in job_links:
            job_link = URL_BASE + job_link
            links.append(job_link)
            job_info = get_job_info(job_link=job_link)
            jobs_info.append(job_info)
            key_list = ["招聘职位", "工作地点", "职位类型", "招聘人数", "工作内容", "职位要求"]
            with open("腾讯python招聘信息.txt", "a", encoding="utf-8") as f:
                f.write("{}\n".format(link_break))
                for key in key_list:
                    if key == "工作内容" or key == "职位要求":
                        f.write("\n{0}:\n{1}".format(key, job_info[key]))
                    else:
                        f.write("{0}: {1}\n".format(key, job_info[key]))
            # break       # 调试时只获得第一个职位的链接
        # break           # 调试时只获得第一页的链接
    return jobs_info

# 获得每个职位的详细信息
def get_job_info(job_link):
    response = requests.get(url=job_link, headers=HEADERS)
    text = response.text
    html = etree.HTML(text=text)
    table = html.xpath("//table[@class='tablelist textl']")[0]
    job_name = table.xpath(".//td[@id='sharetitle']")[0].text
    job_name = re.split("[-（]", job_name)[1]
    # 首先初始化职位的所有信息项内容为空
    job_location,job_type,job_member_num,job_content,job_require = ("","","","","")
    tds = table.xpath(".//tr[@class='c bottomline']//td")
    for index,td in enumerate(tds):
        content = td.xpath("string(.)").split("：")[-1]
        if index == 0:
            job_location = content
        elif index == 1:
            job_type = content
        elif index == 2:
            job_member_num = content
    job_content_ul,job_require_ul = table.xpath(".//ul[@class='squareli']")
    content_lis = job_content_ul.xpath("./li")
    # 将多个信息以"\n"连接为一个字符串
    for content_li in content_lis:
        job_content += "{}\n".format(content_li.text)
    require_lis = job_require_ul.xpath("./li")
    for require_li in require_lis:
        job_require += "{}\n".format(require_li.text)
    job_info = {
        "招聘职位": job_name,
        "工作地点": job_location,
        "职位类型": job_type,
        "招聘人数": job_member_num,
        "工作内容": job_content,
        "职位要求": job_require,
    }
    return job_info


if __name__ == '__main__':
    page_max = get_max_page()
    page_urls = get_page_links(page_max=page_max)
    jobs_info = get_jobs_info(page_urls=page_urls)