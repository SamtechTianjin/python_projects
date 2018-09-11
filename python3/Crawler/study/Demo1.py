# -*- coding:utf-8 -*-
__author__ = "Sam"

import requests
from lxml import etree

# 爬取豆瓣网正在上映和即将上映的影片信息 #

URL = "https://movie.douban.com/cinema/nowplaying/tianjin/"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Referer": "https://movie.douban.com/"
}

def get_movie_info(ul, is_score=True):
    movies = list()
    lis = ul.xpath("./li")
    for li in lis:
        # print(etree.tostring(li, encoding="utf-8").decode("utf-8"))
        title = li.xpath("@data-title")[0]
        director = li.xpath("@data-director")[0]
        duration = li.xpath("@data-duration")[0]
        actors = li.xpath("@data-actors")[0]
        if is_score:
            score = li.xpath("@data-score")[0]
            movie = {
                "影片": title,
                "主演": actors,
                "导演": director,
                "时长": duration,
                "评分": score,
            }
        else:
            movie = {
                "影片": title,
                "主演": actors,
                "导演": director,
                "时长": duration,
            }
        movies.append(movie)
    return movies

if __name__ == '__main__':

    response = requests.get(url=URL, headers=HEADERS)
    text = response.text
    html = etree.HTML(text=text)
    ul_nowplaying,ul_upcoming = html.xpath("//ul[@class='lists']")

    nowplaying_movies = get_movie_info(ul=ul_nowplaying)
    upcoming_movies = get_movie_info(ul=ul_upcoming, is_score=False)

    nowplaying_movie_key = ["影片", "主演", "导演", "时长", "评分"]
    upcoming_movie_key = ["影片", "主演", "导演", "时长"]
    print("\033[1;32m[正在上映]\033[0m")
    for movie in nowplaying_movies:
        print("=" * 50)
        for key in nowplaying_movie_key:
            print("\033[1;34m%s\033[0m: %s"%(key, movie[key]))
    print("\n")
    print("\033[1;31m[即将上映]\033[0m")
    for movie in upcoming_movies:
        print("=" * 50)
        for key in upcoming_movie_key:
            print("\033[1;34m%s\033[0m: %s"%(key, movie[key]))








