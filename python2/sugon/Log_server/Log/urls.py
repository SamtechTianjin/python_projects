from django.conf.urls import url, include
import views

urlpatterns = [
    url(r'^$', views.update_log),
    url(r'^log', views.update_log),
]
