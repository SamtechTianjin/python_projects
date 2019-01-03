# -*- coding:utf-8 -*-

def env_init():
    import os
    import sys
    path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(path)
    path = os.path.dirname(path)
    sys.path.append(path)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Platform.settings")
    import django
    django.setup()


if __name__ == '__main__':
    pass