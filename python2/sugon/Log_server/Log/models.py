# -*- coding:utf-8 -*-
from __future__ import unicode_literals


from django.db import models
from django.core.exceptions import ValidationError
import re

# Create your models here.

def IPValidator(value):
    ip_format = re.compile(r'^((1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){3}(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if not ip_format.match(value):
        raise ValidationError("IP format Error !")

def PortValidator(value):
    try:
        value = int(value)
    except Exception as e:
        raise ValidationError(e)
    else:
        if value > 65535:
            raise ValidationError("Port number should be less than 65535 !")

class Log(models.Model):
    filename = models.CharField(max_length=64)
    ip = models.CharField(max_length=32, validators=[IPValidator,])
    port = models.PositiveIntegerField(validators=[PortValidator,])
    submission_time = models.DateField(auto_now_add=True)

    def __unicode__(self):
        return self.filename
