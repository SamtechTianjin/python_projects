# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-08-14 13:52
from __future__ import unicode_literals

import Log.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Log', '0003_auto_20180814_2054'),
    ]

    operations = [
        migrations.AlterField(
            model_name='log',
            name='ip',
            field=models.CharField(max_length=32, validators=[Log.models.IPValidator]),
        ),
    ]
