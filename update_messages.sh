#!/bin/bash
.venv/bin/django-admin makemessages -a --ignore=.venv/*
.venv/bin/django-admin compilemessages --ignore=.venv/*