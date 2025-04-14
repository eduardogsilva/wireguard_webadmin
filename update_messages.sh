#!/bin/bash
django-admin makemessages -a --ignore=.venv/*
django-admin compilemessages --ignore=.venv/*