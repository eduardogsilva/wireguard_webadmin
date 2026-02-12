#!/bin/bash
.venv/bin/django-admin makemessages -a --ignore=.venv/*
.venv/bin/django-admin compilemessages --ignore=.venv/*
echo
for po in locale/*/LC_MESSAGES/django.po; do
    lang=${po#locale/}
    lang=${lang%%/*}
    echo -n "$lang: "
    msgfmt --statistics "$po" -o /dev/null 2>&1
done

