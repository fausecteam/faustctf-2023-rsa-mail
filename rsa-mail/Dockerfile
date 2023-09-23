FROM faust.cs.fau.de:5000/rsamail_deps

COPY app.py /app.py
COPY static/ /static/

CMD ["gunicorn", "--bind", "[::]:8000", "app:app"]
