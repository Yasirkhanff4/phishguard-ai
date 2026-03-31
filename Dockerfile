FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install flask flask-cors scikit-learn pandas numpy gunicorn
EXPOSE 7860
ENV PORT=7860
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "app:app"]
