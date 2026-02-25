# app.py
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from transformers import pipeline
import random
import time
import io
import requests

st.set_page_config(page_title="Aerospace Cyber Threat Dashboard", layout="wide")
st.title("🚀 Aerospace AI Cyber Threat Detection Dashboard")
st.markdown("""
Classify logs into **Safe**, **Suspicious**, and **High Risk** using AI in real-time.
""")

st.sidebar.header("Options")
st.sidebar.info("Upload a CSV of logs or let the system use sample logs for demo.")
filter_level = st.sidebar.selectbox("Filter Threat Level", ["All","Safe","Suspicious","High Risk"])
simulate_realtime = st.sidebar.checkbox("Simulate Real-Time Logs", value=True)


uploaded_file = st.file_uploader("Upload Log CSV (Max 200MB)", type=["csv"])
if uploaded_file is not None:
    logs = pd.read_csv(uploaded_file)
    st.success("✅ CSV Uploaded Successfully!")
else:
    st.warning("⚠️ No CSV uploaded. Using built-in sample logs for demo.")
    
    sample_logs = [
        "Engine temperature normal",
        "Multiple failed login attempts",
        "System running smoothly",
        "Navigation system operational",
        "Critical firewall breach detected",
        "Unauthorized access attempt detected",
        "Suspicious network activity detected"
    ]
    logs = pd.DataFrame({'log_message': random.sample(sample_logs, k=len(sample_logs))})

st.subheader("🔹 AI Threat Classification")

@st.cache_resource
def load_model():
    return pipeline(
        "sentiment-analysis",
        model="distilbert/distilbert-base-uncased-finetuned-sst-2-english"
    )

classifier = load_model()
logs['Threat Level'] = ""

POSITIVE_THRESHOLD = 0.8
NEGATIVE_THRESHOLD = 0.85

for i in range(len(logs)):
    log_text = logs.loc[i, 'log_message']
    if simulate_realtime:
        time.sleep(0.5)
    try:
        result = classifier(log_text)[0]
        label = result['label']
        score = result['score']

        if label=="POSITIVE" and score > POSITIVE_THRESHOLD:
            logs.loc[i,'Threat Level'] = "Safe"
        elif label=="NEGATIVE" and score > NEGATIVE_THRESHOLD:
            logs.loc[i,'Threat Level'] = "High Risk"
        else:
            logs.loc[i,'Threat Level'] = "Suspicious"
    except:
        logs.loc[i,'Threat Level'] = "Unknown"


display_logs = logs if filter_level=="All" else logs[logs['Threat Level']==filter_level]


safe_count = len(logs[logs['Threat Level']=="Safe"])
suspicious_count = len(logs[logs['Threat Level']=="Suspicious"])
highrisk_count = len(logs[logs['Threat Level']=="High Risk"])

col1, col2, col3 = st.columns(3)
col1.metric("Safe Logs", safe_count, delta=None)
col2.metric("Suspicious Logs", suspicious_count, delta=None)
col3.metric("High Risk Logs", highrisk_count, delta=None)


def color_rows(row):
    if row['Threat Level']=="Safe":
        return ['background-color:#2ecc71']*len(row)
    elif row['Threat Level']=="Suspicious":
        return ['background-color:#f1c40f']*len(row)
    elif row['Threat Level']=="High Risk":
        return ['background-color:#e74c3c']*len(row)
    else:
        return ['background-color:#e0e0e0']*len(row)

st.subheader("🔹 Classified Logs")
st.dataframe(display_logs.style.apply(color_rows, axis=1))


fig1, ax1 = plt.subplots()
ax1.pie([safe_count, suspicious_count, highrisk_count],
        labels=["Safe","Suspicious","High Risk"],
        autopct='%1.1f%%',
        colors=['#2ecc71','#f1c40f','#e74c3c'],
        startangle=90)
ax1.axis('equal')
st.subheader("Threat Distribution")
st.pyplot(fig1)


fig2, ax2 = plt.subplots()
ax2.bar(["Safe","Suspicious","High Risk"], [safe_count,suspicious_count,highrisk_count],
        color=['#2ecc71','#f1c40f','#e74c3c'])
plt.ylabel("Number of Logs")
plt.title("Threat Level Counts")
st.subheader("Threat Level Counts")
st.pyplot(fig2)


csv_buffer = io.StringIO()
logs.to_csv(csv_buffer, index=False)
st.download_button("Download Classified Logs CSV", csv_buffer.getvalue(), "classified_logs.csv", "text/csv")

fig1.savefig("pie_chart.png")
st.download_button("Download Threat Pie Chart", data=open("pie_chart.png","rb"), file_name="threat_distribution.png")
fig2.savefig("bar_chart.png")
st.download_button("Download Threat Count Bar Chart", data=open("bar_chart.png","rb"), file_name="threat_count_bar_chart.png")