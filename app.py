import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import traceback
import base64

# -------------------- Page Config -------------------- #
st.set_page_config(
    page_title="IoT IDS Multi-Class Analyzer",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="auto"
)

# -------------------- Custom Theme with Background Image -------------------- #
def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

def set_background(png_file):
    bin_str = get_base64_of_bin_file(png_file)
    page_bg_img = '''
    <style>
    .stApp {
        background-image: url("data:image/png;base64,%s");
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
    }
    .main {
        background-color: rgba(16, 19, 26, 0.85);
        padding: 2rem;
        border-radius: 10px;
        backdrop-filter: blur(10px);
    }
    .stButton>button {
        background-color: #1E88E5;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #1565C0;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .stDataFrame {
        background-color: rgba(255, 255, 255, 0.1);
        border-radius: 5px;
        padding: 1rem;
    }
    h1, h2, h3, h4, h5, h6 {
        color: white !important;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
    }
    .stMarkdown {
        color: white !important;
    }
    </style>
    ''' % bin_str
    st.markdown(page_bg_img, unsafe_allow_html=True)

# Set the background image
try:
    set_background('cyber_bg.jpg')
except:
    st.markdown("""
        <style>
        .stApp {
            background-color: #10131a;
        }
        .main {
            background-color: rgba(16, 19, 26, 0.85);
            padding: 2rem;
            border-radius: 10px;
        }
        </style>
    """, unsafe_allow_html=True)

# -------------------- Header -------------------- #
st.markdown("<h1 style='text-align: center; color: white;'>ML-based Intrusion Detection System (Multi-Class)</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align: center; color: white;'>Protect your network with the power of Machine Learning 🛡️</h4>", unsafe_allow_html=True)

# -------------------- Load Model -------------------- #
model_path = "no_layering_rf_model.joblib"

try:
    model = joblib.load(model_path)
except Exception as e:
    st.error(f"❌ Failed to load model: {e}")
    st.error(traceback.format_exc())
    st.stop()

# -------------------- Label Mapping, Descriptions & Recommendations -------------------- #
label_map = {
    0: 'Benign Traffic',
    1: 'DoS Flood',
    2: 'DDoS Flood',
    3: 'Recon Flood',
    4: 'MQTT Flood'
}
attack_descriptions = {
    0: 'Normal, harmless network traffic.',
    1: 'Denial of Service attack using flooding.',
    2: 'Distributed Denial of Service attack using flooding.',
    3: 'Reconnaissance activity using flooding.',
    4: 'Flooding attack targeting MQTT protocol.'
}
attack_recommendations = {
    0: 'No action needed.',
    1: 'Check for abnormal traffic and block offending IPs.',
    2: 'Use DDoS mitigation services and rate limiting.',
    3: 'Monitor for scanning activity and block suspicious sources.',
    4: 'Secure MQTT brokers and monitor for unusual activity.'
}

# -------------------- Upload Dataset -------------------- #
st.subheader("📂 Upload IoT Network Data (features only, no label)")
uploaded_file = st.file_uploader("Upload CSV File", type=["csv"], key="no_label")

if uploaded_file is not None:
    try:
        data = pd.read_csv(uploaded_file)
        st.write("### Dataset Preview:")
        st.dataframe(data.head())

        if st.button("🚀 Predict Attacks", key="predict_no_label"):
            preds = model.predict(data)
            preds_named = [label_map.get(label, 'Unknown') for label in preds]
            st.success("✅ Prediction Completed!")
            st.write("### Predicted Attack Classes:")
            results = []
            for label in preds:
                results.append({
                    "Predicted Attack": label_map.get(label, 'Unknown'),
                    "Description": attack_descriptions.get(label, ''),
                    "Recommendation": attack_recommendations.get(label, '')
                })
            st.dataframe(pd.DataFrame(results))

            # -------- Pie Chart: Attack Type Distribution -------- #
            attack_counts = pd.Series(preds_named).value_counts().reset_index()
            attack_counts.columns = ['Attack Type', 'Count']

            fig_pie = px.pie(
                attack_counts,
                names='Attack Type',
                values='Count',
                title="🔍 Distribution of Detected Attack Types",
                color_discrete_sequence=px.colors.sequential.Blues,
                hole=0.3
            )
            st.markdown("### 📊 Attack Distribution")
            st.plotly_chart(fig_pie, use_container_width=True)

    except Exception as e:
        st.error(f"❌ Error reading or processing file: {e}")

# -------------------- Upload Dataset with Label (For Accuracy Calculation) -------------------- #
st.markdown("---")
st.subheader("📂 Upload Dataset with Labels (for accuracy check)")
uploaded_file_with_label = st.file_uploader("Upload CSV File with label column (named exactly 'Attack Name')", type=["csv"], key="with_label")

if uploaded_file_with_label is not None:
    try:
        data_label = pd.read_csv(uploaded_file_with_label)

        if 'Attack Name' not in data_label.columns:
            st.error("❌ The uploaded file must contain an 'Attack Name' column.")
        else:
            X = data_label.drop(columns=['Attack Name'])
            y_true = data_label['Attack Name']

            # Map string labels to numbers for comparison
            str_to_num = {v: k for k, v in label_map.items()}
            y_true_num = y_true.map(str_to_num)

            st.write("### Dataset Preview:")
            st.dataframe(data_label.head())

            if st.button("🚀 Predict & Calculate Accuracy", key="predict_with_label"):
                preds = model.predict(X)
                accuracy = np.mean(preds == y_true_num) * 100
                st.success(f"✅ Prediction Completed! Accuracy: {accuracy:.2f}%")

                # Show sample prediction results with labels
                preds_named = [label_map.get(label, 'Unknown') for label in preds]
                results_df = pd.DataFrame({
                    'True Label': y_true,
                    'Predicted Label': preds_named
                })
                st.write("### Sample Predictions vs True Labels:")
                st.dataframe(results_df.head(20))

    except Exception as e:
        st.error(f"Error reading or processing file: {e}") 