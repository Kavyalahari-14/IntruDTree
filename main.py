import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler


# Load the trained model
model = joblib.load('best_model.pkl')

# Function to preprocess input data
def preprocess_input(data):
    categorical_columns = ['protocol_type', 'service', 'flag']
    for column in categorical_columns:
        le = LabelEncoder()
        data[column] = le.fit_transform(data[column])
    return data

# Function to scale input data
def scale_data(data):
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)
    return data_scaled

# Streamlit web application
def main():
    st.title('Intrusion Detection System')

    # User input form
    st.write('Enter the values for prediction:')
    protocol_type = st.selectbox('Protocol Type', ['tcp', 'udp', 'icmp'])
    service = st.selectbox('Service', ['http', 'smtp', 'private', 'other'])
    flag = st.selectbox('Flag', ['SF', 'S0', 'REJ', 'RSTR', 'RSTO'])

    src_bytes = st.number_input('Source Bytes')
    dst_bytes = st.number_input('Destination Bytes')
    count = st.number_input('Count')
    same_srv_rate = st.number_input('Same Service Rate')
    diff_srv_rate = st.number_input('Different Service Rate')
    dst_host_srv_count = st.number_input('Destination Host Service Count')
    dst_host_same_srv_rate = st.number_input('Destination Host Same Service Rate')

    # Preprocess user input
    input_data = pd.DataFrame({
        'protocol_type': [protocol_type],
        'service': [service],
        'flag': [flag],
        'src_bytes': [src_bytes],
        'dst_bytes': [dst_bytes],
        'count': [count],
        'same_srv_rate': [same_srv_rate],
        'diff_srv_rate': [diff_srv_rate],
        'dst_host_srv_count': [dst_host_srv_count],
        'dst_host_same_srv_rate': [dst_host_same_srv_rate]
    })

    input_data = preprocess_input(input_data)
    input_data_scaled = scale_data(input_data)

    # Make prediction
    if st.button('Predict'):
        prediction = model.predict(input_data_scaled)
        st.write('Prediction:', prediction)

if __name__ == '__main__':
    main()
