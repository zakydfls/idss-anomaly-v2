from sklearn.model_selection import train_test_split
import streamlit as st
import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
import pickle
from sklearn.preprocessing import StandardScaler
from PIL import Image
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

algorithms = ["KNN", "Naive Bayes", "Random Forest"]
    
def aboutUs():
    st.title("About Us")
    st.write("""This application was developed for the purpose of detecting DDoS attacks using machine learning algorithms. This allows users to upload unlabeled datasets to predict attack categories. It also allows users to upload labeled datasets to evaluate the performance of machine learning algorithms.

Our Teams :
* Fauzi Adi Rafrastara, M.Cs. (NIDN: 0630048802)
* Wildanil Ghozi, M.Kom (NIDN: 0604019302)
* Zaky Dafalas Eka Putra (NIM: A11.2021.13316)""")
    if st.button("Close"):
        placeholder.empty()

# Placeholder untuk konten halaman "Tentang Kami"
placeholder = st.empty()
if st.sidebar.button("About Us"):
    aboutUs()
upload_file = st.sidebar.file_uploader("Upload dataset", type=['csv'])
st.sidebar.markdown("[Example dataset](https://streamlit.io/gallery)")
    
st.sidebar.title("Select the Algorithm")
selected_algorithm_1 = st.sidebar.selectbox("Algorithm 1", algorithms)
selected_algorithm_2 = st.sidebar.selectbox("Algorithm 2", algorithms)


def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')
    return accuracy, f1

st.title("Deteksi Serangan DDoS Berbasis Machine Learning")
img = Image.open('dataSec.jpg')
img = img.resize((670, 318))
st.image(img, use_column_width=False)
st.write(f"**Performance Comparasion Between {selected_algorithm_1} dan {selected_algorithm_2}**")    
def select_model(model_name):
    if model_name == "KNN":
        model = pickle.load(open('knn.pkl', 'rb'))
    elif model_name == "Naive Bayes":
        model = pickle.load(open('naive_bayes.pkl', 'rb'))
    elif model_name == "Random Forest":
        model = pickle.load(open('random_forest.pkl', 'rb'))
    else:
        return None
    # model.fit(X_train, y_train)
    return model

if selected_algorithm_1 == selected_algorithm_2:
    st.error("Choose two different algorithm to compare.")
    st.write("Using default dataset")
    data_view = pd.read_csv("dataset.csv")
    st.write(data_view.head(10))
else:
    if upload_file is not None:
        data = pd.read_csv(upload_file)
        if 'attack_cat' not in data.columns:
            st.info("Predicting 'attack_cat' labels...")
            data['attack_cat'] = pd.Series(['unknown'] * len(data)).fillna('unknown')
            st.info("Added 'attack_cat' column with default value 'unknown'.")
            data['ct_flw_http_mthd'].fillna(data['ct_flw_http_mthd'].max(), inplace=True)
            data['is_ftp_login'].fillna(data['is_ftp_login'].max(), inplace=True)
            data['ct_ftp_cmd'] = pd.to_numeric(data['ct_ftp_cmd'], errors='coerce', downcast='integer')
            data = data.drop(['srcip','sport', 'dstip', 'dsport','Stime', 'Ltime'], axis = 1)
            data['ct_ftp_cmd'].fillna(data['ct_ftp_cmd'].max(), inplace=True)
            data['ct_ftp_cmd'] = data['ct_ftp_cmd'].astype(int)
            categorical_columns = ['proto', 'state', 'service', 'attack_cat']
            label_encoders = {}
            for col in categorical_columns:
                le = LabelEncoder()
                data[col] = le.fit_transform(data[col])
                label_encoders[col] = le
            x = data.drop(columns=['attack_cat'])
            X = x.values
            y_test = data['attack_cat']
            # X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
            st.write(data)
            model_1 = select_model(selected_algorithm_1)
            model_2 = select_model(selected_algorithm_2)
            prediction = model_1.predict(X)
            prediction2 = model_2.predict(X)
            prediction_proba = model_1.predict_proba(X)
            attack_cat_labels = np.array(['Fuzzers', 'Analysis', 'Backdoors', 'DoS', 'Exploits','Generic', 'Normal', 'Reconnaissance', 'Shellcode', 'Worms'])
            data.reset_index(drop=True, inplace=True)
            data['Pred with ' + selected_algorithm_1] = attack_cat_labels[prediction]
            data['Pred with ' + selected_algorithm_2] = attack_cat_labels[prediction2]
            st.header("Predicted attack categories")
            st.write(data)
        elif 'attack_cat' in data.columns:
            st.header("Dataset has 'attack_cat' column")
            st.write(data)
            data['ct_flw_http_mthd'].fillna(data['ct_flw_http_mthd'].max(), inplace=True)
            data['is_ftp_login'].fillna(data['is_ftp_login'].max(), inplace=True)
            y = data['attack_cat']
            attack_map = {'Normal' : 6, 'Generic' : 5, 'Exploits' : 4, 'Fuzzers' : 0, 'Reconnaissance' : 7, 'DoS' : 3, 'Bakcdoors' : 2, 'Analysis' : 1, 'Shellcode' : 8, 'Worms' : 9}
            y = y.replace(attack_map, regex=True)
            data['ct_ftp_cmd'] = pd.to_numeric(data['ct_ftp_cmd'], errors='coerce', downcast='integer')
            data = data.drop(['srcip','sport', 'dstip', 'dsport','Stime', 'Ltime','attack_cat'], axis = 1)
            data['ct_ftp_cmd'].fillna(data['ct_ftp_cmd'].max(), inplace=True)
            data['ct_ftp_cmd'] = data['ct_ftp_cmd'].astype(int)
            categorical_columns = ['proto', 'state', 'service']
            label_encoders = {}
            for col in categorical_columns:
                le = LabelEncoder()
                data[col] = le.fit_transform(data[col])
                label_encoders[col] = le
            X = data.values
        # df = pd.DataFrame(X)
        # scaler = StandardScaler()
        # standarized_data = scaler.fit_transform(df)
        # data_columns = X.columns.tolist()
        # scaled_df = pd.DataFrame(standarized_data, columns=data_columns)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
            st.header("Encoded data")
            st.write(y)
            model_1 = select_model(selected_algorithm_1)
            model_2 = select_model(selected_algorithm_2)
            prediction = model_1.predict(X)
            prediction2 = model_2.predict(X)
            prediction_proba = model_1.predict_proba(X)
            attack_cat_labels = np.array(['Fuzzers', 'Analysis', 'Backdoors', 'DoS', 'Exploits','Generic', 'Normal', 'Reconnaissance', 'Shellcode', 'Worms'])
        # st.subheader('Prediction Probability')
        # st.write(prediction_proba)
        # X.reset_index(drop=True, inplace=True)
            data.reset_index(drop=True, inplace=True)
            data['Pred with ' + selected_algorithm_1] = attack_cat_labels[prediction]
            data['Pred with ' + selected_algorithm_2] = attack_cat_labels[prediction2]
            st.header("Result prediction compare with selected algortihm")
            st.write(data)
        
        # Menghitung akurasi
            accuracy_1 = accuracy_score(y, prediction)
            accuracy_2 = accuracy_score(y, prediction2)

# Menghitung presisi
            precision_1 = precision_score(y, prediction, average='weighted')
            precision_2 = precision_score(y, prediction2, average='weighted')

# Menghitung recall
            recall_1 = recall_score(y, prediction, average='weighted')
            recall_2 = recall_score(y, prediction2, average='weighted')

# Menghitung F1 score
            f1_1 = f1_score(y, prediction, average='weighted')
            f1_2 = f1_score(y, prediction2, average='weighted')

# Menampilkan hasil
            performance_data = {
                'Parameter': ['Accuracy', 'Precision', 'Recall', 'F1 Score'],
                selected_algorithm_1: [accuracy_1, precision_1, recall_1, f1_1],
                selected_algorithm_2: [accuracy_2, precision_2, recall_2, f1_2]
            }
            dfm = pd.DataFrame(performance_data)
            dfm_melted = pd.melt(dfm, id_vars="Parameter", var_name="Algoritma", value_name="Nilai")

# Membuat Bar Plot dengan seaborn
            fig, ax = plt.subplots(figsize=(5, 3))
            ax = sns.barplot(x='Parameter', y='Nilai', hue='Algoritma', data=dfm_melted)
            ax.spines[['top', 'right']].set_visible(False)
            sns.move_legend(ax, bbox_to_anchor=(1, 0.5), loc='center left', frameon=False)

# Menampilkan plot di Streamlit
            st.pyplot(fig)
            st.write(dfm)
        ##    data['ct_flw_http_mthd'].fillna(data['ct_flw_http_mthd'].max(), inplace=True)
      ##      data['is_ftp_login'].fillna(data['is_ftp_login'].max(), inplace=True)
    ##        data['ct_ftp_cmd'] = pd.to_numeric(data['ct_ftp_cmd'], errors='coerce', downcast='integer')
  ##          data['ct_ftp_cmd'].fillna(data['ct_ftp_cmd'].max(), inplace=True)
##            data['ct_ftp_cmd'] = data['ct_ftp_cmd'].astype(int)
        ##    categorical_columns = ['proto', 'state', 'service', 'attack_cat']
      ##      label_encoders = {}
    ##        for col in categorical_columns:
  ##              le = LabelEncoder()
##                data[col] = le.fit_transform(data[col])
        ##        label_encoders[col] = le
      ##      x = data.drop(columns=['attack_cat'])
    ##        X = x.values
  ##          y = data['attack_cat']
##            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
        else:
            st.error("Dataset 'attack_cat' column has empty values.")
        
        
    else:
        data = pd.read_csv("cleaned_dataset_v2.csv")
        st.write(data.head(10))
        x = data.drop(columns=['attack_cat'])
        X = x.values
        y = data['attack_cat']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
        model_1 = select_model(selected_algorithm_1)
        acc_1, f1_1 = evaluate_model(model_1, X_test, y_test)
        st.write(f"**{selected_algorithm_1}**\nAccuracy: {acc_1:.4f}, F1 Score: {f1_1:.4f}")
        model_2 = select_model(selected_algorithm_2)
        acc_2, f1_2 = evaluate_model(model_2, X_test, y_test)
        st.write(f"**{selected_algorithm_2}**\nAccuracy: {acc_2:.4f}, F1 Score: {f1_2:.4f}")
        prediction = model_1.predict(X)
        prediction2 = model_2.predict(X)
        precision_1 = precision_score(y, prediction, average='weighted')
        precision_2 = precision_score(y, prediction2, average='weighted')

# Menghitung recall
        recall_1 = recall_score(y, prediction, average='weighted')
        recall_2 = recall_score(y, prediction2, average='weighted')
        performance_data = {
            'Parameter': ['Accuracy', 'Precision', 'Recall', 'F1 Score'],
            selected_algorithm_1: [acc_1, precision_1, recall_1, f1_1],
            selected_algorithm_2: [acc_2, precision_2, recall_2, f1_2]
        }
        dfm = pd.DataFrame(performance_data)
        dfm_melted = pd.melt(dfm, id_vars="Parameter", var_name="Algoritma", value_name="Nilai")

# Membuat Bar Plot dengan seaborn
        fig, ax = plt.subplots(figsize=(5, 3))
        ax = sns.barplot(x='Parameter', y='Nilai', hue='Algoritma', data=dfm_melted)
        ax.spines[['top', 'right']].set_visible(False)
        sns.move_legend(ax, bbox_to_anchor=(1, 0.5), loc='center left', frameon=False)

# Menampilkan plot di Streamlit
        st.pyplot(fig)
        st.write(dfm)
# if upload_file is not None:
#     data = pd.read_csv(upload_file)
#     if 'attack_cat' not in data.columns:
#         data['attack_cat'] = pd.Series(['unknown'] * len(data))
#         st.info("Added 'attack_cat' column with default value 'unknown'.")  
#     else:
#         st.error("Dataset 'attack_cat' column has empty values.")
#     data['ct_flw_http_mthd'].fillna(data['ct_flw_http_mthd'].max(), inplace=True)
#     data['is_ftp_login'].fillna(data['is_ftp_login'].max(), inplace=True)
#     data['ct_ftp_cmd'] = pd.to_numeric(data['ct_ftp_cmd'], errors='coerce', downcast='integer')
#     data['ct_ftp_cmd'].value_counts(dropna=False)
#     data = data.drop(['srcip','sport', 'dstip', 'dsport','Stime', 'Ltime'], axis = 1)
#     data['ct_ftp_cmd'].fillna(data['ct_ftp_cmd'].max(), inplace=True)
#     data['ct_ftp_cmd'] = data['ct_ftp_cmd'].astype(int)
#     categorical_columns = ['proto', 'state', 'service', 'attack_cat']
#     label_encoders = {}
#     for col in categorical_columns:
#         le = LabelEncoder()
#         data[col] = le.fit_transform(data[col])
#         label_encoders[col] = le
#     x = data.drop(columns=['attack_cat'])
#     X = x
#     y = data['attack_cat']
#     df = pd.DataFrame(X)
#     scaler = StandardScaler()
#     standarized_data = scaler.fit_transform(df)
#     data_columns = X.columns.tolist()
#     scaled_df = pd.DataFrame(standarized_data, columns=data_columns)
#     X_train, X_test, y_train, y_test = train_test_split(scaled_df, y, test_size=0.3)
#     st.write(scaled_df)
#     model_1 = select_model(selected_algorithm_1)
#     prediction = model_1.predict(scaled_df)
#     prediction_proba = model_1.predict_proba(scaled_df)
#     attack_cat_labels = np.array(['Normal', 'Exploits', 'Reconnaissance', 'DoS', 'Generic','Shellcode', ' Fuzzers', 'Worms', 'Backdoors', 'Analysis'])
#     data.reset_index(drop=True, inplace=True)
#     st.subheader('Prediction')
#     st.write(attack_cat_labels[prediction])
#     st.subheader('Prediction Probability')
#     st.write(prediction_proba)
#     scaled_df.reset_index(drop=True, inplace=True)
#     data.reset_index(drop=True, inplace=True)
#     data['attack_cat'] = attack_cat_labels[prediction]
#     st.write(data)
# else:
#     data = pd.read_csv("cleaned_dataset_v2.csv")
#     st.write(data.head(10))
#     x = data.drop(columns=['attack_cat'])
#     X = x.values
#     y = data['attack_cat']
#     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
#     model_1 = select_model(selected_algorithm_1)
#     acc_1, f1_1 = evaluate_model(model_1, X_test, y_test)
#     st.write(f"**{selected_algorithm_1}**\nAccuracy: {acc_1:.4f}, F1 Score: {f1_1:.4f}")
#     model_2 = select_model(selected_algorithm_2)
#     acc_2, f1_2 = evaluate_model(model_2, X_test, y_test)
#     st.write(f"**{selected_algorithm_2}**\nAccuracy: {acc_2:.4f}, F1 Score: {f1_2:.4f}")         