#import libraries
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from boruta import BorutaPy
import time
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
from sklearn.ensemble import RandomForestClassifier
import warnings
warnings.filterwarnings("ignore")

# Function to load and preprocess the data
def load_data():
    # Reading the column names from kddcup.names file
    with open("KDDCUP_Data/kddcup.names", 'r') as mdata:
        print(mdata.read())

    # Defining column names
    _cols = """duration,
    protocol_type,
    service,
    flag,
    src_bytes,
    dst_bytes,
    land,
    wrong_fragment,
    urgent,
    hot,
    num_failed_logins,
    logged_in,
    num_compromised,
    root_shell,
    su_attempted,
    num_root,
    num_file_creations,
    num_shells,
    num_access_files,
    num_outbound_cmds,
    is_host_login,
    is_guest_login,
    count,
    srv_count,
    serror_rate,
    srv_serror_rate,
    rerror_rate,
    srv_rerror_rate,
    same_srv_rate,
    diff_srv_rate,
    srv_diff_host_rate,
    dst_host_count,
    dst_host_srv_count,
    dst_host_same_srv_rate,
    dst_host_diff_srv_rate,
    dst_host_same_src_port_rate,
    dst_host_srv_diff_host_rate,
    dst_host_serror_rate,
    dst_host_srv_serror_rate,
    dst_host_rerror_rate,
    dst_host_srv_rerror_rate"""

    get_all_columns = [c.strip() for c in _cols.split(',') if c.strip()]
    get_all_columns.append('target')

    print("\n")
    print(get_all_columns)
    print("\n")

    # Reading the training_attack_types file
    with open("KDDCUP_Data/attack_types", 'r') as mdata:
        print(mdata.read())

    # Reading the main dataset file and assigning column names
    data_path = "KDDCUP_Data/kddcup.dataset_file.gz"
    my_dataframe = pd.read_csv(data_path, names=get_all_columns)

    # Mapping attack types to binary labels 
    map_attack_type = {
        'normal': 0,
        'back': 1,
        'buffer_overflow': 4,
        'ftp_write': 3,
        'guess_passwd': 3,
        'imap': 3,
        'ipsweep': 2,
        'land': 1,
        'loadmodule': 4,
        'multihop': 3,
        'neptune': 1,
        'nmap': 2,
        'perl': 4,
        'phf': 3,
        'pod': 1,
        'portsweep': 2,
        'rootkit': 4,
        'satan': 2,
        'smurf': 1,
        'spy': 3,
        'teardrop': 1,
        'warezclient': 3,
        'warezmaster': 3,
    }

    # Adding a new column 'Attack' and dropping the original 'target' column
    my_dataframe['Attack'] = my_dataframe.target.apply(lambda r: map_attack_type[r[:-1]])
    my_dataframe.drop(['target'], axis=1, inplace=True)
    my_dataframe.drop('service', axis=1, inplace=True)

    print(my_dataframe.head())
    print("\n")
    print(my_dataframe['Attack'].value_counts())
    print("\n")
    

    print(my_dataframe['protocol_type'].value_counts())
    print("\n")
    # Mapping categorical variables to numerical values
    map_protocol = {'icmp': 0, 'tcp': 1, 'udp': 2}
    my_dataframe['protocol_type'] = my_dataframe['protocol_type'].map(map_protocol)

    map_flag = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5, 'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10}
    my_dataframe['flag'] = my_dataframe['flag'].map(map_flag)
    print(my_dataframe['protocol_type'].value_counts())
    print("\n")

    y=my_dataframe['Attack']
    x=my_dataframe.drop(['Attack'],axis=1)

    x=x.to_numpy()
    features = my_dataframe.drop('Attack', axis=1).columns.tolist()

    _r_f = RandomForestClassifier(n_jobs=-1, class_weight='balanced', max_depth=5)
    _r_f.fit(x, y)


    bfs_selector = BorutaPy(_r_f, n_estimators='auto', verbose=2, random_state=1,max_iter=30)

    bfs_selector.fit(x, y)

    print(bfs_selector.support_)
    print(bfs_selector.ranking_)   

    _b_feat = list(zip(features, bfs_selector.ranking_, bfs_selector.support_))

    for get_feat in _b_feat:
           print('Feature Name: {:<25} Rank Order: {},  Keep_or_Not: {}'.format(get_feat[0], get_feat[1], get_feat[2]))

    print("*********************")

    new_data=my_dataframe[['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'hot', 'num_failed_logins',
           'logged_in', 'num_compromised', 'root_shell', 'num_root', 'num_file_creations','is_guest_login',
           'count', 'srv_count', 'serror_rate', 'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
           'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
           'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
           'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','Attack']]

    ## new_data.to_csv("KDDCUP_Data/preprocessed_data.csv",index=False)




    # Separating features and labels
    my_dataframe_y = my_dataframe[['Attack']]
    my_dataframe_X = my_dataframe.drop(['Attack'], axis=1)

    # Scaling the features using Min-Max scaler
    sc = MinMaxScaler()
    Scaled_X = sc.fit_transform(my_dataframe_X)


    # Splitting the dataset into training and testing sets
    X_train, X_test, Y_train, Y_test = train_test_split(Scaled_X, my_dataframe_y, test_size=0.2, random_state=42)
    print("\nFeatures...")
    print(X_train.shape, X_test.shape)
    print("\nLabels....")
    print(Y_train.shape, Y_test.shape)

    return X_train, X_test, Y_train, Y_test

from xgboost import XGBClassifier
from sklearn.ensemble import AdaBoostClassifier

# Function to train and evaluate the XGBoost model
def train_and_evaluate_xgboost(X_train, X_test, Y_train, Y_test):

    from imblearn.over_sampling import RandomOverSampler

    # Example: Oversampling the minority class
    ros = RandomOverSampler(random_state=42)
    X_train, Y_train = ros.fit_sample(X_train, Y_train)

    # Initializing XGBoost model
    model_xgboost = XGBClassifier()
    start_time = time.time()
    # Training the model
    model_xgboost.fit(X_train, Y_train.ravel())
    end_time = time.time()
    print("\n")
    print("XGBoost Model Training time: ", end_time - start_time)

    start_time = time.time()
    # Making predictions on the test set
    Y_test_pred_xgboost = model_xgboost.predict(X_test)
    end_time = time.time()
    print("\n")
    print("XGBoost Model Testing time: ", end_time - start_time)

    # Saving the trained model to a file
    joblib.dump(model_xgboost, 'Models/xgboost_model.joblib')

    accuracy = accuracy_score(Y_test, Y_test_pred_xgboost)
    precision = precision_score(Y_test, Y_test_pred_xgboost, average='weighted')
    recall = recall_score(Y_test, Y_test_pred_xgboost, average='weighted')
    f1 = f1_score(Y_test, Y_test_pred_xgboost, average='weighted')

    # Evaluating the model performance
    print("\n")
    print(f"XGBoost Model Accuracy: {accuracy}")
    print(f"XGBoost Model Precision: {precision}")
    print(f"XGBoost Model Recall: {recall}")
    print(f"XGBoost Model F1 Score: {f1}")

    # Generating and visualizing the confusion matrix
    cm_xgboost = confusion_matrix(Y_test, Y_test_pred_xgboost)
    print("\n")
    print("XGBoost Confusion Matrix:")
    print(cm_xgboost)

    # Visualizing the confusion matrix for XGBoost
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm_xgboost, annot=True, fmt='d', cmap='Blues', linewidths=.5, cbar=False)
    plt.title('XGBoost Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig('Results/xgboost_confusion_matrix.png')
    plt.show()

# Function to train and evaluate the AdaBoost model
def train_and_evaluate_adaboost(X_train, X_test, Y_train, Y_test):

    from imblearn.over_sampling import RandomOverSampler

    # Example: Oversampling the minority class
    ros = RandomOverSampler(random_state=42)
    X_train, Y_train = ros.fit_sample(X_train, Y_train)


    # Initializing AdaBoost model
    model_adaboost = AdaBoostClassifier()
    start_time = time.time()
    # Training the model
    model_adaboost.fit(X_train, Y_train.ravel())
    end_time = time.time()
    print("\n")
    print("AdaBoost Model Training time: ", end_time - start_time)

    start_time = time.time()
    # Making predictions on the test set
    Y_test_pred_adaboost = model_adaboost.predict(X_test)
    end_time = time.time()
    print("\n")
    print("AdaBoost Model Testing time: ", end_time - start_time)

    # Saving the trained model to a file
    joblib.dump(model_adaboost, 'Models/adaboost_model.joblib')

    accuracy = accuracy_score(Y_test, Y_test_pred_adaboost)
    precision = precision_score(Y_test, Y_test_pred_adaboost, average='weighted')
    recall = recall_score(Y_test, Y_test_pred_adaboost, average='weighted')
    f1 = f1_score(Y_test, Y_test_pred_adaboost, average='weighted')

    # Evaluating the model performance
    print("\n")
    print(f"AdaBoost Model Accuracy: {accuracy}")
    print(f"AdaBoost Model Precision: {precision}")
    print(f"AdaBoost Model Recall: {recall}")
    print(f"AdaBoost Model F1 Score: {f1}")

    # Generating and visualizing the confusion matrix
    cm_adaboost = confusion_matrix(Y_test, Y_test_pred_adaboost)
    print("\n")
    print("AdaBoost Confusion Matrix:")
    print(cm_adaboost)

    # Visualizing the confusion matrix for AdaBoost
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm_adaboost, annot=True, fmt='d', cmap='Blues', linewidths=.5, cbar=False)
    plt.title('AdaBoost Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig('Results/adaboost_confusion_matrix.png')
    plt.show()


# Main execution block
if __name__ == "__main__":
    my_dataframe=pd.read_csv("KDDCUP_Data/preprocessed_data.csv")

    # Separating features and labels
    my_dataframe_y = my_dataframe[['Attack']]
    my_dataframe_X = my_dataframe.drop(['Attack'], axis=1)

    # Scaling the features using Min-Max scaler
    sc = MinMaxScaler()
    Scaled_X = sc.fit_transform(my_dataframe_X)
    # Save the Min-Max scaler to a file
    joblib.dump(sc, 'Models/minmax_scaler.joblib')

    # Splitting the dataset into training and testing sets
    X_train, X_test, Y_train, Y_test = train_test_split(Scaled_X, my_dataframe_y, test_size=0.2, random_state=42)
    print("\nFeatures...")
    print(X_train.shape, X_test.shape)
    print("\nLabels....")
    print(Y_train.shape, Y_test.shape)
    # X_train, X_test, Y_train, Y_test = load_data()
    train_and_evaluate_xgboost(X_train, X_test, Y_train, Y_test)
    train_and_evaluate_adaboost(X_train, X_test, Y_train, Y_test)
