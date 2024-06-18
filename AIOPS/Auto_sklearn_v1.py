import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import autosklearn.classification

# 데이터 로드
file_path = 'training_data.csv'
data = pd.read_csv(file_path)

# 데이터 전처리
data['Timestamp'] = pd.to_datetime(data['Timestamp'])
data['Timestamp'] = data['Timestamp'].astype(int) / 10**9  # 타임스탬프를 초 단위로 변환

# 문자형 데이터를 숫자로 변환
label_encoders = {}
for column in ['Vendor', 'Part No', 'Tx Power (dBm)' , 'Rx Power (dBm)','FCS Error']:
    label_encoders[column] = LabelEncoder()
    data[column] = label_encoders[column].fit_transform(data[column])

# 특징과 레이블 분리
X = data.drop('Link Status', axis=1)
y = data['Link Status']

# 학습 데이터와 테스트 데이터 분리
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Auto-Sklearn 분류기 생성 및 학습
automl = autosklearn.classification.AutoSklearnClassifier(time_left_for_this_task=300, per_run_time_limit=30)
automl.fit(X_train, y_train)

# 예측
y_pred = automl.predict(X_test)

# 성능 평가
from sklearn.metrics import accuracy_score, classification_report

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:")
print(classification_report(y_test, y_pred))
